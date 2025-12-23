# core/management/commands/fetch_emails.py (CORRECTION)
from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import EmailAccount, EmailMessage, QuarantineEmail
from core.services.imap_service import IMAPService
from core.services.email_analyzer import EmailAnalyzer
import logging
from core.services.playbook_executor import PlaybookExecutor


logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Récupère et analyse les emails depuis les comptes configurés'

    def add_arguments(self, parser):
        parser.add_argument(
            '--account-id',
            type=int,
            help='ID du compte spécifique à traiter (sinon tous les comptes actifs)'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=50,
            help='Nombre maximum d\'emails à récupérer par compte'
        )

    def handle(self, *args, **options):
        account_id = options.get('account_id')
        limit = options.get('limit')
        
        # Récupérer les comptes à traiter
        if account_id:
            accounts = EmailAccount.objects.filter(id=account_id, is_active=True)
        else:
            accounts = EmailAccount.objects.filter(is_active=True)
        
        if not accounts.exists():
            self.stdout.write(self.style.WARNING('Aucun compte email actif trouvé'))
            return
        
        analyzer = EmailAnalyzer()
        
        for account in accounts:
            self.stdout.write(f"\n📧 Traitement du compte: {account.name}")
            
            try:
                # Connexion IMAP
                imap_service = IMAPService(
                    server=account.imap_server,
                    port=account.imap_port,
                    username=account.username,
                    password=account.password,
                    use_ssl=account.use_ssl
                )
                
                if not imap_service.connect():
                    self.stdout.write(self.style.ERROR(f'  ❌ Échec de connexion'))
                    continue
                
                # Récupérer les emails
                emails = imap_service.fetch_emails(limit=limit)
                
                self.stdout.write(f'  ✅ {len(emails)} emails récupérés')
                
                # Traiter chaque email
                processed = 0
                for email_data in emails:
                    try:
                        # Debug: afficher un résumé de l'email reçu
                        self.stdout.write(f"    - Email reçu UID(raw)={email_data.get('uid')} subject={email_data.get('subject')[:40]}...")
                        # Utiliser un UID stable par compte pour éviter les collisions
                        uid_to_use = f"{account.id}_{email_data.get('uid', '')}"

                        # Si le Message-ID est disponible, vérifier aussi sur ce champ
                        message_id = email_data.get('message_id', '')

                        if message_id:
                            # Si un email avec ce message_id existe, on le considère comme déjà traité
                            if EmailMessage.objects.filter(message_id=message_id).exists():
                                self.stdout.write(f"      ⚠️ Ignoré: message_id déjà présent ({message_id})")
                                continue

                        # Vérifier l'uid composé (par compte)
                        if EmailMessage.objects.filter(uid=uid_to_use).exists():
                            self.stdout.write(f"      ⚠️ Ignoré: uid déjà présent ({uid_to_use})")
                            continue
                        
                        # Analyser l'email
                        threat_level, threat_type, risk_score = analyzer.analyze(email_data)
                        
                        # Créer l'objet EmailMessage
                        email_obj = EmailMessage.objects.create(
                            account=account,
                            uid=uid_to_use,
                            message_id=email_data.get('message_id', ''),
                            sender=email_data['sender'],
                            sender_name=email_data.get('sender_name', ''),
                            recipients=email_data['recipients'],
                            subject=email_data['subject'],
                            received_date=email_data['received_date'],
                            body_text=email_data['body_text'],
                            body_html=email_data['body_html'],
                            attachments=email_data['attachments'],
                            has_attachments=email_data['has_attachments'],
                            size=email_data['size'],
                            threat_level=threat_level,
                            threat_type=threat_type,
                            risk_score=risk_score,
                            analyzed=True,
                            analysis_date=timezone.now()
                        )
                        
                        processed += 1
                        self.stdout.write(self.style.SUCCESS(f"      ✅ Enregistré: uid={uid_to_use} id={email_obj.id}"))
                        
                        # ============ AUTOMATIQUEMENT METTRE EN QUARANTAINE LES EMAILS MALVEILLANTS ============
                        # Si l'email est détecté comme MALWARE ou un threat_level élevé, le mettre automatiquement en quarantaine
                        if threat_type == 'MALWARE' or threat_level in ['HIGH', 'CRITICAL']:
                            try:
                                # Marquer l'email comme quarantiné
                                email_obj.is_quarantined = True
                                email_obj.save()
                                
                                # Créer une entrée dans QuarantineEmail
                                quarantine_threat_type = 'MALWARE' if threat_type == 'MALWARE' else threat_type
                                QuarantineEmail.objects.create(
                                    original_email=email_obj,
                                    sender=email_data['sender'],
                                    sender_name=email_data.get('sender_name', ''),
                                    subject=email_data['subject'],
                                    received_date=email_data['received_date'],
                                    body_text=email_data['body_text'],
                                    body_html=email_data['body_html'],
                                    attachments=email_data['attachments'],
                                    threat_type=quarantine_threat_type,
                                    risk_score=risk_score,
                                    size=email_data['size'],
                                    has_attachments=email_data['has_attachments'],
                                    analysis_summary=f"Détecté comme {threat_type} avec un niveau de menace {threat_level}. Score de risque: {risk_score}%",
                                    reason=f"Mis en quarantaine automatiquement - Menace détectée: {threat_type}"
                                )
                                self.stdout.write(f'    🚨 ✅ Email mis en quarantaine automatiquement: {threat_type} ({threat_level})')
                            except Exception as e:
                                logger.error(f"Erreur création quarantaine: {e}")
                        
                        # Exécuter les playbooks sur cet email
                        executor = PlaybookExecutor(email_obj)
                        executed_actions = executor.execute_playbooks()
                        if executed_actions:
                            for action in executed_actions:
                                logger.info(f"    ⚡ Action exécutée: {action['action']} - {action['result'].get('message', '')}")
                        # Afficher les menaces détectées
                        if threat_level != 'SAFE':
                            self.stdout.write(f'    🚨 Menace détectée: {threat_type} ({threat_level}) - {email_data["subject"][:50]}...')
                            
                    except Exception as e:
                        logger.error(f"Erreur traitement email: {e}")
                        self.stdout.write(self.style.ERROR(f"    ❌ Erreur traitement email: {e}"))
                        # Afficher l'email brut pour debug (sans content long)
                        try:
                            preview = {k: (str(v)[:200] + '...') if isinstance(v, (str, bytes)) and len(str(v))>200 else v for k,v in email_data.items()}
                            self.stdout.write(f"      DEBUG email_data: {preview}")
                        except:
                            pass
                        continue
                
                imap_service.disconnect()
                
                self.stdout.write(self.style.SUCCESS(f'  ✅ {processed} nouveaux emails enregistrés'))
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  ❌ Erreur: {e}'))
                continue
        
        self.stdout.write(self.style.SUCCESS('\n✅ Traitement terminé'))




#pour tester avec la commande: python manage.py fetch_emails --limit 5

