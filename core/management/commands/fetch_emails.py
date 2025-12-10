# core/management/commands/fetch_emails.py (CORRECTION)
from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import EmailAccount, EmailMessage
from core.services.imap_service import IMAPService
from core.services.email_analyzer import EmailAnalyzer
import logging

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
                        # Vérifier si l'email existe déjà
                        if EmailMessage.objects.filter(uid=email_data['uid']).exists():
                            continue
                        
                        # Analyser l'email
                        threat_level, threat_type, risk_score = analyzer.analyze(email_data)
                        
                        # Créer l'objet EmailMessage
                        email_obj = EmailMessage.objects.create(
                            account=account,
                            uid=email_data['uid'],
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
                        
                        # Afficher les menaces détectées
                        if threat_level != 'SAFE':
                            self.stdout.write(f'    🚨 Menace détectée: {threat_type} ({threat_level}) - {email_data["subject"][:50]}...')
                            
                    except Exception as e:
                        logger.error(f"Erreur traitement email: {e}")
                        continue
                
                imap_service.disconnect()
                
                self.stdout.write(self.style.SUCCESS(f'  ✅ {processed} nouveaux emails enregistrés'))
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  ❌ Erreur: {e}'))
                continue
        
        self.stdout.write(self.style.SUCCESS('\n✅ Traitement terminé'))


#pour tester avec la commande: python manage.py fetch_emails --limit 5