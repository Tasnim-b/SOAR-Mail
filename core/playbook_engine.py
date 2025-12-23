# core/playbook_engine.py
from datetime import datetime
import json
from django.utils import timezone
from .models import Playbook, PlaybookRule, PlaybookAction, IncidentLog, QuarantineEmail, EmailMessage

class PlaybookEngine:
    def __init__(self):
        self.execution_log = []
    
    def execute_playbook(self, playbook, email, user=None):
        """Exécute un playbook sur un email"""
        try:
            # Vérifier si toutes les règles sont satisfaites
            all_rules_passed = True
            for rule in playbook.rules.all():
                if not rule.evaluate(email):
                    all_rules_passed = False
                    break
            
            if not all_rules_passed:
                return False
            
            # Exécuter les actions dans l'ordre
            actions_executed = []
            for action in playbook.actions.all().order_by('order'):
                success, message = self.execute_action(action, email, user)
                actions_executed.append({
                    'action': action.get_action_type_display(),
                    'success': success,
                    'message': message,
                    'executed_at': timezone.now().isoformat()
                })
                
                # Ajouter un délai si spécifié
                if action.delay_seconds > 0:
                    import time
                    time.sleep(action.delay_seconds)
            
            # Mettre à jour les statistiques du playbook
            playbook.execution_count += 1
            playbook.last_executed = timezone.now()
            playbook.save()
            
            # Créer un log d'incident
            IncidentLog.objects.create(
                email=email,
                playbook=playbook,
                status='detected',
                actions_executed=actions_executed,
                notes=f"Playbook déclenché automatiquement"
            )
            
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'exécution du playbook: {e}")
            return False
    
    def execute_action(self, action, email, user=None):
        """Exécute une action spécifique"""
        try:
            action_type = action.action_type
            params = action.parameters or {}
            
            if action_type == 'quarantine':
                return self._quarantine_email(email, user, params)
            elif action_type == 'delete':
                return self._delete_email(email, user)
            elif action_type == 'mark_as_read':
                return self._mark_as_read(email)
            elif action_type == 'mark_as_unread':
                return self._mark_as_unread(email)
            elif action_type == 'log_only':
                return self._log_only(email, playbook=None)
            elif action_type == 'block_sender':
                return self._block_sender(email, params)
            elif action_type == 'notify':
                return self._notify_admin(email, params)
            else:
                return False, f"Action non implémentée: {action_type}"
                
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _quarantine_email(self, email, user, params):
        """Met un email en quarantaine"""
        try:
            # Vérifier si l'email n'est pas déjà en quarantaine
            if email.is_quarantined:
                return True, "Email déjà en quarantaine"
            
            # Créer l'entrée de quarantaine
            quarantine_email = QuarantineEmail.objects.create(
                original_email=email,
                sender=email.sender,
                sender_name=email.sender_name,
                subject=email.subject,
                received_date=email.received_date,
                body_text=email.body_text,
                body_html=email.body_html,
                attachments=email.attachments,
                threat_type=email.threat_type,
                risk_score=email.risk_score,
                analysis_summary=params.get('reason', 'Mise en quarantaine par playbook'),
                quarantined_by=user,
                reason=params.get('reason', 'Playbook automatique'),
                size=email.size,
                has_attachments=email.has_attachments
            )
            
            # Marquer l'email original comme quarantaine
            email.is_quarantined = True
            email.save()
            
            return True, "Email mis en quarantaine avec succès"
            
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _delete_email(self, email, user):
        """Supprime un email"""
        try:
            email.delete()
            return True, "Email supprimé avec succès"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _mark_as_read(self, email):
        """Marque un email comme lu"""
        try:
            email.is_read = True
            email.save()
            return True, "Email marqué comme lu"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _mark_as_unread(self, email):
        """Marque un email comme non lu"""
        try:
            email.is_read = False
            email.save()
            return True, "Email marqué comme non lu"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _block_sender(self, email, params):
        """Bloque l'expéditeur (simulation)"""
        try:
            # Dans une vraie implémentation, vous ajouteriez à une liste noire
            sender = email.sender
            return True, f"Expéditeur {sender} bloqué (simulation)"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def _log_only(self, email, params):
        """Seulement journaliser"""
        try:
            # Créer un incident log sans action supplémentaire
            IncidentLog.objects.create(
                email=email,
                status='detected',
                actions_executed=[{
                    'action': 'log_only',
                    'success': True,
                    'message': 'Incident journalisé uniquement',
                    'executed_at': timezone.now().isoformat()
                }],
                notes=params.get('reason', 'Journalisation par playbook')
            )
            return True, "Incident journalisé avec succès"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def run_all_playbooks_for_email(self, email, user=None):
        """Exécute tous les playbooks actifs pour un email"""
        try:
            # Récupérer tous les playbooks actifs par ordre de priorité
            playbooks = Playbook.objects.filter(is_active=True).order_by('priority')
            
            for playbook in playbooks:
                self.execute_playbook(playbook, email, user)
                
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'exécution des playbooks: {e}")
            return False
        
    def _notify_admin(self, email, params):
        """Notifie l'admin via l'interface (pas d'email)"""
        try:
            # Créer une entrée de notification dans la base
            from django.contrib.auth import get_user_model
            User = get_user_model()
            admin = User.objects.filter(is_superuser=True).first()
            
            if admin:
                # Vous pourriez créer un modèle Notification, mais pour simplifier,
                # nous allons créer un IncidentLog spécial
                IncidentLog.objects.create(
                    email=email,
                    status='notified',
                    actions_executed=[{
                        'action': 'notify',
                        'success': True,
                        'message': f'Admin notifié: {email.subject[:50]}...',
                        'executed_at': timezone.now().isoformat()
                    }],
                    notes=f"Notification envoyée à l'admin: {email.sender} - {email.subject}"
                )
                return True, f"Admin notifié pour email: {email.subject[:30]}..."
            else:
                return False, "Aucun admin trouvé"
        except Exception as e:
            return False, f"Erreur: {str(e)}"