# core/services/playbook_executor.py
import re
import logging
from typing import List, Dict, Optional
from core.models import Playbook, PlaybookRule, PlaybookAction, EmailMessage, IncidentLog, QuarantineEmail
from core.services.imap_service import IMAPService
from django.utils import timezone

logger = logging.getLogger(__name__)

class PlaybookExecutor:
    """Exécute les playbooks sur les emails"""
    
    def __init__(self, email: EmailMessage):
        self.email = email
        self.triggered_playbooks = []
        self.executed_actions = []
    
    def evaluate_rules(self, rules) -> bool:
        """Évalue un ensemble de règles (ET logique entre les règles)"""
        for rule in rules:
            field_value = self._get_field_value(rule.field)
            rule_result = self._evaluate_rule(rule, field_value)
            
            # Si une règle est fausse (et non négation), l'ensemble est faux
            if not rule_result:
                return False
        
        return True
    
    def _get_field_value(self, field_name: str):
        """Récupère la valeur d'un champ de l'email"""
        if field_name == 'sender':
            return self.email.sender
        elif field_name == 'subject':
            return self.email.subject
        elif field_name == 'body_text':
            return self.email.body_text
        elif field_name == 'body_html':
            return self.email.body_html
        elif field_name == 'threat_level':
            return self.email.threat_level
        elif field_name == 'threat_type':
            return self.email.threat_type
        elif field_name == 'risk_score':
            return self.email.risk_score
        elif field_name == 'has_attachments':
            return self.email.has_attachments
        else:
            # Pour les champs personnalisés ou non gérés
            return getattr(self.email, field_name, '')
    
    def _evaluate_rule(self, rule, field_value) -> bool:
        """Évalue une règle individuelle"""
        # Convertir en string pour la comparaison
        if not isinstance(field_value, str):
            field_value = str(field_value)
        
        value = str(rule.value)
        
        result = False
        
        if rule.operator == 'contains':
            result = value.lower() in field_value.lower()
        elif rule.operator == 'in':
            # value may be a comma-separated list like 'HIGH,CRITICAL'
            try:
                options = [v.strip().lower() for v in value.split(',') if v.strip()]
                result = field_value.lower() in options
            except Exception:
                result = False
        elif rule.operator == 'equals':
            result = field_value.lower() == value.lower()
        elif rule.operator == 'startswith':
            result = field_value.lower().startswith(value.lower())
        elif rule.operator == 'endswith':
            result = field_value.lower().endswith(value.lower())
        elif rule.operator == 'regex':
            try:
                result = bool(re.search(value, field_value, re.IGNORECASE))
            except re.error:
                logger.error(f"Regex invalide: {value}")
                result = False
        elif rule.operator == 'gt':
            try:
                result = float(field_value) > float(value)
            except (ValueError, TypeError):
                result = False
        elif rule.operator == 'gte':
            try:
                result = float(field_value) >= float(value)
            except (ValueError, TypeError):
                result = False
        elif rule.operator == 'lt':
            try:
                result = float(field_value) < float(value)
            except (ValueError, TypeError):
                result = False
        elif rule.operator == 'lte':
            try:
                result = float(field_value) <= float(value)
            except (ValueError, TypeError):
                result = False
        
        # Appliquer la négation si nécessaire
        if rule.negate:
            result = not result
        
        return result
    
    def execute_playbooks(self) -> List[Dict]:
        """Exécute les playbooks sur l'email"""
        # Récupérer les playbooks actifs triés par priorité
        playbooks = Playbook.objects.filter(is_active=True).order_by('priority')
        
        for playbook in playbooks:
            rules = playbook.rules.all()
            
            # Si le playbook n'a pas de règles, on le saute
            if not rules.exists():
                continue
            
            # Évaluer les règles
            if self.evaluate_rules(rules):
                self.triggered_playbooks.append(playbook)
                
                # Exécuter les actions
                actions = playbook.actions.all()
                for action in actions:
                    action_result = self._execute_action(action)
                    self.executed_actions.append({
                        'playbook': playbook.name,
                        'action': action.get_action_type_display(),
                        'result': action_result,
                        'timestamp': timezone.now().isoformat()
                    })
        
        # Créer un log d'incident si des playbooks ont été déclenchés
        if self.triggered_playbooks:
            self._create_incident_log()
        
        return self.executed_actions
    
    def _execute_action(self, action: PlaybookAction) -> Dict:
        """Exécute une action spécifique"""
        try:
            if action.action_type == 'quarantine':
                return self._action_quarantine(action)
            elif action.action_type == 'delete':
                return self._action_delete(action)
            elif action.action_type == 'move_to_folder':
                return self._action_move_to_folder(action)
            elif action.action_type == 'mark_as_read':
                return self._action_mark_as_read(action)
            elif action.action_type == 'mark_as_unread':
                return self._action_mark_as_unread(action)
            elif action.action_type == 'forward':
                return self._action_forward(action)
            elif action.action_type == 'reply':
                return self._action_reply(action)
            elif action.action_type == 'notify':
                return self._action_notify(action)
            elif action.action_type == 'log_only':
                return self._action_log_only(action)
            elif action.action_type == 'create_ticket':
                return self._action_create_ticket(action)
            elif action.action_type == 'block_sender':
                return self._action_block_sender(action)
            else:
                return {'success': False, 'error': f'Action inconnue: {action.action_type}'}
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'action {action.action_type}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_quarantine(self, action: PlaybookAction) -> Dict:
        """Met l'email en quarantaine"""
        try:
            # Marquer l'email comme quarantiné
            self.email.is_quarantined = True
            self.email.save()
            
            # Vérifier si une quarantaine existe déjà pour cet email
            if not QuarantineEmail.objects.filter(original_email=self.email).exists():
                # Créer une entrée dans QuarantineEmail
                QuarantineEmail.objects.create(
                    original_email=self.email,
                    sender=self.email.sender,
                    sender_name=self.email.sender_name,
                    subject=self.email.subject,
                    received_date=self.email.received_date,
                    body_text=self.email.body_text,
                    body_html=self.email.body_html,
                    attachments=self.email.attachments,
                    threat_type=self.email.threat_type if self.email.threat_type in ['PHISHING', 'SPAM', 'MALWARE', 'SUSPICIOUS', 'SPOOFING'] else 'SUSPICIOUS',
                    risk_score=self.email.risk_score,
                    size=self.email.size,
                    has_attachments=self.email.has_attachments,
                    analysis_summary=f"Détecté comme {self.email.threat_type} avec un niveau de menace {self.email.threat_level}. Score de risque: {self.email.risk_score}%",
                    reason=f"Mis en quarantaine par playbook - Menace détectée: {self.email.threat_type}"
                )
            
            return {
                'success': True,
                'message': f'Email mis en quarantaine avec succès',
                'email_id': self.email.id
            }
        except Exception as e:
            logger.error(f"Erreur lors de la quarantaine: {e}")
            return {
                'success': False,
                'error': str(e),
                'email_id': self.email.id
            }
    
    def _action_delete(self, action: PlaybookAction) -> Dict:
        """Supprime l'email (simulé pour l'instant)"""
        # Note: Dans une vraie implémentation, on supprimerait l'email du serveur IMAP
        return {
            'success': True,
            'message': f'Email marqué pour suppression (simulé)',
            'email_id': self.email.id
        }
    
    def _action_move_to_folder(self, action: PlaybookAction) -> Dict:
        """Déplace l'email vers un dossier spécifique"""
        folder = action.parameters.get('folder', 'INBOX.Quarantine')
        
        # Connexion IMAP pour déplacer l'email
        account = self.email.account
        imap_service = IMAPService(
            server=account.imap_server,
            port=account.imap_port,
            username=account.username,
            password=account.password,
            use_ssl=account.use_ssl
        )
        
        if imap_service.connect():
            try:
                # Sélectionner la boîte de réception
                imap_service.connection.select('INBOX')
                # Déplacer l'email (UID MOVE nécessite IMAP4rev1)
                # Pour compatibilité, on peut faire COPY + STORE +FLAGS \Deleted + EXPUNGE
                result = {
                    'success': True,
                    'message': f'Email déplacé vers {folder} (simulé - nécessite IMAP4rev1)',
                    'email_id': self.email.id
                }
            except Exception as e:
                result = {'success': False, 'error': str(e)}
            finally:
                imap_service.disconnect()
        else:
            result = {'success': False, 'error': 'Connexion IMAP échouée'}
        
        return result
    
    def _action_mark_as_read(self, action: PlaybookAction) -> Dict:
        """Marque l'email comme lu"""
        self.email.is_read = True
        self.email.save()
        return {'success': True, 'message': 'Email marqué comme lu'}
    
    def _action_mark_as_unread(self, action: PlaybookAction) -> Dict:
        """Marque l'email comme non lu"""
        self.email.is_read = False
        self.email.save()
        return {'success': True, 'message': 'Email marqué comme non lu'}
    
    def _action_forward(self, action: PlaybookAction) -> Dict:
        """Transfère l'email à une adresse spécifique"""
        forward_to = action.parameters.get('forward_to', '')
        return {
            'success': True,
            'message': f'Email transféré à {forward_to} (simulé)',
            'forward_to': forward_to
        }
    
    def _action_reply(self, action: PlaybookAction) -> Dict:
        """Répond avec un modèle prédéfini"""
        template = action.parameters.get('template', '')
        return {
            'success': True,
            'message': f'Réponse envoyée avec modèle (simulé)',
            'template': template[:50] + '...' if len(template) > 50 else template
        }
    
    def _action_notify(self, action: PlaybookAction) -> Dict:
        """Envoie une notification par email"""
        notify_to = action.parameters.get('notify_to', '')
        subject = action.parameters.get('subject', 'Alerte de sécurité')
        return {
            'success': True,
            'message': f'Notification envoyée à {notify_to} (simulé)',
            'subject': subject
        }
    
    def _action_log_only(self, action: PlaybookAction) -> Dict:
        """Seulement journalise l'incident"""
        return {
            'success': True,
            'message': 'Incident journalisé',
            'log_level': action.parameters.get('log_level', 'INFO')
        }
    
    def _action_create_ticket(self, action: PlaybookAction) -> Dict:
        """Crée un ticket dans un système de ticketing"""
        system = action.parameters.get('system', 'internal')
        return {
            'success': True,
            'message': f'Ticket créé dans {system} (simulé)',
            'ticket_system': system
        }
    
    def _action_block_sender(self, action: PlaybookAction) -> Dict:
        """Bloque l'expéditeur"""
        sender = self.email.sender
        # Ici, on pourrait ajouter à une blacklist en base de données
        return {
            'success': True,
            'message': f'Expéditeur {sender} bloqué (simulé)',
            'blocked_sender': sender
        }
    
    def _create_incident_log(self):
        """Crée un journal d'incident"""
        incident = IncidentLog.objects.create(
            email=self.email,
            playbook=self.triggered_playbooks[0] if self.triggered_playbooks else None,
            status='detected',
            actions_executed=self.executed_actions,
            notes=f"Playbooks déclenchés: {', '.join([p.name for p in self.triggered_playbooks])}"
        )
        return incident