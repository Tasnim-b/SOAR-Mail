# core/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings

class CustomUserManager(BaseUserManager):
    """Manager personnalisé pour utiliser email au lieu de username"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValidationError(_('L\'email est obligatoire'))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = CustomUserManager()
    
    def __str__(self):
        return self.email
    



# Modèle pour les emails
class EmailAccount(models.Model):
    """Configuration d'un compte email à analyser"""
    name = models.CharField(max_length=100, verbose_name="Nom du compte")#nom  pour identifier le compte email
    email = models.EmailField(verbose_name="Adresse email")#adresse email du compte
    imap_server = models.CharField(max_length=200, verbose_name="Serveur IMAP")#adresse du serveur IMAP
    imap_port = models.IntegerField(default=993, verbose_name="Port IMAP")#port du serveur IMAP
    username = models.CharField(max_length=200, verbose_name="Nom d'utilisateur")#nom d'utilisateur pour se connecter au serveur IMAP
    password = models.CharField(max_length=500, verbose_name="Mot de passe (chiffré)")#mot de passe chiffré pour se connecter au serveur IMAP
    use_ssl = models.BooleanField(default=True, verbose_name="Utiliser SSL")#pour que la connexion doit se passer par IMAP sécurisé (IMAPS) afin d'interdire les connexions non chiffrées
    is_active = models.BooleanField(default=True, verbose_name="Actif")#indique si le compte est actif pour la récupération des emails
    
    created_at = models.DateTimeField(auto_now_add=True)#date de création
    updated_at = models.DateTimeField(auto_now=True)#date de dernière modification
    
    def __str__(self):
        return f"{self.name} ({self.email})"
    
    class Meta:
        verbose_name = "Compte Email"
        verbose_name_plural = "Comptes Emails"

# Modèle pour les emails récupérés
class EmailMessage(models.Model):
    """Email récupéré et analysé"""
    
    # Types de menaces possibles
    THREAT_LEVEL_CHOICES = [
        ('SAFE', 'Sûr'),
        ('LOW', 'Faible'),
        ('MEDIUM', 'Moyen'),
        ('HIGH', 'Élevé'),
        ('CRITICAL', 'Critique'),
    ]
    
    THREAT_TYPE_CHOICES = [
        ('PHISHING', 'Phishing'),
        ('SPAM', 'Spam'),
        ('MALWARE', 'Malware'),
        ('SUSPICIOUS', 'Suspect'),
        ('SPOOFING', 'Usurpation'),
        ('NONE', 'Aucune'),
    ]
    
    # Informations de base
    account = models.ForeignKey(EmailAccount, on_delete=models.CASCADE, related_name='emails')#compte email associé
    uid = models.CharField(max_length=100, unique=True, verbose_name="UID IMAP")#identifiant unique de l'email sur le serveur IMAP
    message_id = models.CharField(max_length=500, verbose_name="Message-ID")#identifiant unique de l'email dans les en-têtes issu du serveur d'envoi iamp
    
    # Métadonnées
    sender = models.EmailField(verbose_name="Expéditeur")#adresse email de l'expéditeur
    sender_name = models.CharField(max_length=200, blank=True, verbose_name="Nom expéditeur")#nom de l'expéditeur
    recipients = models.TextField(verbose_name="Destinataires")#liste des destinataires
    subject = models.TextField(verbose_name="Sujet")#sujet de l'email
    received_date = models.DateTimeField(verbose_name="Date réception")#date et heure de réception de l'email
    size = models.IntegerField(verbose_name="Taille (octets)")
    
    # Contenu
    body_text = models.TextField(blank=True, verbose_name="Corps texte")#corps en texte brut
    body_html = models.TextField(blank=True, verbose_name="Corps HTML")#corps en HTML
    attachments = models.JSONField(default=list, verbose_name="Pièces jointes")#liste des pièces jointes (noms, types, tailles)
    
    # Analyse
    threat_level = models.CharField(
        max_length=20, 
        choices=THREAT_LEVEL_CHOICES, 
        default='SAFE',
        verbose_name="Niveau de menace"
    )#niveau de menace détecté
    threat_type = models.CharField(
        max_length=20, 
        choices=THREAT_TYPE_CHOICES, 
        default='NONE',
        verbose_name="Type de menace"
    )#type de menace détectée
    risk_score = models.IntegerField(default=0, verbose_name="Score de risque")#score de risque calculé
    analyzed = models.BooleanField(default=False, verbose_name="Analysé")#indique si l'email a été analysé
    analysis_date = models.DateTimeField(null=True, blank=True, verbose_name="Date analyse")#date et heure de l'analyse
    
    # Flags
    has_attachments = models.BooleanField(default=False, verbose_name="A des pièces jointes")#indique si l'email contient des pièces jointes
    is_encrypted = models.BooleanField(default=False, verbose_name="Chiffré")#indique si l'email est chiffré 
    is_read = models.BooleanField(default=False, verbose_name="Lu")#indique si l'email a été lu
    
    # Logs
    created_at = models.DateTimeField(auto_now_add=True)#date de création
    updated_at = models.DateTimeField(auto_now=True)#date de dernière modification
    
    # Quarantaine
    is_quarantined = models.BooleanField(default=False, verbose_name="En quarantaine")

    def __str__(self):
        return f"{self.sender} - {self.subject[:50]}..."
    
    class Meta:
        verbose_name = "Email"
        verbose_name_plural = "Emails"
        ordering = ['-received_date']
        indexes = [
            models.Index(fields=['threat_level', 'received_date']),
            models.Index(fields=['sender', 'received_date']),
        ]


# Modèle pour les emails en quarantaine
class QuarantineEmail(models.Model):
    """Email mis en quarantaine"""
    
    # Types de menaces possibles
    THREAT_TYPE_CHOICES = [
        ('PHISHING', 'Phishing'),
        ('SPAM', 'Spam'),
        ('MALWARE', 'Malware'),
        ('SUSPICIOUS', 'Suspect'),
        ('SPOOFING', 'Usurpation'),
    ]
    
    # Relation avec l'email original
    original_email = models.OneToOneField(
        EmailMessage, 
        on_delete=models.CASCADE, 
        related_name='quarantine',
        verbose_name="Email original"
    )
    
    # Informations de base
    sender = models.EmailField(verbose_name="Expéditeur")
    sender_name = models.CharField(max_length=200, blank=True, verbose_name="Nom expéditeur")
    subject = models.TextField(verbose_name="Sujet")
    received_date = models.DateTimeField(verbose_name="Date réception")
    
    # Contenu (stocké pour référence, mais peut être réduit)
    body_text = models.TextField(blank=True, verbose_name="Corps texte")
    body_html = models.TextField(blank=True, verbose_name="Corps HTML")
    attachments = models.JSONField(default=list, verbose_name="Pièces jointes")
    
    # Analyse
    threat_type = models.CharField(
        max_length=20, 
        choices=THREAT_TYPE_CHOICES, 
        default='SUSPICIOUS',
        verbose_name="Type de menace"
    )
    risk_score = models.IntegerField(default=0, verbose_name="Score de risque")
    analysis_summary = models.TextField(blank=True, verbose_name="Résumé de l'analyse")
    
    # Gestion de la quarantaine
    quarantined_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        verbose_name="Mis en quarantaine par"
    )
    quarantined_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de quarantaine")
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name="Expire le")
    
    # Flags
    is_restored = models.BooleanField(default=False, verbose_name="Restauré")
    restored_at = models.DateTimeField(null=True, blank=True, verbose_name="Date de restauration")
    restored_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='restored_quarantine',
        verbose_name="Restauré par"
    )
    
    # Raison de la quarantaine
    reason = models.TextField(blank=True, verbose_name="Raison de la quarantaine")
    
    # Métadonnées
    size = models.IntegerField(verbose_name="Taille (octets)", default=0)
    has_attachments = models.BooleanField(default=False, verbose_name="A des pièces jointes")
    
    def __str__(self):
        return f"Quarantaine: {self.sender} - {self.subject[:50]}..."
    
    class Meta:
        verbose_name = "Email en quarantaine"
        verbose_name_plural = "Emails en quarantaine"
        ordering = ['-quarantined_at']
        indexes = [
            models.Index(fields=['threat_type', 'quarantined_at']),
            models.Index(fields=['is_restored', 'quarantined_at']),
        ]
    
    def save(self, *args, **kwargs):
        # Définir la date d'expiration par défaut (30 jours)
        if not self.expires_at and not self.is_restored:
            self.expires_at = timezone.now() + timezone.timedelta(days=30)
        super().save(*args, **kwargs)


# Modèles pour les playbooks SOAR
class Playbook(models.Model):
    """Playbook SOAR : ensemble de règles et d'actions"""
    name = models.CharField(max_length=100, verbose_name="Nom")
    description = models.TextField(blank=True, verbose_name="Description")
    is_active = models.BooleanField(default=True, verbose_name="Actif")
    priority = models.IntegerField(default=1, verbose_name="Priorité (1=le plus haut)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='playbooks_created')
    execution_count = models.IntegerField(default=0, verbose_name="Nombre d'exécutions")
    last_executed = models.DateTimeField(null=True, blank=True, verbose_name="Dernière exécution")

    def __str__(self):
        return f"{self.name} (Priorité: {self.priority})"

    class Meta:
        verbose_name = "Playbook"
        verbose_name_plural = "Playbooks"
        ordering = ['priority', 'name']


class PlaybookRule(models.Model):
    """Règle pour déclencher un playbook"""
    
    FIELD_CHOICES = [
        ('sender', 'Expéditeur'),
        ('subject', 'Sujet'),
        ('body_text', 'Corps texte'),
        ('body_html', 'Corps HTML'),
        ('threat_level', 'Niveau de menace'),
        ('threat_type', 'Type de menace'),
        ('risk_score', 'Score de risque'),
        ('has_attachments', 'A des pièces jointes'),
    ]
    
    OPERATOR_CHOICES = [
        ('contains', 'Contient'),
        ('equals', 'Égal à'),
        ('startswith', 'Commence par'),
        ('endswith', 'Finit par'),
        ('regex', 'Expression régulière'),
        ('gt', 'Supérieur à'),
        ('gte', 'Supérieur ou égal à'),
        ('lt', 'Inférieur à'),
        ('lte', 'Inférieur ou égal à'),
    ]

    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='rules')
    field = models.CharField(max_length=50, choices=FIELD_CHOICES, verbose_name="Champ")#Quel champ de l’email analyser
    operator = models.CharField(max_length=50, choices=OPERATOR_CHOICES, verbose_name="Opérateur")
    value = models.TextField(verbose_name="Valeur")
    negate = models.BooleanField(default=False, verbose_name="Négation (NOT)")
    class Meta:
        verbose_name = "Règle de playbook"
        verbose_name_plural = "Règles de playbooks"
        ordering = ['playbook', 'id']  # Pour maintenir l'ordre

    def evaluate(self, email):
        """Évalue si la règle correspond à l'email"""
        email_value = getattr(email, self.field, None)
        
        if not email_value:
            return False
            
        if isinstance(email_value, bool):
            email_value = str(email_value)
        
        operator = self.operator
        rule_value = self.value
        
        try:
            if operator == 'contains':
                result = rule_value.lower() in str(email_value).lower()
            elif operator == 'equals':
                result = str(email_value).lower() == rule_value.lower()
            elif operator == 'startswith':
                result = str(email_value).lower().startswith(rule_value.lower())
            elif operator == 'endswith':
                result = str(email_value).lower().endswith(rule_value.lower())
            elif operator == 'regex':
                import re
                result = bool(re.search(rule_value, str(email_value), re.IGNORECASE))
            elif operator == 'gt':
                result = float(email_value) > float(rule_value)
            elif operator == 'gte':
                result = float(email_value) >= float(rule_value)
            elif operator == 'lt':
                result = float(email_value) < float(rule_value)
            elif operator == 'lte':
                result = float(email_value) <= float(rule_value)
            else:
                result = False
                
            return not result if self.negate else result
            
        except (ValueError, AttributeError):
            return False

    def __str__(self):
        return f"{self.field} {self.operator} '{self.value[:50]}'"


class PlaybookAction(models.Model):
    """Action à exécuter quand un playbook est déclenché"""
    
    ACTION_CHOICES = [
        ('quarantine', 'Mettre en quarantaine'),
        ('delete', 'Supprimer l\'email'),
        ('move_to_folder', 'Déplacer vers dossier'),
        ('mark_as_read', 'Marquer comme lu'),
        ('mark_as_unread', 'Marquer comme non lu'),
        ('forward', 'Transférer à'),
        ('reply', 'Répondre avec un modèle'),
        ('notify', 'Notifier par email'),
        ('log_only', 'Seulement journaliser'),
        ('create_ticket', 'Créer un ticket'),
        ('block_sender', 'Bloquer l\'expéditeur'),
    ]

    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='actions')
    action_type = models.CharField(max_length=50, choices=ACTION_CHOICES, verbose_name="Type d'action")
    parameters = models.JSONField(default=dict, verbose_name="Paramètres")
    order = models.IntegerField(default=1, verbose_name="Ordre d'exécution")
    delay_seconds = models.IntegerField(default=0, verbose_name="Délai avant exécution (secondes)")

    class Meta:
        verbose_name = "Action de playbook"
        verbose_name_plural = "Actions de playbooks"
        ordering = ['order']

    def __str__(self):
        return f"{self.get_action_type_display()} (Ordre: {self.order})"


class IncidentLog(models.Model):
    """Journal des incidents et actions exécutées"""
    
    STATUS_CHOICES = [
        ('detected', 'Détecté'),
        ('quarantined', 'Mis en quarantaine'),
        ('deleted', 'Supprimé'),
        ('resolved', 'Résolu'),
        ('false_positive', 'Faux positif'),
    ]

    email = models.ForeignKey(EmailMessage, on_delete=models.CASCADE, related_name='incidents')
    playbook = models.ForeignKey(Playbook, on_delete=models.SET_NULL, null=True, blank=True, related_name='incidents')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='detected', verbose_name="Statut")
    actions_executed = models.JSONField(default=list, verbose_name="Actions exécutées")
    notes = models.TextField(blank=True, verbose_name="Notes")
    resolved_at = models.DateTimeField(null=True, blank=True, verbose_name="Résolu à")
    resolved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_incidents')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Journal d'incident"
        verbose_name_plural = "Journaux d'incidents"
        ordering = ['-created_at']

    def __str__(self):
        return f"Incident #{self.id} - {self.email.subject[:50]}"