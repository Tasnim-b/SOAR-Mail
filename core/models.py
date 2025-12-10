# core/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

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