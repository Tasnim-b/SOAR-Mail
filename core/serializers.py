
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from .models import EmailAccount, EmailMessage, QuarantineEmail

User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom serializer to use email for authentication."""
    # Override the default 'username' field to accept an email
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    # This tells the serializer to validate using the 'email' field
    def validate(self, attrs):
        # Rename 'email' to 'username' for the parent class's validation logic
        attrs['username'] = attrs.get('email')
        return super().validate(attrs)

    @classmethod
    def get_token(cls, user):
        """Add custom claims to the token (optional)."""
        token = super().get_token(user)
        # Add user email to the token payload for easy identification
        token['email'] = user.email
        return token
    






class EmailAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailAccount
        fields = ['id', 'name', 'email', 'imap_server', 'imap_port', 
                  'username', 'use_ssl', 'is_active', 'created_at']
        read_only_fields = ['created_at']

class EmailMessageSerializer(serializers.ModelSerializer):
    threat_status = serializers.SerializerMethodField()
    analysis_summary = serializers.SerializerMethodField()
    formatted_date = serializers.SerializerMethodField()
    
    class Meta:
        model = EmailMessage
        fields = [
            'id', 'uid', 'message_id', 'sender', 'sender_name', 
            'subject', 'received_date', 'formatted_date', 'size',
            'threat_level', 'threat_type', 'risk_score', 'threat_status',
            'analysis_summary', 'has_attachments', 'is_read', 'is_encrypted',
            'analyzed', 'analysis_date','body_text', 'body_html'
        ]
    
    def get_threat_status(self, obj):
        """Mapper le niveau de menace vers une classification simple"""
        if obj.threat_level == 'SAFE':
            return 'safe'
        elif obj.threat_level in ['LOW', 'MEDIUM']:
            return 'suspicious'
        else:  # HIGH, CRITICAL
            return 'malicious'
    
    def get_analysis_summary(self, obj):
        """Créer un résumé de l'analyse"""
        if obj.threat_type == 'NONE':
            return 'Aucune menace détectée'
        
        summary = []
        if obj.threat_type == 'PHISHING':
            summary.append('Phishing')
        if obj.threat_type == 'MALWARE':
            summary.append('Malware')
        if obj.threat_type in ['SPAM', 'SUSPICIOUS']:
            summary.append('Spam/Suspect')
        
        return ', '.join(summary) if summary else 'Menace détectée'
    
    def get_formatted_date(self, obj):
        """Formater la date pour l'affichage"""
        return obj.received_date.strftime('%Y-%m-%d %H:%M')
    
    def get_preview(self, obj):
        """Créer un aperçu du contenu de l'email"""
        text = obj.body_text or obj.body_html
        if text:
            # Nettoyer le HTML si présent
            import re
            clean_text = re.sub(r'<[^>]+>', '', text)
            clean_text = re.sub(r'\s+', ' ', clean_text)
            return (clean_text[:100] + '...') if len(clean_text) > 100 else clean_text
        return "Aucun contenu"
    

    def get_sender_info(self, obj):
        """Formater les informations de l'expéditeur pour le frontend"""
        return {
            'name': obj.sender_name or obj.sender.split('@')[0],
            'email': obj.sender
        }
  
    
    def _get_reputation_text(self, risk_score):
        """Convertir le score de risque en texte de réputation"""
        if risk_score <= 20:
            return 'very_high'
        elif risk_score <= 40:
            return 'high'
        elif risk_score <= 60:
            return 'medium'
        elif risk_score <= 80:
            return 'low'
        else:
            return 'very_low'
         





class QuarantineEmailSerializer(serializers.ModelSerializer):
    """Sérialiseur pour les emails en quarantaine"""
    
    quarantined_since = serializers.SerializerMethodField()
    days_in_quarantine = serializers.SerializerMethodField()
    original_email_id = serializers.SerializerMethodField()
    
    class Meta:
        model = QuarantineEmail
        fields = [
            'id', 'original_email_id', 'sender', 'sender_name', 'subject',
            'received_date', 'threat_type', 'risk_score', 'analysis_summary',
            'quarantined_at', 'expires_at', 'quarantined_since',
            'days_in_quarantine', 'is_restored', 'reason', 'size',
            'has_attachments', 'body_text', 'body_html', 'attachments'
        ]
    
    def get_quarantined_since(self, obj):
        """Calculer combien de temps l'email est en quarantaine"""
        from django.utils import timezone
        delta = timezone.now() - obj.quarantined_at
        days = delta.days
        if days == 0:
            hours = delta.seconds // 3600
            if hours == 0:
                minutes = delta.seconds // 60
                return f"{minutes} minutes"
            return f"{hours} heures"
        return f"{days} jours"
    
    def get_days_in_quarantine(self, obj):
        """Nombre de jours exacts en quarantaine"""
        from django.utils import timezone
        delta = timezone.now() - obj.quarantined_at
        return delta.days
    
    def get_original_email_id(self, obj):
        """ID de l'email original"""
        return obj.original_email.id