
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect
from django.middleware.csrf import get_token
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import UntypedToken
from .serializers import CustomTokenObtainPairSerializer,EmailMessageSerializer,QuarantineEmailSerializer
from .models import EmailAccount, EmailMessage,QuarantineEmail,IncidentLog
from rest_framework import generics, filters
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from datetime import datetime, timedelta
import json

User = get_user_model()
#la vue qui permet de se connecter via email + mot de passe: Login JWT
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    View for obtaining JWT tokens (Login).
    Takes email and password, returns access and refresh tokens.
    """
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]  # Allow unauthenticated access for login

    def post(self, request, *args, **kwargs):
        # You can add custom logic here (e.g., logging login attempts)
        return super().post(request, *args, **kwargs)

#la vue qui permet de rafraichir le token d'accès via le token de rafraichissement: Refresh JWT
class CustomTokenRefreshView(TokenRefreshView):
    """
    View for refreshing an access token using a valid refresh token.
    """
    pass  # Uses the default behavior, which is fine

#la vue qui permet de se déconnecter en invalidant le token de rafraichissement: Logout JWT
class LogoutView(APIView):
    """
    View for secure logout.
    Blacklists the provided refresh token to prevent its future use[citation:2].
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            token = RefreshToken(refresh_token)
            #le refresh token est ajouté à la liste noire pour l'invalider lors de la déconnexion et empêcher son utilisation future
            token.blacklist()  # Requires 'rest_framework_simplejwt.token_blacklist': 
            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_205_RESET_CONTENT
            )
        except TokenError as e:
            return Response(
                {"error": f"Invalid or expired refresh token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )





def login_page(request):
    """Page HTML vide qui chargera le JavaScript pour l'authentification"""
    return render(request, "login.html")

def dashboard_page(request):
    """Page du dashboard protégée - redirige vers login si non authentifié"""
    # Cette vue vérifie que l'utilisateur accède via JavaScript avec un token JWT valide
    # Le JWT sera validé côté client et envoyé dans les headers Authorization
    return render(request, "dashboard.html")


#la vue protégée qui nécessite une authentification JWT: Protected API View

class ProtectedDashboardView(APIView):
    """
    API pour le dashboard avec les vraies données
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
      
        
        # Récupérer les vraies statistiques
        total_emails = EmailMessage.objects.count()
        threats_detected = EmailMessage.objects.exclude(threat_level='SAFE').count()
        
        # Emails aujourd'hui
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        incidents_today = EmailMessage.objects.filter(
            received_date__gte=today_start,
            threat_level__in=['HIGH', 'CRITICAL']
        ).count()
        
        # Distribution par type de menace
        threat_distribution = EmailMessage.objects.exclude(threat_type='NONE').values(
            'threat_type'
        ).annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Incidents récents
        recent_incidents = EmailMessage.objects.filter(
            threat_level__in=['HIGH', 'CRITICAL']
        ).order_by('-received_date')[:10]
        
        # Préparer les données pour le graphique (normaliser en minuscules pour le front)
        threat_types_data = {item['threat_type'].lower(): item['count'] for item in threat_distribution}
        
        # Activité des dernières 24h
        hours_data = []
        for i in range(24):
            hour_start = timezone.now() - timedelta(hours=i+1)
            hour_end = timezone.now() - timedelta(hours=i)
            count = EmailMessage.objects.filter(
                received_date__range=[hour_start, hour_end],
                threat_level__in=['MEDIUM', 'HIGH', 'CRITICAL']
            ).count()
            hours_data.append({
                'hour': hour_start.strftime('%H:00'),
                'count': count
            })
        
        hours_data.reverse()
        recent_incidents_log = IncidentLog.objects.select_related('email', 'playbook').order_by('-created_at')[:10]
        
        return Response({
            "user": {
                "email": request.user.email,
                "is_staff": request.user.is_staff,
            },
            "stats": {
                "emails_analyzed": total_emails,
                "threats_detected": threats_detected,
                "incidents_today": incidents_today,
                # Comptabilise les incidents marqués 'resolved' sans utilisateur (résolus automatiquement)
                "auto_resolved": IncidentLog.objects.filter(status='resolved', resolved_by__isnull=True).count(),

            },
            "charts": {
                "threat_types": threat_types_data,
                "activity": {
                    "labels": [item['hour'] for item in hours_data],
                    "data": [item['count'] for item in hours_data]
                }
            },
            "recent_incidents": [
                {
                    "id": incident.id,
                    "type": incident.get_threat_type_display(),
                    "email": incident.sender,
                    "date": incident.received_date.strftime('%Y-%m-%d %H:%M'),
                    "status": "Élevé" if incident.threat_level in ['HIGH', 'CRITICAL'] else "Moyen"
                }
                for incident in recent_incidents
            ],
            "message": "Dashboard SOAR-Mail",
            "recent_incidents_log": [
                {
                    "id": incident.id,
                    "email_subject": incident.email.subject[:50] + "..." if len(incident.email.subject) > 50 else incident.email.subject,
                    "playbook": incident.playbook.name if incident.playbook else "Aucun",
                    "status": incident.get_status_display(),
                    "created_at": incident.created_at.strftime('%Y-%m-%d %H:%M'),
                    "actions_count": len(incident.actions_executed)
                }
                for incident in recent_incidents_log
            ],
        })
    




# Vue pour la page HTML des emails analysés
def emails_page(request):
    """Page des emails analysés protégée"""
    return render(request, "emails.html")

# Pagination personnalisée pour les emails
class EmailPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

# Vue API pour récupérer les emails analysés
class EmailListView(generics.ListAPIView):
    """
    API pour récupérer la liste des emails analysés avec filtres et pagination
    """
    permission_classes = [IsAuthenticated]
    pagination_class = EmailPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    serializer_class = EmailMessageSerializer
    
    filterset_fields = ['threat_level', 'threat_type', 'has_attachments', 'is_read']
    search_fields = ['sender', 'sender_name', 'subject', 'body_text']
    
    def get_queryset(self):
        queryset = EmailMessage.objects.filter(is_quarantined=False).order_by('-received_date')
        
        # Filtre par date
        date_filter = self.request.query_params.get('date_filter', None)
        if date_filter:
            today = timezone.now().date()
            if date_filter == 'today':
                queryset = queryset.filter(received_date__date=today)
            elif date_filter == 'week':
                week_ago = today - timedelta(days=7)
                queryset = queryset.filter(received_date__date__gte=week_ago)
            elif date_filter == 'month':
                month_ago = today - timedelta(days=30)
                queryset = queryset.filter(received_date__date__gte=month_ago)
        
        # Filtre par expéditeur spécifique
        sender_filter = self.request.query_params.get('sender', None)
        if sender_filter:
            queryset = queryset.filter(sender__icontains=sender_filter)
        
        # Filtre par sujet spécifique
        subject_filter = self.request.query_params.get('subject', None)
        if subject_filter:
            queryset = queryset.filter(subject__icontains=subject_filter)
        
        # Filtre par statut de menace (adapté au frontend)
        threat_status = self.request.query_params.get('threat_status', None)
        if threat_status:
            if threat_status == 'safe':
                queryset = queryset.filter(threat_level='SAFE')
            elif threat_status == 'suspicious':
                queryset = queryset.filter(threat_level__in=['LOW', 'MEDIUM'])
            elif threat_status == 'malicious':
                queryset = queryset.filter(threat_level__in=['HIGH', 'CRITICAL'])
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        
        # Obtenir les statistiques avant la pagination
        total = queryset.count()
        safe_count = queryset.filter(threat_level='SAFE').count()
        suspicious_count = queryset.filter(threat_level__in=['LOW', 'MEDIUM']).count()
        malicious_count = queryset.filter(threat_level__in=['HIGH', 'CRITICAL']).count()
        
        # Paginer les résultats
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'stats': {
                    'total': total,
                    'safe': safe_count,
                    'suspicious': suspicious_count,
                    'malicious': malicious_count
                },
                'emails': serializer.data
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'stats': {
                'total': total,
                'safe': safe_count,
                'suspicious': suspicious_count,
                'malicious': malicious_count
            },
            'emails': serializer.data
        })

# Vue API pour les détails d'un email
class EmailDetailView(generics.RetrieveAPIView):
    """
    API pour récupérer les détails d'un email spécifique
    """
    permission_classes = [IsAuthenticated]
    queryset = EmailMessage.objects.all()
    # URL uses <int:pk> for detail routes, keep default lookup 'pk'
    lookup_field = 'pk'
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Convertir le champ JSON attachments si nécessaire
        attachments = instance.attachments
        if isinstance(attachments, str):
            try:
                attachments = json.loads(attachments)
            except:
                attachments = []
        
        # Préparer les données pour le frontend
        data = {
            'id': instance.id,
            'sender': {
                'name': instance.sender_name,
                'email': instance.sender
            },
            'subject': instance.subject,
            'date': instance.received_date.strftime('%Y-%m-%d %H:%M'),
            'threatStatus': self._map_threat_status(instance.threat_level),
            'threatScore': instance.risk_score,
            'analysis': {
                'phishing': instance.threat_type == 'PHISHING',
                'malware': instance.threat_type == 'MALWARE',
                'spam': instance.threat_type in ['SPAM', 'SUSPICIOUS'],
                'reputation': self._get_reputation(instance.risk_score)
            },
            'body': instance.body_text or instance.body_html,
            'body_text': instance.body_text, 
            'body_html': instance.body_html, 
            'attachments': attachments,
            'recipients': instance.recipients,
            'size': instance.size,
            'has_attachments': instance.has_attachments,
            'is_read': instance.is_read,
            'is_encrypted': instance.is_encrypted
        }
        
        return Response(data)
    
    def _map_threat_status(self, threat_level):
        """Mapper les niveaux de menace Django vers le frontend"""
        if threat_level == 'SAFE':
            return 'safe'
        elif threat_level in ['LOW', 'MEDIUM']:
            return 'suspicious'
        else:  # HIGH, CRITICAL
            return 'malicious'
    
    def _get_reputation(self, risk_score):
        """Déterminer la réputation basée sur le score de risque"""
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

# Vue API pour marquer un email comme sûr
class MarkEmailSafeView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = EmailMessage.objects.all()
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.threat_level = 'SAFE'
        instance.risk_score = 10
        instance.threat_type = 'NONE'
        instance.is_read = True
        instance.save()
        
        return Response({
            'message': 'Email marqué comme sûr',
            'threatStatus': 'safe',
            'threatScore': instance.risk_score
        })
    
    # Support POST from frontend convenience (was using POST)
    def post(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

# Vue API pour mettre en quarantaine un email
class QuarantineEmailView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = EmailMessage.objects.all()
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        # Créer un enregistrement de quarantaine
        quarantine_email = QuarantineEmail.objects.create(
            original_email=instance,
            sender=instance.sender,
            sender_name=instance.sender_name,
            subject=instance.subject,
            received_date=instance.received_date,
            body_text=instance.body_text,
            body_html=instance.body_html,
            attachments=instance.attachments,
            threat_type=instance.threat_type,
            risk_score=instance.risk_score,
            analysis_summary=self._get_analysis_summary(instance),
            quarantined_by=request.user,
            reason=request.data.get('reason', 'Mise en quarantaine manuelle'),
            size=instance.size,
            has_attachments=instance.has_attachments
        )
        instance.is_quarantined = True
        instance.threat_level = 'MEDIUM'
        instance.risk_score = 50
        instance.is_read = True
        instance.save()
        
        return Response({
            'message': 'Email mis en quarantaine',
            'quarantine_id': quarantine_email.id,
            'threatStatus': 'suspicious',
            'threatScore': instance.risk_score
        })
    def _get_analysis_summary(self, email):
        """Générer un résumé d'analyse"""
        if email.threat_type == 'PHISHING':
            return f"Email de phishing détecté (score: {email.risk_score}%)"
        elif email.threat_type == 'MALWARE':
            return f"Email contenant du malware (score: {email.risk_score}%)"
        elif email.threat_type == 'SPAM':
            return f"Email de spam suspect (score: {email.risk_score}%)"
        elif email.threat_type == 'SUSPICIOUS':
            return f"Email suspect (score: {email.risk_score}%)"
        else:
            return f"Email mis en quarantaine (score: {email.risk_score}%)"
    
    # Support POST from frontend convenience
    def post(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

class QuarantineListView(generics.ListAPIView):
    """API pour récupérer la liste des emails en quarantaine"""
    permission_classes = [IsAuthenticated]
    serializer_class = QuarantineEmailSerializer
    pagination_class = EmailPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    
    filterset_fields = ['threat_type', 'is_restored', 'has_attachments']
    search_fields = ['sender', 'sender_name', 'subject', 'body_text']
    
    def get_queryset(self):
        queryset = QuarantineEmail.objects.filter(is_restored=False).order_by('-quarantined_at')
        
        # Filtre par type de menace
        threat_type = self.request.query_params.get('threat_type', None)
        if threat_type and threat_type != 'all':
            queryset = queryset.filter(threat_type=threat_type.upper())
        
        # Filtre par date
        date_filter = self.request.query_params.get('date_filter', None)
        if date_filter:
            today = timezone.now().date()
            if date_filter == 'today':
                queryset = queryset.filter(quarantined_at__date=today)
            elif date_filter == 'week':
                week_ago = today - timezone.timedelta(days=7)
                queryset = queryset.filter(quarantined_at__date__gte=week_ago)
            elif date_filter == 'month':
                month_ago = today - timezone.timedelta(days=30)
                queryset = queryset.filter(quarantined_at__date__gte=month_ago)
            elif date_filter == 'older':
                thirty_days_ago = today - timezone.timedelta(days=30)
                queryset = queryset.filter(quarantined_at__date__lt=thirty_days_ago)
        
        # Filtre par expéditeur
        sender_filter = self.request.query_params.get('sender_filter', None)
        if sender_filter and sender_filter != 'all':
            if sender_filter == 'unknown':
                queryset = queryset.filter(sender_name='')
            elif sender_filter == 'suspicious':
                queryset = queryset.filter(sender__icontains='unknown')
            elif sender_filter == 'blacklisted':
                # Ici vous pourriez filtrer par une liste noire
                queryset = queryset.filter(sender__icontains='spam')
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        
        # Calculer les statistiques
        total = queryset.count()
        phishing_count = queryset.filter(threat_type='PHISHING').count()
        malware_count = queryset.filter(threat_type='MALWARE').count()
        spam_count = queryset.filter(threat_type='SPAM').count()
        
        # Calculer le plus ancien email en quarantaine
        oldest = queryset.order_by('quarantined_at').first()
        oldest_days = 0
        if oldest:
            delta = timezone.now() - oldest.quarantined_at
            oldest_days = delta.days
        
        # Paginer les résultats
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated_response = self.get_paginated_response(serializer.data)
            # Modifier le response data pour inclure les statistiques et quarantined_emails
            paginated_response.data['stats'] = {
                'total': total,
                'phishing': phishing_count,
                'malware': malware_count,
                'spam': spam_count,
                'oldest_days': oldest_days
            }
            paginated_response.data['quarantined_emails'] = serializer.data
            return paginated_response
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': total,
            'results': serializer.data,
            'stats': {
                'total': total,
                'phishing': phishing_count,
                'malware': malware_count,
                'spam': spam_count,
                'oldest_days': oldest_days
            },
            'quarantined_emails': serializer.data
        })


class QuarantineDetailView(generics.RetrieveAPIView):
    """API pour récupérer les détails d'un email en quarantaine"""
    permission_classes = [IsAuthenticated]
    serializer_class = QuarantineEmailSerializer
    queryset = QuarantineEmail.objects.all()
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

class RestoreQuarantineEmailView(generics.UpdateAPIView):
    """API pour restaurer un email de la quarantaine"""
    permission_classes = [IsAuthenticated]
    queryset = QuarantineEmail.objects.filter(is_restored=False)
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Marquer l'email original comme non quarantaine
        instance.original_email.is_quarantined = False
        instance.original_email.save()
        
        # Marquer l'email en quarantaine comme restauré
        instance.is_restored = True
        instance.restored_at = timezone.now()
        instance.restored_by = request.user
        instance.save()
        
        return Response({
            'message': 'Email restauré avec succès',
            'email_id': instance.original_email.id,
            'quarantine_id': instance.id
        })
    
    # Support POST from frontend convenience (allow POST to perform restore)
    def post(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

class DeleteQuarantineEmailView(generics.DestroyAPIView):
    """API pour supprimer définitivement un email de la quarantaine"""
    permission_classes = [IsAuthenticated]
    queryset = QuarantineEmail.objects.filter(is_restored=False)
    lookup_field = 'id'
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        original_email_id = instance.original_email.id
        
        # Supprimer l'email original
        instance.original_email.delete()
        
        # Supprimer l'enregistrement de quarantaine
        instance.delete()
        
        return Response({
            'message': 'Email supprimé définitivement',
            'email_id': original_email_id
        })

class BulkRestoreQuarantineView(APIView):
    """API pour restaurer plusieurs emails de la quarantaine"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        email_ids = request.data.get('email_ids', [])
        
        if not email_ids:
            return Response({'error': 'Aucun email sélectionné'}, status=400)
        
        quarantined_emails = QuarantineEmail.objects.filter(
            id__in=email_ids, 
            is_restored=False
        )
        
        restored_count = 0
        for q_email in quarantined_emails:
            # Marquer l'email original comme non quarantaine
            q_email.original_email.is_quarantined = False
            q_email.original_email.save()
            
            # Marquer comme restauré
            q_email.is_restored = True
            q_email.restored_at = timezone.now()
            q_email.restored_by = request.user
            q_email.save()
            restored_count += 1
        
        return Response({
            'message': f'{restored_count} email(s) restauré(s) avec succès',
            'restored_count': restored_count
        })

class BulkDeleteQuarantineView(APIView):
    """API pour supprimer plusieurs emails de la quarantaine"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        email_ids = request.data.get('email_ids', [])
        
        if not email_ids:
            return Response({'error': 'Aucun email sélectionné'}, status=400)
        
        quarantined_emails = QuarantineEmail.objects.filter(
            id__in=email_ids, 
            is_restored=False
        )
        
        deleted_count = 0
        for q_email in quarantined_emails:
            # Supprimer l'email original
            q_email.original_email.delete()
            q_email.delete()
            deleted_count += 1
        
        return Response({
            'message': f'{deleted_count} email(s) supprimé(s) définitivement',
            'deleted_count': deleted_count
        })


# Vue API pour supprimer un email
class DeleteEmailView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = EmailMessage.objects.all()
    lookup_field = 'id'
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        email_id = instance.id
        instance.delete()
        
        return Response({
            'message': 'Email supprimé',
            'emailId': email_id
        })

# Vue API pour démarrer une nouvelle analyse
class StartScanView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Ici, vous ajouterez la logique pour déclencher une nouvelle analyse IMAP
        # Pour l'instant, nous simulons une analyse
        
        # En production, vous appelleriez une tâche asynchrone ici
        # Par exemple: tasks.scan_emails.delay()
        
        return Response({
            'message': 'Analyse des emails lancée',
            'scan_id': 'scan_' + str(int(timezone.now().timestamp())),
            'status': 'started'
        })
    
# Vue pour la page HTML des playbooks
def playbooks_page(request):
    """Page des playbooks protégée"""
    return render(request, "playbooks.html")


#vue pour la page HTML des quarantaines
def quarantaine_page(request):
    """Page des quarantaines protégée"""
    return render(request, "quarantaine.html")

#vue pour la page HTML des statiqtiques
def statistiques_page(request):
    """Page des statistiques protégée"""
    return render(request, "statistiques.html")


from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.db.models import Count, Sum
from .models import Playbook, PlaybookRule, PlaybookAction, IncidentLog, EmailMessage
from .serializers import PlaybookSerializer, IncidentLogSerializer

# ============ VUES POUR LES PLAYBOOKS ============

class PlaybookListView(generics.ListAPIView):
    """Liste tous les playbooks"""
    queryset = Playbook.objects.all().order_by('-created_at')
    serializer_class = PlaybookSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filtrage par statut
        status_filter = self.request.query_params.get('status')
        if status_filter == 'active':
            queryset = queryset.filter(is_active=True)
        elif status_filter == 'inactive':
            queryset = queryset.filter(is_active=False)
        
        # Filtrage par priorité
        priority = self.request.query_params.get('priority')
        if priority:
            queryset = queryset.filter(priority=priority)
        
        return queryset

class PlaybookCreateView(generics.CreateAPIView):
    """Crée un nouveau playbook"""
    serializer_class = PlaybookSerializer
    permission_classes = [IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        # Log request data for debugging
        try:
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Playbook create payload: {request.data}")
        except:
            pass

        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            # Log errors server-side to appear in runserver console
            try:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Playbook validation failed: {serializer.errors}")
            except Exception:
                print("Playbook validation failed:", serializer.errors)

            # Return detailed errors to help frontend debugging
            return Response({
                'status': 'error',
                'message': 'Validation failed',
                'errors': serializer.errors,
                'payload': request.data
            }, status=status.HTTP_400_BAD_REQUEST)

        # Save with created_by set to the requesting user
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class PlaybookDetailView(generics.RetrieveAPIView):
    """Détail d'un playbook"""
    queryset = Playbook.objects.all()
    serializer_class = PlaybookSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

class PlaybookUpdateView(generics.UpdateAPIView):
    """Met à jour un playbook"""
    queryset = Playbook.objects.all()
    serializer_class = PlaybookSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

class PlaybookDeleteView(generics.DestroyAPIView):
    """Supprime un playbook"""
    queryset = Playbook.objects.all()
    serializer_class = PlaybookSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

class PlaybookToggleActiveView(APIView):
    """Active/désactive un playbook"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, id):
        playbook = get_object_or_404(Playbook, id=id)
        playbook.is_active = not playbook.is_active
        playbook.save()
        
        return Response({
            'status': 'success',
            'message': f'Playbook {"activé" if playbook.is_active else "désactivé"}',
            'is_active': playbook.is_active
        })

class PlaybookTestView(APIView):
    """Teste un playbook sur un email spécifique"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, id):
        playbook = get_object_or_404(Playbook, id=id)
        email_id = request.data.get('email_id')
        
        if not email_id:
            return Response({
                'error': 'email_id est requis'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            email = EmailMessage.objects.get(id=email_id)
            
            # Évaluer les règles
            from .services.playbook_executor import PlaybookExecutor
            executor = PlaybookExecutor(email)
            rules_passed = executor.evaluate_rules(playbook.rules.all())
            
            if rules_passed:
                # Simuler les actions
                actions = playbook.actions.all().order_by('order')
                simulated_actions = []
                
                for action in actions:
                    simulated_actions.append({
                        'action_type': action.action_type,
                        'action_name': action.get_action_type_display(),
                        'parameters': action.parameters,
                        'order': action.order
                    })
                
                return Response({
                    'status': 'success',
                    'rules_passed': True,
                    'message': f'Le playbook se déclencherait pour cet email',
                    'actions': simulated_actions,
                    'email': {
                        'id': email.id,
                        'subject': email.subject[:50],
                        'sender': email.sender,
                        'risk_score': email.risk_score,
                        'threat_type': email.get_threat_type_display()
                    }
                })
            else:
                return Response({
                    'status': 'success',
                    'rules_passed': False,
                    'message': 'Les règles du playbook ne correspondent pas à cet email'
                })
                
        except EmailMessage.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Email non trouvé'
            }, status=status.HTTP_404_NOT_FOUND)

class PlaybookStatsView(APIView):
    """Statistiques des playbooks"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        total_playbooks = Playbook.objects.count()
        active_playbooks = Playbook.objects.filter(is_active=True).count()
        total_executions = Playbook.objects.aggregate(total=Sum('execution_count'))['total'] or 0
        
        # Menaces bloquées (incidents créés)
        threats_blocked = IncidentLog.objects.count()
        
        return Response({
            'total_playbooks': total_playbooks,
            'active_playbooks': active_playbooks,
            'total_executions': total_executions,
            'threats_blocked': threats_blocked
        })
    



from .serializers import PlaybookRuleSerializer, PlaybookActionSerializer
class PlaybookRuleCreateView(generics.CreateAPIView):
    """Crée une règle pour un playbook"""
    serializer_class = PlaybookRuleSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        playbook_id = self.kwargs.get('playbook_id')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        serializer.save(playbook=playbook)

class PlaybookActionCreateView(generics.CreateAPIView):
    """Crée une action pour un playbook"""
    serializer_class = PlaybookActionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        playbook_id = self.kwargs.get('playbook_id')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        serializer.save(playbook=playbook)














# ============ VUES POUR LES INCIDENTS ============

class IncidentLogListView(generics.ListAPIView):
    """Liste des incidents"""
    serializer_class = IncidentLogSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = IncidentLog.objects.all().order_by('-created_at')
        
        # Filtrage par playbook
        playbook_id = self.request.query_params.get('playbook_id')
        if playbook_id:
            queryset = queryset.filter(playbook_id=playbook_id)
        
        # Filtrage par statut
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Limite
        limit = self.request.query_params.get('limit', 50)
        return queryset[:int(limit)]

class IncidentLogDetailView(generics.RetrieveAPIView):
    """Détail d'un incident"""
    queryset = IncidentLog.objects.all()
    serializer_class = IncidentLogSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'


#statistiques page
# ============ VUES POUR LES STATISTIQUES ============

from django.db.models import Count, Avg, Q, F, Sum, Case, When
from django.db.models.functions import TruncDate, TruncWeek, TruncMonth
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from django.db.models import Max, Count
from django.db.models.expressions import ExpressionWrapper
from django.db import models
class StatsKPIsView(APIView):
    """KPIs principaux pour le tableau de bord"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Calculer la période (par défaut 7 jours)
        days = int(request.query_params.get('days', 7))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Période précédente pour les tendances (même durée)
        previous_start_date = start_date - timedelta(days=days)
        previous_end_date = start_date
        
        # 1. Emails analysés (TOUS les emails de la période)
        total_emails_current = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date]
        ).count()
        
        # 2. Emails analysés (période précédente)
        total_emails_previous = EmailMessage.objects.filter(
            received_date__range=[previous_start_date, previous_end_date]
        ).count()
        
        # 3. Menaces détectées (cohérent avec le dashboard : threat_level != 'SAFE')
        threats_current = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            analyzed=True
        ).exclude(threat_level='SAFE').count()
        
        # 4. Menaces détectées (période précédente)
        threats_previous = EmailMessage.objects.filter(
            received_date__range=[previous_start_date, previous_end_date],
            analyzed=True
        ).exclude(threat_level='SAFE').count()
        
        # 5. Taux de détection (par rapport aux emails analysés seulement)
        analyzed_emails_current = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            analyzed=True
        ).count()
        
        if analyzed_emails_current > 0:
            detection_rate_current = (threats_current / analyzed_emails_current) * 100
        else:
            detection_rate_current = 0
            
        analyzed_emails_previous = EmailMessage.objects.filter(
            received_date__range=[previous_start_date, previous_end_date],
            analyzed=True
        ).count()
        
        if analyzed_emails_previous > 0:
            detection_rate_previous = (threats_previous / analyzed_emails_previous) * 100
        else:
            detection_rate_previous = 0
        
        # 6. Temps moyen de réponse (seulement pour les emails analysés)
        # Filtrer seulement les emails avec analysis_date non nul et dans la période
        response_times = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            analyzed=True,
            analysis_date__isnull=False,
            analysis_date__gte=F('received_date')  # S'assurer que l'analyse est après réception
        ).annotate(
            response_time=ExpressionWrapper(
                F('analysis_date') - F('received_date'),
                output_field=models.DurationField()
            )
        ).filter(
            response_time__gte=timedelta(0)  # Temps positif seulement
        ).aggregate(
            avg_response=Avg('response_time')
        )
        
        # Convertir en secondes (max 1 heure pour éviter les valeurs aberrantes)
        if response_times['avg_response']:
            avg_response_seconds = min(response_times['avg_response'].total_seconds(), 3600)
        else:
            avg_response_seconds = 0
        
        # Récupérer la valeur précédente pour le temps de réponse
        response_times_previous = EmailMessage.objects.filter(
            received_date__range=[previous_start_date, previous_end_date],
            analyzed=True,
            analysis_date__isnull=False,
            analysis_date__gte=F('received_date')
        ).annotate(
            response_time=ExpressionWrapper(
                F('analysis_date') - F('received_date'),
                output_field=models.DurationField()
            )
        ).filter(
            response_time__gte=timedelta(0)
        ).aggregate(
            avg_response=Avg('response_time')
        )
        
        if response_times_previous['avg_response']:
            avg_response_seconds_previous = min(response_times_previous['avg_response'].total_seconds(), 3600)
        else:
            avg_response_seconds_previous = 0
        
        # Calcul des tendances (éviter la division par zéro)
        def calculate_trend(current, previous):
            if previous == 0:
                if current == 0:
                    return 0
                else:
                    return 100.0  # De 0 à X -> +100%
            return round(((current - previous) / previous) * 100, 1)
        
        # Pour le temps de réponse, une diminution est positive
        response_trend = 0
        if avg_response_seconds_previous > 0 and avg_response_seconds > 0:
            response_trend = -round(((avg_response_seconds - avg_response_seconds_previous) / avg_response_seconds_previous) * 100, 1)
        
        return Response({
            'current_period': {
                'total_emails': total_emails_current,
                'threats_detected': threats_current,
                'detection_rate': round(detection_rate_current, 1),
                'avg_response_time': round(avg_response_seconds, 1)
            },
            'previous_period': {
                'total_emails': total_emails_previous,
                'threats_detected': threats_previous,
                'detection_rate': round(detection_rate_previous, 1),
                'avg_response_time': round(avg_response_seconds_previous, 1)
            },
            'trends': {
                'total_emails': calculate_trend(total_emails_current, total_emails_previous),
                'threats_detected': calculate_trend(threats_current, threats_previous),
                'detection_rate': calculate_trend(detection_rate_current, detection_rate_previous),
                'avg_response_time': response_trend
            },
            'period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        })
class StatsThreatDistributionView(APIView):
    """Répartition des types de menaces"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        days = int(request.query_params.get('days', 7))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Compter les menaces par type
        threat_distribution = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type__in=['PHISHING', 'MALWARE', 'SPAM', 'SUSPICIOUS', 'SPOOFING']
        ).values('threat_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Compter les emails sûrs
        safe_count = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type='NONE',
            threat_level='SAFE'
        ).count()
        
        # Formater les données pour Chart.js
        labels = []
        data = []
        background_colors = [
            'rgba(248, 150, 30, 0.8)',  # Phishing - orange
            'rgba(247, 37, 133, 0.8)',   # Malware - rose
            'rgba(108, 117, 125, 0.8)',  # Spam - gris
            'rgba(76, 201, 240, 0.8)',   # Suspect - bleu clair
            'rgba(114, 9, 183, 0.8)',    # Spoofing - violet
            'rgba(40, 167, 69, 0.8)'     # Safe - vert
        ]
        
        threat_names = {
            'PHISHING': 'Phishing',
            'MALWARE': 'Malware',
            'SPAM': 'Spam',
            'SUSPICIOUS': 'Suspect',
            'SPOOFING': 'Usurpation',
            'SAFE': 'Sûr'
        }
        
        # Ajouter les menaces
        total_threats = 0
        for item in threat_distribution:
            labels.append(threat_names.get(item['threat_type'], item['threat_type']))
            data.append(item['count'])
            total_threats += item['count']
        
        # Ajouter les emails sûrs
        if safe_count > 0:
            labels.append('Sûrs')
            data.append(safe_count)
        
        # Calculer les pourcentages
        total_emails = sum(data)
        percentages = [round((count / total_emails) * 100, 1) if total_emails > 0 else 0 for count in data]
        
        return Response({
            'labels': labels,
            'data': data,
            'percentages': percentages,
            'background_colors': background_colors[:len(labels)],
            'total_threats': total_threats,
            'total_emails': total_emails
        })

class StatsEmailTimelineView(APIView):
    """Évolution des emails dans le temps"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        days = int(request.query_params.get('days', 7))
        view_type = request.query_params.get('view', 'daily')
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Déterminer la fonction de truncation
        if view_type == 'weekly':
            trunc_func = TruncWeek('received_date')
        elif view_type == 'monthly':
            trunc_func = TruncMonth('received_date')
        else:  # daily
            trunc_func = TruncDate('received_date')
        
        # Récupérer les données par période
        timeline_data = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date]
        ).annotate(
            period=trunc_func
        ).values('period').annotate(
            total=Count('id'),
            safe=Count(Case(When(threat_type='NONE', threat_level='SAFE', then=1))),
            suspicious=Count(Case(When(threat_type='SUSPICIOUS', then=1))),
            malicious=Count(Case(
                When(threat_type__in=['PHISHING', 'MALWARE', 'SPAM', 'SPOOFING'], then=1)
            ))
        ).order_by('period')
        
        # Formater les données
        labels = []
        safe_data = []
        suspicious_data = []
        malicious_data = []
        
        for item in timeline_data:
            if item['period']:
                if view_type == 'daily':
                    labels.append(item['period'].strftime('%a'))
                elif view_type == 'weekly':
                    labels.append(f'S{item["period"].isocalendar()[1]}')
                else:  # monthly
                    labels.append(item['period'].strftime('%b'))
                
                safe_data.append(item['safe'])
                suspicious_data.append(item['suspicious'])
                malicious_data.append(item['malicious'])
        
        return Response({
            'labels': labels,
            'datasets': [
                {
                    'label': 'Sûrs',
                    'data': safe_data,
                    'backgroundColor': 'rgba(40, 167, 69, 0.5)',
                    'borderColor': 'rgba(40, 167, 69, 1)'
                },
                {
                    'label': 'Suspects',
                    'data': suspicious_data,
                    'backgroundColor': 'rgba(76, 201, 240, 0.5)',
                    'borderColor': 'rgba(76, 201, 240, 1)'
                },
                {
                    'label': 'Malveillants',
                    'data': malicious_data,
                    'backgroundColor': 'rgba(247, 37, 133, 0.5)',
                    'borderColor': 'rgba(247, 37, 133, 1)'
                }
            ]
        })

from django.db.models import Count, Max, F
from django.db.models.functions import Concat
from django.db import models

class StatsThreatSourcesView(APIView):
    """Top des sources de menaces"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        limit = int(request.query_params.get('limit', 10))
        
        # Pour SQLite, on utilise une approche différente
        # D'abord, on récupère les sources avec leur compte
        threat_sources = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type__in=['PHISHING', 'MALWARE', 'SPAM', 'SUSPICIOUS', 'SPOOFING']
        ).values('sender', 'sender_name').annotate(
            count=Count('id'),
            last_seen=Max('received_date'),
        ).order_by('-count')[:limit]
        
        # Ensuite, pour chaque source, on récupère les types de menaces uniques
        sources = []
        for source in threat_sources:
            # Récupérer les types de menaces distincts pour cette source
            threat_types_qs = EmailMessage.objects.filter(
                sender=source['sender'],
                received_date__range=[start_date, end_date]
            ).values_list('threat_type', flat=True).distinct()
            
            # Convertir en liste
            threat_types = list(threat_types_qs)
            
            # Déterminer le type de menace principal (le plus fréquent)
            if threat_types:
                # Compter les occurrences de chaque type
                type_counts = {}
                for t_type in threat_types_qs:
                    type_counts[t_type] = type_counts.get(t_type, 0) + 1
                
                # Prendre le type le plus fréquent
                main_threat = max(type_counts, key=type_counts.get)
            else:
                main_threat = 'SUSPICIOUS'
            
            sources.append({
                'sender': source['sender'],
                'sender_name': source['sender_name'] or source['sender'].split('@')[0],
                'domain': source['sender'].split('@')[-1] if '@' in source['sender'] else source['sender'],
                'threat_type': main_threat,
                'count': source['count'],
                'last_seen': source['last_seen'].strftime('%Y-%m-%d') if source['last_seen'] else None,
                'status': 'Active'
            })
        
        return Response({
            'sources': sources,
            'period_days': days
        })

class StatsRecentActivityView(APIView):
    """Activité récente (incidents et actions)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        limit = int(request.query_params.get('limit', 10))
        
        # Récupérer les incidents récents
        recent_incidents = IncidentLog.objects.select_related(
            'email', 'playbook'
        ).order_by('-created_at')[:limit]
        
        # Récupérer les playbooks récemment exécutés
        recent_playbooks = Playbook.objects.filter(
            execution_count__gt=0,
            last_executed__isnull=False
        ).order_by('-last_executed')[:5]
        
        # Formater les activités
        activities = []
        
        # Ajouter les incidents
        for incident in recent_incidents:
            activity_type = 'danger' if incident.status == 'detected' else 'success'
            activities.append({
                'type': activity_type,
                'title': f'Incident #{incident.id} - {incident.get_status_display()}',
                'description': f'Email: {incident.email.subject[:50]}...',
                'time': self._format_time_ago(incident.created_at),
                'created_at': incident.created_at
            })
        
        # Ajouter les exécutions de playbooks
        for playbook in recent_playbooks:
            activities.append({
                'type': 'success',
                'title': f'Playbook exécuté: {playbook.name}',
                'description': f'{playbook.execution_count} exécutions totales',
                'time': self._format_time_ago(playbook.last_executed),
                'created_at': playbook.last_executed
            })
        
        # Trier par date
        activities.sort(key=lambda x: x['created_at'], reverse=True)
        
        return Response({
            'activities': activities[:limit]
        })
    
    def _format_time_ago(self, dt):
        """Formater la date en 'il y a X temps'"""
        now = timezone.now()
        diff = now - dt
        
        if diff.days > 365:
            years = diff.days // 365
            return f'Il y a {years} an{"s" if years > 1 else ""}'
        elif diff.days > 30:
            months = diff.days // 30
            return f'Il y a {months} mois'
        elif diff.days > 0:
            return f'Il y a {diff.days} jour{"s" if diff.days > 1 else ""}'
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f'Il y a {hours} heure{"s" if hours > 1 else ""}'
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f'Il y a {minutes} minute{"s" if minutes > 1 else ""}'
        else:
            return 'À l\'instant'

class StatsExportView(APIView):
    """Export des statistiques"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        format_type = request.query_params.get('format', 'json')
        days = int(request.query_params.get('days', 7))
        
        # Récupérer les données de base
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Compilation des données
        stats_data = {
            'export_date': timezone.now().isoformat(),
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': days
            },
            'summary': {
                'total_emails': EmailMessage.objects.filter(
                    received_date__range=[start_date, end_date]
                ).count(),
                'total_threats': EmailMessage.objects.filter(
                    received_date__range=[start_date, end_date],
                    threat_type__in=['PHISHING', 'MALWARE', 'SPAM', 'SUSPICIOUS', 'SPOOFING']
                ).count(),
                'quarantined_emails': QuarantineEmail.objects.filter(
                    quarantined_at__range=[start_date, end_date]
                ).count(),
                'playbook_executions': Playbook.objects.aggregate(
                    total=Sum('execution_count')
                )['total'] or 0
            }
        }
        
        if format_type == 'csv':
            # Générer CSV simple
            import csv
            from django.http import HttpResponse
            
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="soar_stats_{datetime.now().strftime("%Y%m%d")}.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Statistiques SOAR', f'Période: {days} jours'])
            writer.writerow([])
            writer.writerow(['Métrique', 'Valeur'])
            
            for key, value in stats_data['summary'].items():
                writer.writerow([key.replace('_', ' ').title(), value])
            
            return response
        
        elif format_type == 'json':
            return Response(stats_data)
        
        else:
            return Response({
                'error': 'Format non supporté. Utilisez json ou csv.'
            }, status=400)
        

class EmailStatsView(APIView):
    """Statistiques pour la page emails analysés"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Récupérer les filtres
        days = int(request.query_params.get('days', 7))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Compter les emails par catégorie
        safe_emails = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type='NONE',
            threat_level='SAFE'
        ).count()
        
        suspicious_emails = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type='SUSPICIOUS'
        ).count()
        
        malicious_emails = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            threat_type__in=['PHISHING', 'MALWARE', 'SPAM', 'SPOOFING']
        ).count()
        
        # Emails non analysés
        unanalyzed_emails = EmailMessage.objects.filter(
            received_date__range=[start_date, end_date],
            analyzed=False
        ).count()
        
        total_emails = safe_emails + suspicious_emails + malicious_emails + unanalyzed_emails
        
        return Response({
            'period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'stats': {
                'total': total_emails,
                'safe': safe_emails,
                'suspicious': suspicious_emails,
                'malicious': malicious_emails,
                'unanalyzed': unanalyzed_emails
            },
            'percentages': {
                'safe': round((safe_emails / total_emails * 100) if total_emails > 0 else 0, 1),
                'suspicious': round((suspicious_emails / total_emails * 100) if total_emails > 0 else 0, 1),
                'malicious': round((malicious_emails / total_emails * 100) if total_emails > 0 else 0, 1),
                'unanalyzed': round((unanalyzed_emails / total_emails * 100) if total_emails > 0 else 0, 1)
            }
        })