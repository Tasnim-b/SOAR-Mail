
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
from .serializers import CustomTokenObtainPairSerializer
from .models import EmailAccount, EmailMessage
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
        
        # Préparer les données pour le graphique
        threat_types_data = {item['threat_type']: item['count'] for item in threat_distribution}
        
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
        
        return Response({
            "user": {
                "email": request.user.email,
                "is_staff": request.user.is_staff,
            },
            "stats": {
                "emails_analyzed": total_emails,
                "threats_detected": threats_detected,
                "incidents_today": incidents_today,
                "auto_resolved": 0,  # À implémenter avec les playbooks
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
            "message": "Dashboard SOAR-Mail"
        })


# views.py - Suite


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
    
    filterset_fields = ['threat_level', 'threat_type', 'has_attachments', 'is_read']
    search_fields = ['sender', 'sender_name', 'subject', 'body_text']
    
    def get_queryset(self):
        queryset = EmailMessage.objects.all().order_by('-received_date')
        
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
    lookup_field = 'id'
    
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

# Vue API pour mettre en quarantaine un email
class QuarantineEmailView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = EmailMessage.objects.all()
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.threat_level = 'MEDIUM'
        instance.risk_score = 50
        instance.is_read = True
        instance.save()
        
        return Response({
            'message': 'Email mis en quarantaine',
            'threatStatus': 'suspicious',
            'threatScore': instance.risk_score
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