# core/urls.py
from django.urls import path
from . import views
from .views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LogoutView,
    ProtectedDashboardView,
    login_page,
    dashboard_page,
    PlaybookListView,
    PlaybookDetailView,
    PlaybookCreateView,
    PlaybookUpdateView,
    PlaybookDeleteView,
    PlaybookToggleActiveView,
    PlaybookTestView,
    PlaybookStatsView,
    IncidentLogListView,
    IncidentLogDetailView,
    PlaybookRuleCreateView,
    PlaybookActionCreateView,

)

urlpatterns = [
    path('', login_page, name='login_page'),
    path('dashboard/', dashboard_page, name='dashboard_page'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/dashboard/', ProtectedDashboardView.as_view(), name='dashboard_api'),
    path('emails/', views.emails_page, name='emails_page'),
    # API endpoints for emails 
    path('api/emails/', views.EmailListView.as_view(), name='api_emails'),
    path('api/emails/<int:pk>/', views.EmailDetailView.as_view(), name='api_email_detail'),
    path('api/emails/<int:id>/mark-safe/', views.MarkEmailSafeView.as_view(), name='mark_email_safe'),
    path('api/emails/<int:id>/quarantine/', views.QuarantineEmailView.as_view(), name='quarantine_email'),
    path('api/emails/<int:id>/delete/', views.DeleteEmailView.as_view(), name='delete_email'),
    path('api/scan/', views.StartScanView.as_view(), name='start_scan'),

    path('playbooks/', views.playbooks_page, name='playbooks_page'),
    # API endpoints for playbooks
 # API Playbooks
    path('api/playbooks/', PlaybookListView.as_view(), name='playbook-list'),
    path('api/playbooks/create/', PlaybookCreateView.as_view(), name='playbook-create'),
    path('api/playbooks/<int:id>/', PlaybookDetailView.as_view(), name='playbook-detail'),
    path('api/playbooks/<int:id>/update/', PlaybookUpdateView.as_view(), name='playbook-update'),
    path('api/playbooks/<int:id>/delete/', PlaybookDeleteView.as_view(), name='playbook-delete'),
    path('api/playbooks/<int:id>/toggle-active/', PlaybookToggleActiveView.as_view(), name='playbook-toggle-active'),
    path('api/playbooks/<int:id>/test/', PlaybookTestView.as_view(), name='playbook-test'),
    path('api/playbooks/stats/', PlaybookStatsView.as_view(), name='playbook-stats'),
    path('api/playbooks/<int:playbook_id>/rules/create/', PlaybookRuleCreateView.as_view(), name='playbook-rule-create'),
    path('api/playbooks/<int:playbook_id>/actions/create/', PlaybookActionCreateView.as_view(), name='playbook-action-create'),

    # API Incidents
    path('api/incidents/', IncidentLogListView.as_view(), name='incident-list'),
    path('api/incidents/<int:id>/', IncidentLogDetailView.as_view(), name='incident-detail'),

    path('quarantaine/', views.quarantaine_page, name='quarantaine_page'),
        # Quarantaine
    path('api/quarantine/', views.QuarantineListView.as_view(), name='quarantine-list'),
    path('api/quarantine/<int:id>/', views.QuarantineDetailView.as_view(), name='quarantine-detail'),
    path('api/quarantine/<int:id>/restore/', views.RestoreQuarantineEmailView.as_view(), name='restore-quarantine'),
    path('api/quarantine/<int:id>/delete/', views.DeleteQuarantineEmailView.as_view(), name='delete-quarantine'),
    path('api/quarantine/bulk-restore/', views.BulkRestoreQuarantineView.as_view(), name='bulk-restore-quarantine'),
    path('api/quarantine/bulk-delete/', views.BulkDeleteQuarantineView.as_view(), name='bulk-delete-quarantine'),
    
    path('statistiques/', views.statistiques_page, name='statistiques_page'),
        
    # API Statistiques
    path('api/stats/kpis/', views.StatsKPIsView.as_view(), name='stats-kpis'),
    path('api/stats/threat-distribution/', views.StatsThreatDistributionView.as_view(), name='stats-threat-distribution'),
    path('api/stats/email-timeline/', views.StatsEmailTimelineView.as_view(), name='stats-email-timeline'),
    path('api/stats/threat-sources/', views.StatsThreatSourcesView.as_view(), name='stats-threat-sources'),
    path('api/stats/recent-activity/', views.StatsRecentActivityView.as_view(), name='stats-recent-activity'),
    path('api/stats/export/', views.StatsExportView.as_view(), name='stats-export'),
    path('api/emails/stats/', views.EmailStatsView.as_view(), name='email-stats'),


]