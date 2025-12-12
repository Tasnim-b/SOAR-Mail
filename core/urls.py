# core/urls.py
from django.urls import path
from . import views
from .views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LogoutView,
    ProtectedDashboardView,
    login_page,
    dashboard_page
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
  
]