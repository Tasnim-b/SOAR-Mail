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
    # API endpoints for emails (list and detail)
    path('api/emails/', views.EmailListView.as_view(), name='api_emails'),
    path('api/emails/<int:pk>/', views.EmailDetailView.as_view(), name='api_email_detail'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/dashboard/', ProtectedDashboardView.as_view(), name='dashboard_api'),
    path('emails/', views.emails_page, name='emails_page'),
  
]