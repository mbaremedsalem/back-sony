from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('api/register/', views.register, name='register'),
    path('api/verify-otp/', views.verify_otp, name='verify_otp'),  # NOUVEAU
    path('api/login/', views.login, name='login'),
    path('api/logout/', views.logout, name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/password-reset/', views.password_reset_request, name='password_reset_request'),
    path('api/password-reset/confirm/', views.password_reset_confirm, name='password_reset_confirm'),
    path('api/profile/', views.get_user_profile, name='get_user_profile'),
]