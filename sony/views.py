from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
import datetime

from .models import PasswordResetToken, EmailVerification
from .serializers import (
    UserSerializer, 
    RegisterSerializer, 
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    VerifyOTPSerializer
)

# NOUVEAU : Register avec OTP en deux étapes
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        # Créer l'utilisateur mais ne pas l'activer tout de suite
        user = serializer.save()
        user.is_active = False  # Désactiver jusqu'à vérification OTP
        user.save()
        
        # Générer un code OTP
        code = get_random_string(6, '0123456789')
        
        # Sauvegarder la vérification
        verification = EmailVerification.objects.create(
            user=user,
            email=user.email,
            code=code,
            expires_at=timezone.now() + datetime.timedelta(minutes=30)
        )
        
        # Envoyer l'email avec le code OTP
        send_mail(
            'Vérification de votre email - Code OTP',
            f'Votre code de vérification est : {code}\n\n'
            f'Ce code expirera dans 30 minutes.',
            'noreply@votresite.com',
            [user.email],
            fail_silently=False,
        )
        
        return Response({
            'message': 'Un code de vérification a été envoyé à votre email',
            'email': user.email,
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# NOUVEAU : Vérification OTP pour l'inscription
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    serializer = VerifyOTPSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        
        try:
            verification = EmailVerification.objects.get(
                email=email,
                code=code,
                expires_at__gt=timezone.now(),
                verified=False
            )
            
            # Activer l'utilisateur
            user = verification.user
            user.is_active = True
            user.save()
            
            # Marquer comme vérifié
            verification.verified = True
            verification.save()
            
            # Générer les tokens JWT
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Email vérifié avec succès'
            }, status=status.HTTP_200_OK)
            
        except EmailVerification.DoesNotExist:
            return Response({
                'error': 'Code OTP invalide ou expiré'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# MODIFIÉ : Login par email
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']  # Modifié ici
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    serializer = PasswordResetRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            # Générer un token unique
            token = get_random_string(50)
            code = get_random_string(6, '0123456789')  # Code à 6 chiffres
            
            # Sauvegarder le token
            reset_token = PasswordResetToken.objects.create(
                user=user,
                token=token,
                code=code,
                expires_at=timezone.now() + datetime.timedelta(hours=1)
            )
            
            # Envoyer l'email
            send_mail(
                'Réinitialisation de votre mot de passe',
                f'Votre code de réinitialisation est : {code}\n\n'
                f'Ou utilisez ce lien : http://localhost:3000/reset-password/{token}',
                'noreply@votresite.com',
                [email],
                fail_silently=False,
            )
            
            return Response({
                'message': 'Un email de réinitialisation a été envoyé',
                'token': token
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            # Pour des raisons de sécurité, on ne révèle pas si l'email existe
            return Response({
                'message': 'Si cet email existe, un lien de réinitialisation a été envoyé'
            }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        token = serializer.validated_data['token']
        code = serializer.validated_data['code']
        new_password = serializer.validated_data['new_password']
        
        try:
            reset_token = PasswordResetToken.objects.get(
                token=token,
                code=code,
                expires_at__gt=timezone.now(),
                used=False
            )
            
            # Mettre à jour le mot de passe
            user = reset_token.user
            user.set_password(new_password)
            user.save()
            
            # Marquer le token comme utilisé
            reset_token.used = True
            reset_token.save()
            
            # CORRECTION : Utiliser OutstandingToken au lieu de RefreshToken
            from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
            
            # Blacklist tous les tokens JWT existants de l'utilisateur
            outstanding_tokens = OutstandingToken.objects.filter(user=user)
            for token in outstanding_tokens:
                BlacklistedToken.objects.get_or_create(token=token)
            
            return Response({
                'message': 'Mot de passe réinitialisé avec succès'
            }, status=status.HTTP_200_OK)
            
        except PasswordResetToken.DoesNotExist:
            return Response({
                'error': 'Token ou code invalide ou expiré'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)