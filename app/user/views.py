from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.db.models import Count, Q
from django.utils.crypto import get_random_string
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, filters, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_simplejwt.views import TokenObtainPairView

from common.permissions import IsAdmin
from user.models import Token
from user.serializers import UserSerializer, InitializePasswordResetSerializer, VerifyTokenSerializer, \
    CreateUserSerializer, CreatePasswordSerializer, ResendTokenSerializer, CustomObtainTokenPairSerializer, \
    AuthTokenSerializer

CACHE_TTL = getattr(settings, 'CACHE_TTL', DEFAULT_TIMEOUT)


class AuthViewSets(viewsets.ModelViewSet):
    """User ViewSets"""
    queryset = get_user_model().objects.exclude(is_deleted=True)
    serializer_class = UserSerializer
    http_method_names = ['get', 'post', 'patch', 'delete']
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['email', 'firstname', 'lastname', 'phone']
    ordering_fields = ['created_at', 'last_login', 'email', 'firstname', 'lastname', 'phone']

    def get_serializer_class(self):
        if self.action == 'create_password':
            return CreatePasswordSerializer
        elif self.action == 'initialize_reset':
            return InitializePasswordResetSerializer
        elif self.action == 'verify_token':
            return VerifyTokenSerializer
        elif self.action in ['create', 'invite_user', 'partial_update']:
            return CreateUserSerializer
        return super().get_serializer_class()

    def paginate_results(self, queryset):
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def get_permissions(self):
        permission_classes = self.permission_classes
        if self.action in ['create_password', 'initialize_reset',
                           'verify_token', 'retrieve', 'list']:
            permission_classes = [AllowAny]
        elif self.action in ['destroy', 'partial_update']:
            permission_classes = [IsAuthenticated]
        elif self.action in ['create_bulk_user']:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        user.is_deleted = True
        user.save()
        return Response(data='delete success')

    @action(methods=['POST'],
            detail=False, serializer_class=CreateUserSerializer,
            permission_classes=[IsAuthenticated, IsAdmin],
            url_path='invite-user')
    def invite_user(self, request, pk=None):
        """This endpoint invites new user by admin"""
        serializer = self.get_serializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(tenant=self.request.user.tenant)
            return Response(
                {'success': True, 'data': serializer.data}, status=status.HTTP_200_OK)
        return Response(
            {'success': False, 'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'],
            detail=False, serializer_class=ResendTokenSerializer,
            permission_classes=[IsAdmin],
            url_path='resend-token')
    def resend_token(self, request, pk=None):
        """This endpoint resends token """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {'success': True, 'data': serializer.data},
            status=status.HTTP_200_OK)

    @action(methods=['POST'],
            detail=False, serializer_class=VerifyTokenSerializer,
            url_path='verify-token')
    def verify_token(self, request, pk=None):
        """This endpoint verifies token"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = Token.objects.filter(
                token=request.data.get('token')).first()
            if token and token.is_valid():
                return Response({'success': True, 'valid': True}, status=status.HTTP_200_OK)
            return Response({'success': True, 'valid': False}, status=status.HTTP_200_OK)
        return Response({'success': False, 'errors': serializer.errors},
                        status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'],
            detail=False, serializer_class=InitializePasswordResetSerializer,
            url_path='reset-password')
    def initialize_reset(self, request, pk=None):
        """This endpoint initializes password reset by sending password reset email to user"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = request.data['email'].lower().strip()
            user = get_user_model().objects.filter(email=email, is_active=True).first()
            if not user:
                return Response(
                    {'success': False,
                     'message': 'user with this record not found'},
                    status=status.HTTP_400_BAD_REQUEST)
            token, created = Token.objects.update_or_create(
                user=user, token_type='PASSWORD_RESET',
                defaults={'user': user, 'token_type': 'PASSWORD_RESET',
                          'token': get_random_string(120)})

            email_data = {
                'id': user.id, 'email': user.email,
                'tenant_name': user.tenant.name, "token": token.token,
                'tenant_logo': user.tenant.logo.url
                if user.tenant.logo else '',
                'fullname': f"{user.lastname} {user.firstname}",
                "url": f"{settings.CLIENT_URL}/reset-password/?token={token.token}", }

            # send_password_reset_email.delay(email_data)
            return Response(
                {'success': True,
                 'message': 'Email successfully sent to registered email'},
                status=status.HTTP_200_OK)
        return Response(
            {'success': False, 'errors': serializer.errors},
            status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, serializer_class=CreatePasswordSerializer,
            url_path='create-password')
    def create_password(self, request, pk=None):
        """Create a new password given the reset token"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = Token.objects.filter(
                token=request.data['token']).first()
            if not token or not token.is_valid():
                return Response(
                    {'success': False, 'errors': 'Invalid token specified'},
                    status=status.HTTP_400_BAD_REQUEST)
            token.reset_user_password(request.data['password'])
            token.verify_user()
            token.delete()
            return Response(
                {'success': True, 'message': 'Password successfully reset'},
                status=status.HTTP_200_OK)
        return Response(
            {'success': False, 'errors': serializer.errors},
            status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET'],
            permission_classes=[IsAdmin],
            detail=False, url_path='stats')
    def get_user_stats(self, request, pk=None):
        """Get user stats"""
        qs = self.get_queryset().filter(is_deleted=False)
        qs = qs.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(verified=True, is_active=True)),
            deactivated=Count('id', filter=Q(verified=True, is_active=False)),
            pending=Count('id', filter=Q(verified=False, is_active=False)))
        return Response(
            {'success': True, 'data': qs},
            status=status.HTTP_200_OK)

    @action(methods=['GET'],
            permission_classes=[IsAuthenticated],
            serializer_class=UserSerializer, detail=False,
            url_path='me')
    def me(self, request, pk=None):
        user = request.user
        return Response({
            'success': True,
            'data': self.serializer_class(user).data
        }, status=status.HTTP_200_OK)


class CustomObtainTokenPairView(TokenObtainPairView):
    """Login with email and password"""
    serializer_class = CustomObtainTokenPairSerializer


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for user"""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response(
            {'token': token.key, 'created': created, 'role': user.role},
            status=status.HTTP_200_OK)
