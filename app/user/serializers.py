from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _
from django.utils.crypto import get_random_string
from email_validator import EmailNotValidError
from rest_framework import serializers, exceptions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User, Token
from .tasks import send_new_user_email


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = get_user_model()
        fields = [
            'id', 'firstname', 'lastname', 'email', 'role', 'phone', 'image', 'is_active']


class CreateUserSerializer(serializers.ModelSerializer):
    """Serializer for creating user object"""

    class Meta:
        model = get_user_model()
        fields = ['id', 'email', 'firstname', 'lastname', 'phone', 'image', 'role', 'created_at']

    def validate(self, attrs):
        if not self.instance:
            email = attrs.get('email', None)
            if email:
                email = attrs['email'].lower().strip()
                if get_user_model().objects.filter(email=email).exists():
                    raise serializers.ValidationError('Email already exists')
                try:
                    valid = validate_email(attrs['email'])
                    attrs['email'] = valid.email
                    return super().validate(attrs)
                except EmailNotValidError as e:
                    raise serializers.ValidationError({'email': 'Invalid Email', 'e': e})
        return super().validate(attrs)

    def create(self, validated_data):
        user = User.objects.create_user(password='Password@@1', **validated_data)
        token, _ = Token.objects.update_or_create(
            user=user, token_type='ACCOUNT_VERIFICATION',
            defaults={'user': user, 'token_type': 'ACCOUNT_VERIFICATION',
                      'token': get_random_string(120)})
        user_data = {
            'id': user.id, 'email': user.email,
            'tenant_name': user.tenant.name,
            'tenant_logo': user.tenant.logo.url if user.tenant.logo else '',
            'fullname': f"{user.lastname} {user.firstname}",
            'url': f"{settings.CLIENT_URL}/create-password/?token={token.token}"}
        send_new_user_email.delay(user_data)
        return user

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        if validated_data.get('password', False):
            instance.set_password(validated_data.get('password'))
        instance.save()
        return instance


class ResendTokenSerializer(serializers.Serializer):
    """Serializer for resending token"""
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs['email'].lower().strip()
        user = get_user_model().objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError('User does not exists')
        if user.verified:
            raise serializers.ValidationError(
                {'user': 'cannot resend token to a user who status is not pending '})
        return super().validate(attrs)

    def create(self, validated_data):
        email = validated_data['email']
        user = get_user_model().objects.filter(email=email).first()
        token = Token.objects.filter(user=user)
        if token.exists():
            token.delete()
        token = Token.objects.create(user=user, token=get_random_string(120),
                                     token_type='ACCOUNT_VERIFICATION')
        user_data = {
            'id': user.id, 'email': user.email,
            'tenant_name': user.tenant.name,
            'tenant_logo': user.tenant.logo.url if user.tenant.logo else '',
            'fullname': f"{user.lastname} {user.firstname}",
            'url': f"{settings.CLIENT_URL}/create-password/?token={token.token}"}
        send_new_user_email.delay(user_data)
        return user


class CustomObtainTokenPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        if user.is_deleted:
            raise exceptions.AuthenticationFailed(
                _('Account deleted.'), code='authentication')
        if not user.verified:
            raise exceptions.AuthenticationFailed(
                _('Account not yet verified.'), code='authentication')
        token = super().get_token(user)
        # Add custom claims
        token.id = user.id
        token['email'] = user.email
        token['role'] = user.role
        token['firstname'] = user.firstname
        token['lastname'] = user.lastname
        if user.image:
            token['image'] = user.image.url
        token['phone'] = user.phone
        user.save_last_login()
        return token


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for user authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        if email:
            user = authenticate(
                request=self.context.get('request'),
                username=email.lower().strip(),
                password=password
            )

        if not user:
            msg = _('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(msg, code='authentication')
        attrs['user'] = user
        return attrs


class VerifyTokenSerializer(serializers.Serializer):
    """Serializer for token verification"""
    token = serializers.CharField(required=True)


class CreatePasswordSerializer(serializers.Serializer):
    """Serializer for password change on reset"""
    token = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class InitializePasswordResetSerializer(serializers.Serializer):
    """Serializer for sending password reset email to the user"""
    email = serializers.CharField(required=True)
