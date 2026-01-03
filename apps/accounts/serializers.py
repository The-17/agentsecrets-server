# Django
from django.utils.translation import gettext_lazy as _

# Third-party
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# Local
from .models import User


class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(
        max_length=50, error_messages={"max_length": _("{max_length} characters max.")}
    )
    last_name = serializers.CharField(
        max_length=50, error_messages={"max_length": _("{max_length} characters max.")}
    )
    email = serializers.EmailField()
    password = serializers.CharField(
        min_length=8, error_messages={"min_length": _("{min_length} characters min.")}
    )
    key_salt = serializers.CharField(help_text="Salt for deriving user_key from password")
    terms_agreement = serializers.BooleanField()
    
    # Asymmetric keypair for workspace encryption
    public_key = serializers.CharField(required=False, allow_blank=True)
    encrypted_private_key = serializers.CharField(required=False, allow_blank=True)
        
    def validate(self, attrs):
        first_name = attrs["first_name"]
        last_name = attrs["last_name"]
        terms_agreement = attrs["terms_agreement"]

        if len(first_name.split(" ")) > 1:
            raise serializers.ValidationError({"first_name": "No spacing allowed"})

        if len(last_name.split(" ")) > 1:
            raise serializers.ValidationError({"last_name": "No spacing allowed"})

        if terms_agreement != True:
            raise serializers.ValidationError(
                {"terms_agreement": "You must agree to terms and conditions"}
            )
        return attrs
    
    


class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()


class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()


class LoginSerializer(ResendOtpSerializer):
    password = serializers.CharField()


class ResetPasswordSerializer(ResendOtpSerializer):
    email = serializers.EmailField()


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=30, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=30, min_length=8, write_only=True)
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    
    class Meta:
        fields = [
            'password',
            'confirm_password',
            'token',
            'uidb64'
        ]


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {
        "bad_token": "Token is invalid or expired"
    }

    def validate(self, attrs):
        self.token =  attrs.get("refresh_token")
        return attrs

    def save(self, **Kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail("bad_token")


