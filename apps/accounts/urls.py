# Django
from django.urls import path

# Local
from .views import (
    RegisterUserAPIView, 
    LoginUserAPIView,
    LogoutUserAPIView,
    RefreshTokenAPIView,
    VerifyEmailAPIView,
    ResendOtpAPIView,
    ResetPasswordRequestAPIView,
    ResetPasswordConfirmAPIVIew,
    SetNewPasswordAPIView,
    UserPublicKeyAPIView,
)

urlpatterns = [
    path("auth/register/", RegisterUserAPIView.as_view(), name="register"),
    path("auth/login/", LoginUserAPIView.as_view(), name="login"),
    path("auth/logout/", LogoutUserAPIView.as_view(), name="logout"),
    path("auth/refresh/", RefreshTokenAPIView.as_view(), name="token-refresh"),
    path("auth/verify-email/", VerifyEmailAPIView.as_view(), name="verify-email"),
    path("auth/resend-otp/", ResendOtpAPIView.as_view(), name="resend-otp"),
    path("auth/reset-password-request/", ResetPasswordRequestAPIView.as_view(), name="reset-password-request"),
    path("auth/reset-password-confirm/", ResetPasswordConfirmAPIVIew.as_view(), name="reset-password-confirm"),
    path("auth/set-new-password/", SetNewPasswordAPIView.as_view(), name="set-new-password"),
    
    # Public key lookup
    path("users/<str:email>/public-key/", UserPublicKeyAPIView.as_view(), name="user-public-key"),
]