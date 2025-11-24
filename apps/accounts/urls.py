from django.urls import path
from .views import (
    RegisterUserAPIView, 
    LoginUserAPIView,
    LogoutUserAPIView,
    VerifyEmailAPIView,
    ResendOtpAPIView,
    ResetPasswordRequestAPIView,
    ResetPasswordConfirmAPIVIew,
    SetNewPasswordAPIView,
)

urlpatterns = [
    path("auth/register/", RegisterUserAPIView.as_view(), name="register"),
    path("auth/login/", LoginUserAPIView.as_view(), name="login"),
    path("auth/logout/", LogoutUserAPIView.as_view(), name="logout"),
    path("auth/verify-email/", VerifyEmailAPIView.as_view(), name="verify-email"),
    path("auth/resend-otp/", ResendOtpAPIView.as_view(), name="resend-otp"),
    path("auth/reset-password-request/", ResetPasswordRequestAPIView.as_view(), name="reset-password-request"),
    path("auth/reset-password-confirm/", ResetPasswordConfirmAPIVIew.as_view(), name="reset-password-confirm"),
    path("auth/set-new-password/", SetNewPasswordAPIView.as_view(), name="set-new-password"),

]