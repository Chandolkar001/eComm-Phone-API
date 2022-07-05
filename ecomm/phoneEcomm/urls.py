from django.urls import path
from .views import LoginAPIView, PhoneAPIView, RegistrationAPIView, VerifyOTPView

urlpatterns = [
    path('register', RegistrationAPIView.as_view()), #Registeration
    path('login', LoginAPIView.as_view()), #Login after otp verification
    path('verify', VerifyOTPView.as_view()), #otp Verify
    path('phones', PhoneAPIView.as_view()), #phones list
    ]