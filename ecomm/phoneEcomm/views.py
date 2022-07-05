from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_jwt.settings import api_settings
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from .models import *
from .serializers import *
import pyotp
import jwt

def generateOTP():
    global totp
    secret = pyotp.random_base32()
    # set interval(time of the otp expiration) according to your need in seconds.
    totp = pyotp.TOTP(secret, interval=300)
    one_time = totp.now()
    return one_time

# verifying OTP


def verifyOTP(one_time):
    answer = totp.verify(one_time)
    return answer


class RegistrationAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def get(self, request):
        return Response({'Status': 'You cannot view all users data.....'})

    def post(self, request):
        email = request.data['email']
        print(email)

        data = User.objects.filter(email=email)
        print('data ', data)

        if data.exists():
            return Response({'msg': 'Already registered'}, status=status.HTTP_409_CONFLICT)
        else:
            serializer = self.serializer_class(data=request.data)
            print("ser", serializer)
            username = request.data['username']

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = f'Welcome {username} Your OTP is : ' + \
                    generateOTP()
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [email]
                message = message
                subject = "OTP" 
                send_mail(
                    subject,
                    message,
                    email_from,
                    recipient_list,
                    fail_silently=False,
                )

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"Error": "Sign Up Failed"}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        email = request.data['email']
        one_time = request.data['otp']
        print('one_time_password', one_time)
        one = verifyOTP(one_time)
        print('one', one)
        if one:
            User.objects.filter(email=email).update(
                is_confirmed=True, is_used=True, otp=one_time)
            return Response({'msg': 'OTP verfication successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'msg': 'OTP verfication Failed'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        print('email', email)
        filter_data = User.objects.filter(email=email).values('is_active')
        if filter_data.exists():
            val = filter_data[0]['is_active']
            
        else:
            return Response("Email is not Registered", status=status.HTTP_400_BAD_REQUEST)

        if val:
            if serializer.is_valid():
                user = authenticate(
                    username=request.data['email'], password=request.data['password'])
                update_last_login(None, user)
                if user is not None and user.is_confirmed and user.is_active:  # change according to yourself
                    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
                    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
                    payload = jwt_payload_handler(user)
                    token = jwt_encode_handler(payload)
                    return Response({'msg': 'Login successful', 'is_confirmed': user.is_confirmed, 'token': token,
                                     }, status=status.HTTP_200_OK)
                else:
                    return Response({'msg': 'Account not approved or wrong Password.'}, status=status.HTTP_409_CONFLICT)
            else:
                return Response({'msg': 'Invalid data'}, status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response({'Error': 'Not a valid user'}, status=status.HTTP_401_UNAUTHORIZED)

class PhoneAPIView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PhoneSerializer

    def get(self, request):
        phones = Phone.objects.all()
        serializer = PhoneSerializer(phones, many=True)
        return Response(serializer.data)