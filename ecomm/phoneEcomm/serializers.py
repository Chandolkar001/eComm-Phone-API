from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import Phone, User

class RegisterSerializer(serializers.ModelSerializer):
    password  = serializers.CharField(max_length = 128, write_only = True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def create(self, validated_data):
        user = User.objects.create(
            username = validated_data['username'],
            email = validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

class VerifyOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['otp', 'email']

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length = 255, read_only=True)

    class Meta:
        fields = ('email', 'password', 'token')

class PhoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Phone
        fields = "__all__"