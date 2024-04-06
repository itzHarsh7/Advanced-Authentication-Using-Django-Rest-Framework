from rest_framework import serializers
from .models import *
import re
import uuid

class UserRegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(allow_blank=True, required=False)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, min_length=8,style={'input_type':'password'}, write_only=True)
    confirm_password = serializers.CharField(required=True, min_length=8,style={'input_type':'password'}, write_only=True)
    
    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already in use.")
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[.@$])[A-Za-z.@$]{8,}$', value):
            raise serializers.ValidationError("Username must contain at least one uppercase letter, one lowercase letter, and one of the following characters: '.', '@', or '$'.")
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value
    
    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError("The passwords do not match.")
        return data
    
    def create(self, validated_data):
        last_name = validated_data.pop('last_name', '')
        user_id = uuid.uuid4()
        user = CustomUser.objects.create_user(id=user_id, **validated_data)
        profile_data = {
            'user': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': last_name if last_name else user.last_name
        }
        Profile.objects.create(**profile_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type':'password'}, write_only=True)

class ForgotPasswordSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True)


class ForgetResetPasswordSerializer(serializers.Serializer):
    new_password =serializers.CharField(style={'input_type':'password'}, write_only=True)
    confirm_new_password =serializers.CharField(write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password =serializers.CharField(style={'input_type':'password'}, write_only=True)
    confirm_password =serializers.CharField(write_only=True)


class EmailUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class EmailVerificationTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailVerificationToken
        fields = ['token']

class UsernameUpdateSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)

class EmailUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True) 

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('user','first_name','last_name', 'dob', 'gender', 'address', 'city', 'state', 'country', 'zipcode', 'contact')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username', 'first_name', 'last_name')
        extra_kwargs = {'username': {'required': True}} 
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists')
        return value

class EmailUpdateSerializer(serializers.Serializer):
    new_email = serializers.EmailField(label='New email address')