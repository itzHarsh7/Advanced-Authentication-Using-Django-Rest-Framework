import uuid
from datetime import datetime
from .models import *
from .serializers import *
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
class UserRegistrationAPIView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            token = str(uuid.uuid4())
            email_subject = 'Testing Email Verification'
            email_message = f'Click on the following link to verify your email: http://127.0.0.1:8000/api/tokenverify/{token}'
            send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [serializer.validated_data['email']])
            user = CustomUser.objects.create_user(
                first_name=serializer.validated_data['first_name'],
                last_name=serializer.validated_data.get('last_name'),
                username=serializer.validated_data['username'],
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password'],
                is_active=False
            )
            Profile.objects.create(
                user=user,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name
            )
            user_details = {
                                "id": user.id,
                                "username": user.username,
                                "email": user.email,
                                "first_name": user.first_name,
                                "last_name": user.last_name
                            }
            request.session['username'] = serializer.validated_data['username']
            request.session.set_expiry(600)
            EmailVerificationToken.objects.create(user=user, token=token)
            return Response({"message":"User registered successfully. Please check your email for verification link.","status":True,"User_Details":user_details}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationAPIView(APIView):
    def get(self, request, token):
        try:
            email_verification_token = EmailVerificationToken.objects.get(token=token)
            user = email_verification_token.user
            user.is_active = True
            user.save()
            email_verification_token.delete()
            
            return Response({"message":"Email verified successfully. Your account is activated.Please Login Now","Verified_User":True,"status":True}, status=status.HTTP_200_OK)
        except EmailVerificationToken.DoesNotExist:
            return Response({"message":"Invalid token or token expired","Verified_User":False,"status":False}, status=status.HTTP_400_BAD_REQUEST)
        
class ResendEmailVerificationAPIView(APIView):
    def post(self, request):
        username = request.session.get('username')
        if not username:
            return Response({"message": "Username not found in session.", "status": "False"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = CustomUser.objects.get(username=username)
            email_verification_token = EmailVerificationToken.objects.get(user=user)
            new_token = str(uuid.uuid4())
            email_verification_token.token = new_token
            email_verification_token.save()
            email_subject = 'Resend Email Verification'
            email_message = f'Click on the following link to verify your email: http://127.0.0.1:8000/api/tokenverify/{new_token}'
            send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [user.email])
            
            return Response({"message": "Verification email resent successfully.", "status": "True"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "User not found.", "status": "False"}, status=status.HTTP_400_BAD_REQUEST)
        except EmailVerificationToken.DoesNotExist:
            return Response({"message": "Email verification token not found.", "status": "False"}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginAPIView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = CustomUser.objects.filter(username=username).first()
            if user:
                if user.is_active:
                    if user.check_password(password):
                        user = authenticate(request, username=username, password=password)
                        if user is not None:
                            login(request, user)
                            token = get_tokens_for_user(user)
                            welcome_message = f"Welcome {user.first_name}!"
                            email_subject = 'Account Login Notification'
                            email_message = f'Your Account Logged In detected {datetime.now()}'
                            send_mail(email_subject, email_message, 'from@example.com', [user.email])
                            user_details = {
                                "id": user.id,
                                "username": user.username,
                                "email": user.email,
                                "first_name": user.first_name,
                                "last_name": user.last_name
                            }
                            return Response({"token": token, "msg": welcome_message,"status":True,"User_Details":user_details}, status=status.HTTP_200_OK)
                    else:
                        return Response({"message":"Incorrect Password!!!","status":False}, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    return Response({"message":'Email is Not verified!!!',"status":False}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"message":"User does not exist","status":False}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeEmailAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        user = CustomUser.objects.get(username=username)
        profile = Profile.objects.get(user=user)
        profile.delete()
        email_verification_token = EmailVerificationToken.objects.get(user=user)
        email_verification_token.delete()
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            token = str(uuid.uuid4())
            user = CustomUser.objects.create_user(
                first_name=serializer.validated_data['first_name'],
                last_name=serializer.validated_data.get('last_name'),
                username=serializer.validated_data['username'],
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password'],
                is_active=False
            )
            Profile.objects.create(
                user=user,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name
            )
            request.session['username'] = serializer.validated_data['username']
            request.session.set_expiry(600)
            EmailVerificationToken.objects.create(user=user, token=token)
            email_subject = 'Testing Email Verification'
            email_message = f'Click on the following link to verify your email: http://127.0.0.1:8000/api/tokenverify/{token}'
            send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [serializer.validated_data['email']])
            user_details = {
                                "id": user.id,
                                "username": user.username,
                                "email": user.email,
                                "first_name": user.first_name,
                                "last_name": user.last_name
                            }
            return Response({"message":"User registered successfully. Please check your email for verification link.","status":True,"User_Details":user_details}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserRefreshTokenAPIView(TokenRefreshView):
    pass

class LogoutAPIView(APIView):
    def get(self, request):
        logout(request)
        return Response({"message":"Logged out successfully.","status":True}, status=status.HTTP_200_OK)
    
# Forget Password
class ForgotPasswordAPIView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            username_or_email = serializer.validated_data['username_or_email']
            if CustomUser.objects.filter(email=username_or_email).exists():
                user = CustomUser.objects.get(email=username_or_email)
            elif CustomUser.objects.filter(username=username_or_email).exists():
                user = CustomUser.objects.get(username=username_or_email)
            else:
                return Response("User not found.", status=status.HTTP_404_NOT_FOUND)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f'http://127.0.0.1:8000/api/reset-password/{uid}/{token}/'
            email_subject = 'Forgot Password'
            email_message = f'Click the link to reset your password: {reset_link}'
            send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [user.email])
            return Response({"message":"Password reset link sent to your email.","status":True}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Forget Password Link
class ForgetResetPasswordAPIView(APIView):
    def post(self, request, uidb64, token):
        serializer = ForgetResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = get_user_model().objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
                user = None
            if user is not None and default_token_generator.check_token(user, token):
                new_password = serializer.validated_data['new_password']
                confirm_new_password = serializer.validated_data['confirm_new_password']
                if new_password == confirm_new_password:
                    user.set_password(new_password)
                    user.save()
                    return Response({"message":"Password reset successfully.","status":True}, status=status.HTTP_200_OK)
                else:
                    return Response({"message":"Passwords do not match.","status":False}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message":"Invalid token.","status":False}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
#Reset Password when logged in user
class ChangePasswordAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            confirm_new_password = serializer.validated_data['confirm_password']
            if user.check_password(old_password):
                if new_password == confirm_new_password:
                    user.set_password(new_password)
                    user.save()
                    return Response({"message":"Password changed successfully","status":True}, status=status.HTTP_200_OK)
                else:
                    return Response({"message":'New Password and Confirm Password Didn\'t Match',"status":False}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message":"Old password does not match","status":False}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class ProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def patch(self, request):
        user = request.user
        profile = user.profile
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            if 'email' in serializer.validated_data:
                serializer.validated_data.pop('email')
            serializer.save()
            return Response({'message': "Data Updated","status":True}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileListAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self,request):
        user = request.user
        profile = Profile.objects.get(user=user)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)  

class IsActiveUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_active
    
class UsernameUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def put(self, request):
        serializer = UsernameUpdateSerializer(data=request.data)
        if serializer.is_valid():
            new_username = serializer.validated_data['username']
            if CustomUser.objects.filter(username=new_username).exists():
                return Response({'message':"This username is already in use.","status":False}, status=status.HTTP_400_BAD_REQUEST)
            else:
                request.user.username = new_username
                request.user.save()
                return Response({"message":"Username updated successfully","status":True}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# class EmailUpdateAPIView(APIView):
#     permission_classes = [IsAuthenticated]
#     authentication_classes = [JWTAuthentication]

#     def put(self, request):
#         user = request.user
#         print(user)
#         serializer = EmailUpdateSerializer(data=request.data)
#         if serializer.is_valid():
#             new_email = serializer.validated_data['new_email']
#             if new_email == user.email:
#                 return Response({"message": "New email is same as the current one.","status":False}, status=status.HTTP_400_BAD_REQUEST)
#             if CustomUser.objects.filter(email=new_email).exists():
#                 return Response({"message": "Email is already in use.","status":False}, status=status.HTTP_400_BAD_REQUEST)
#             try:
#                 verification_token = EmailVerificationToken.objects.get(user=user)
#                 verification_token.token = str(uuid.uuid4())
#                 verification_token.save()
#             except EmailVerificationToken.DoesNotExist:
#                 verification_token = EmailVerificationToken.objects.create(user=user, token=str(uuid.uuid4()))
#             user.email = new_email
#             user.is_active=False
#             user.save()
#             profile = Profile.objects.get(user=user)
#             profile.email = new_email
#             profile.save()
#             email_subject = 'Update Email Address'
#             email_message = f'Click on the following link to update your email address: http://127.0.0.1:8000/api/verify-update-email/{verification_token.token}/'
#             send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [new_email])
#             return Response({"message": "Email Updation mail sent successfully!! Please Verify it and Login again!","status":True}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class EmailUpdateVerificationAPIView(APIView):
    def get(self, request, token):
        try:
            verification_token = EmailVerificationToken.objects.get(token=token)
            user = verification_token.user
            new_email = user.email
            user.profile.email = new_email
            user.is_active=True
            user.save()
            verification_token.delete()
            logout(request)
            return Response({"message": "Email verified successfully. Your email address has been updated. Please log in again.","status":True}, status=status.HTTP_200_OK)
        except EmailVerificationToken.DoesNotExist:
            return Response({"message": "Invalid token or token expired","status":False}, status=status.HTTP_400_BAD_REQUEST)