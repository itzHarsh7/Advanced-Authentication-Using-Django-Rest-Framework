from django.urls import path
from . import views
urlpatterns = [
        path('api/signup/',views.UserRegistrationAPIView.as_view(),name='signup'),
        path('api/signin/',views.UserLoginAPIView.as_view(),name='signin'),
        path('api/refresh-token/',views.UserRefreshTokenAPIView.as_view(),name='user_refresh_token'),
        path('api/resend-email/',views.ResendEmailVerificationAPIView.as_view(),name='resend_email'),
        path('api/tokenverify/<str:token>',views.EmailVerificationAPIView.as_view(),name='emailverify'),
        path('api/change-email/',views.ChangeEmailAPIView.as_view( ),name="change_email"),
        path('api/signout/',views.LogoutAPIView.as_view(),name='signout'),
        path('api/forget/',views.ForgotPasswordAPIView.as_view(),name='forget_password'),
        path('api/reset-password/<str:uidb64>/<str:token>/',views.ForgetResetPasswordAPIView.as_view(),name='forget_reset'),
        path('api/reset/',views.ChangePasswordAPIView.as_view(),name='reset_password'),
        path('api/update-profile/',views.ProfileUpdateAPIView.as_view(),name='update_profile'),
        path('api/profile/',views.ProfileListAPIView.as_view(),name='list_profile'),
        path('api/update-user/',views.UsernameUpdateAPIView.as_view(),name='update_username'),
        # path('api/update-email/',views.EmailUpdateAPIView.as_view(),name='update_email'),
        path('api/verify-update-email/<str:token>/',views.EmailVerificationAPIView.as_view(),name='email_update_verify'),
    ]