from django.urls import path, include
from .views import *

urlpatterns = [
    path('login/', login_page, name='login'),
    path('registration/', registration, name='registration'),
    path('logout/', logout_page, name='logout'),
    path('success/', success, name='success'),
    path('success1/', success1, name='success1'),
    path('error/', error, name='error'),
    path('new_pass/', new_pass, name='new_pass'),
    path('reset_password/', reset_password, name='reset_password'),
    path('token_send/', token_send, name='token_send'),
    path('verify/<auth_token>/', verify, name='verify'),
    path('reset_user_pass/<auth_token>/', reset_user_pass, name='reset_user_pass'),
]
