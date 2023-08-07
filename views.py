from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
import uuid
from .models import *
from django.conf import settings
from django.core.mail import send_mail


# Create your views here.
def login_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if not User.objects.filter(username=username).exists():
            messages.error(request, 'invalid username ...')
            return redirect('login')
        if not password:
            messages.error(request, "no password found ...")
            return redirect('login')
        user = authenticate(username=username, password=password)
        if user is not None:
            prof = Profile.objects.get(user=user)
            if prof.is_verified == True:
                login(request, user)
                return redirect('home')
            else:
                return redirect(error)
        else:
            messages.error(request, 'invalid password ...')
            return redirect('login')
    else:
        return render(request, 'Accounts/login.html')


def registration(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        if username is not None:
            for i in username:
                if i in ['.', '@', '#', '$', '*', '!']:
                    messages.error(request, 'username has special character! please remove them...')
                    return redirect('registration')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'username already exists! please try some other name...')
                return redirect('registration')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'this email already register...')
                return redirect('registration')
            else:
                if pass1 == pass2:
                    user = User.objects.create_user(
                        username=username,
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        password=pass1,
                    )
                    user.save()
                    user.set_password(pass1)
                    auth_token = str(uuid.uuid4())
                    pro_obj = Profile.objects.create(user=user, auth_token=auth_token)
                    pro_obj.save()
                    send_mail_registration(email, auth_token)
                    return redirect('success')
                else:
                    messages.error(request, "your given password doesn't match....")
                    return redirect('registration')
    else:
        return render(request, 'Accounts/registration.html', locals())


def logout_page(request):
    logout(request)
    messages.error(request, "you are logged out..")
    return redirect("login")


def success(request):
    return render(request, 'Accounts/success.html')


def error(request):
    return render(request, 'Accounts/error.html')


def token_send(request):
    return render(request, 'Accounts/token_send.html')


def send_mail_registration(email, auth_token):
    subject = 'Your Account Authentication Link'
    message = f'hi,please click here to verify your account: http://127.0.0.1:8000/accounts/verify/{auth_token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


def verify(request, auth_token):
    profile_obj = Profile.objects.filter(auth_token=auth_token).first()
    profile_obj.is_verified = True
    profile_obj.save()
    messages.success(request, 'Congratulation Account Verify Its done')
    return redirect('login')


def reset_password(request):
    if request.method == 'POST':
        server_taken_email = request.POST.get('email')
        user_email = User.objects.get(email=server_taken_email)
        res_prof = Profile.objects.get(user=user_email)  # models user
        auth_token = res_prof.auth_token
        print(auth_token)
        send_mail_reset(server_taken_email, auth_token)
        return redirect('success1')

    else:
        return render(request, 'Accounts/reset_password.html')


def send_mail_reset(server_taken_email, auth_token):
    subject = 'Your Account Authentication Link'
    message = f'hi,please click here to Reset your password: http://127.0.0.1:8000/accounts/reset_user_pass/{auth_token} '
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [server_taken_email]
    send_mail(subject, message, email_from, recipient_list)


def reset_user_pass(request, auth_token):
    profile_obj = Profile.objects.filter(auth_token=auth_token).first()
    if profile_obj:
        if request.method == 'POST':
            pass1 = request.POST.get('password1')
            pass2 = request.POST.get('password2')
            if pass1 == pass2:
                user = profile_obj.user
                user.set_password(pass1)
                user.save()
                messages.success(request, 'your password successfully changed')
                return redirect('login')
            else:
                messages.error(request, 'please enter the same password')
                return redirect('new_pass')
    return render(request, 'Accounts/new_pass.html')


def new_pass(request):
    return render(request, 'Accounts/new_pass.html')


def success1(request):
    return render(request, 'Accounts/success1.html')
