from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import IntegrityError
from .forms import RegistrationForm, LoginForm, PasswordChangeForm, UserProfileForm
from .models import UserProfile


def register(request):
    """User registration view"""
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                # Create associated UserProfile
                UserProfile.objects.get_or_create(user=user)
                messages.success(request, 'Registration successful! Please log in.')
                return redirect('taremwa:login')
            except IntegrityError:
                messages.error(request, 'An error occurred during registration. Please try again.')
    else:
        form = RegistrationForm()
    
    return render(request, 'taremwa/register.html', {'form': form})


def user_login(request):
    """User login view"""
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!')
                return redirect('taremwa:dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'taremwa/login.html', {'form': form})


@login_required(login_url='taremwa:login')
def dashboard(request):
    """Protected dashboard view showing user info"""
    try:
        profile = request.user.taremwa_profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)
    
    return render(request, 'taremwa/dashboard.html', {'profile': profile})


@login_required(login_url='taremwa:login')
def profile(request):
    """User profile view"""
    profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('taremwa:profile')
    else:
        form = UserProfileForm(instance=profile)
    
    return render(request, 'taremwa/profile.html', {'form': form, 'profile': profile})


@login_required(login_url='taremwa:login')
def change_password(request):
    """Password change view"""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Password changed successfully!')
            return redirect('taremwa:profile')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'taremwa/change_password.html', {'form': form})


def user_logout(request):
    """User logout view"""
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('taremwa:login')
