from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import IntegrityError
from django.http import HttpResponseForbidden
from .forms import RegistrationForm, LoginForm, PasswordChangeForm, UserProfileForm
from .models import UserProfile
from .authorization import (
    can_view_profile, can_edit_profile, can_delete_user, 
    staff_required, instructor_required, get_user_role
)


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
def profile(request, user_id=None):
    """
    User profile view - can view own or (if staff) others' profiles.
    If user_id is None, shows current user's profile.
    If user_id is provided, shows that user's profile (with permission checks).
    """
    if user_id is None:
        # Viewing own profile
        profile = get_object_or_404(UserProfile, user=request.user)
        target_user = request.user
    else:
        # Viewing other user's profile
        target_user = get_object_or_404(User, id=user_id)
        profile = get_object_or_404(UserProfile, user=target_user)
        
        # Check permission to view this profile
        if not can_view_profile(request.user, target_user):
            messages.error(request, 'You do not have permission to view this profile.')
            return HttpResponseForbidden('Forbidden: You cannot access this profile.')
    
    # Check if editing
    if request.method == 'POST':
        # Check permission to edit this profile
        if not can_edit_profile(request.user, target_user):
            messages.error(request, 'You do not have permission to edit this profile.')
            return HttpResponseForbidden('Forbidden: You cannot edit this profile.')
        
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            if user_id:
                return redirect('taremwa:view_profile', user_id=user_id)
            return redirect('taremwa:profile')
    else:
        form = UserProfileForm(instance=profile)
    
    # Add metadata for template
    is_own_profile = request.user == target_user
    can_edit = can_edit_profile(request.user, target_user)
    
    return render(request, 'taremwa/profile.html', {
        'form': form,
        'profile': profile,
        'target_user': target_user,
        'is_own_profile': is_own_profile,
        'can_edit': can_edit,
    })


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


@staff_required
def staff_dashboard(request):
    """Staff-only dashboard with user management options"""
    all_users = User.objects.all().prefetch_related('taremwa_profile', 'groups')
    staff_group = User.objects.filter(groups__name='staff')
    instructor_group = User.objects.filter(groups__name='instructor')
    
    context = {
        'total_users': all_users.count(),
        'staff_count': staff_group.count(),
        'instructor_count': instructor_group.count(),
        'admin_count': User.objects.filter(is_superuser=True).count(),
        'user_role': get_user_role(request.user),
    }
    
    return render(request, 'taremwa/staff_dashboard.html', context)


@instructor_required
def view_all_users(request):
    """View all users - available to instructors and staff"""
    all_users = User.objects.all().prefetch_related('taremwa_profile', 'groups')
    
    # Add role information for each user
    users_with_roles = []
    for user in all_users:
        users_with_roles.append({
            'user': user,
            'role': get_user_role(user),
            'can_edit': can_edit_profile(request.user, user),
            'profile': user.taremwa_profile,
        })
    
    context = {
        'users': users_with_roles,
        'user_role': get_user_role(request.user),
    }
    
    return render(request, 'taremwa/view_all_users.html', context)


@login_required(login_url='taremwa:login')
def view_profile(request, user_id):
    """View specific user profile (with authorization checks)"""
    return profile(request, user_id=user_id)


@staff_required
def delete_user(request, user_id):
    """Delete user - staff only"""
    target_user = get_object_or_404(User, id=user_id)
    
    # Cannot delete yourself
    if target_user == request.user:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('taremwa:view_all_users')
    
    # Cannot delete superusers (only superusers can)
    if target_user.is_superuser and not request.user.is_superuser:
        messages.error(request, 'You cannot delete administrator accounts.')
        return redirect('taremwa:view_all_users')
    
    if request.method == 'POST':
        username = target_user.username
        target_user.delete()
        messages.success(request, f'User {username} has been deleted.')
        return redirect('taremwa:view_all_users')
    
    context = {
        'target_user': target_user,
        'user_role': get_user_role(request.user),
    }
    
    return render(request, 'taremwa/confirm_delete_user.html', context)
