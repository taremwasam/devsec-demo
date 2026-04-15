from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.core.mail import send_mail
from django.db import IntegrityError
from django.http import HttpResponseForbidden
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .forms import (
    RegistrationForm, LoginForm, PasswordChangeForm, UserProfileForm,
    PasswordResetRequestForm, PasswordResetConfirmForm
)
from .models import UserProfile
from .authorization import (
    can_view_profile, can_edit_profile, can_delete_user, 
    staff_required, instructor_required, get_user_role,
    # IDOR Prevention Functions
    get_viewable_user, get_editable_user, get_deletable_user
)
from .login_throttle import LoginThrottler, get_client_ip


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
    """
    User login view with brute-force protection.
    
    Security features:
    - Tracks failed login attempts per account
    - Tracks failed attempts per IP address
    - Temporarily locks account after 5 failed attempts
    - 15-minute lockout period
    """
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    # Get client IP for throttling
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            # Check if account/IP is throttled
            if LoginThrottler.is_throttled(username, client_ip):
                # Log the throttle event
                throttle_reason = LoginThrottler.get_throttle_reason(username, client_ip)
                print(f"[SECURITY] Login throttled for {username} from {client_ip} - {throttle_reason}")
                
                # Show generic message to prevent information leakage
                messages.error(
                    request,
                    'Too many failed login attempts. Please try again later.'
                )
                return render(request, 'taremwa/login.html', {'form': form})
            
            # Attempt authentication
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Successful login
                login(request, user)
                LoginThrottler.record_attempt(username, client_ip, successful=True)
                # Clear failure counters on success
                LoginThrottler.clear_failures(username=username, ip_address=client_ip)
                
                messages.success(request, f'Welcome back, {user.username}!')
                return redirect('taremwa:dashboard')
            else:
                # Failed login - record and check throttle
                LoginThrottler.record_attempt(username, client_ip, successful=False)
                failures_account, failures_ip = LoginThrottler.get_failure_count(username, client_ip)
                
                # Show generic error (don't reveal if user exists)
                messages.error(request, 'Invalid username or password.')
                
                # Optionally warn user if they're close to lockout
                remaining = max(
                    5 - failures_account,
                    5 - failures_ip
                )
                if 0 < remaining < 3:
                    messages.warning(
                        request,
                        f'Warning: {remaining} login attempt(s) remaining before temporary lockout.'
                    )
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
    
    IDOR Prevention: Uses get_viewable_user and get_editable_user for atomic
    access control checks, preventing IDOR attacks via ID manipulation.
    """
    if user_id is None:
        # Viewing own profile - no IDOR risk
        profile = get_object_or_404(UserProfile, user=request.user)
        target_user = request.user
    else:
        # Viewing other user's profile - IDOR check required
        # Use IDOR prevention function: atomically get user AND check permission
        target_user = get_viewable_user(request.user, user_id)
        if target_user is None:
            messages.error(request, 'Profile not found or access denied.')
            return HttpResponseForbidden('Forbidden: You cannot access this profile.')
        
        profile = get_object_or_404(UserProfile, user=target_user)
    
    # Check if editing
    if request.method == 'POST':
        # IDOR check for editing: use atomic access control function
        if user_id is not None:
            editable_user = get_editable_user(request.user, user_id)
            if editable_user is None:
                messages.error(request, 'You do not have permission to edit this profile.')
                return HttpResponseForbidden('Forbidden: You cannot edit this profile.')
            target_user = editable_user
        elif not can_edit_profile(request.user, request.user):
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
    """
    Delete user - staff only with granular object-level access control.
    
    IDOR Prevention: Uses get_deletable_user for atomic access control check.
    Staff cannot delete other staff or admins. Only admins can delete staff.
    """
    # IDOR check: Use atomic access control function
    target_user = get_deletable_user(request.user, user_id)
    if target_user is None:
        messages.error(request, 'User not found or you do not have permission to delete this user.')
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


def password_reset_request(request):
    """
    Handle password reset requests.
    
    Security considerations:
    1. Prevents user enumeration: Returns generic success message regardless
       of whether email exists in system
    2. Uses Django's default token generator: Cryptographically secure,
       time-limited tokens based on user state (prevents token reuse after password change)
    3. Token sent via email: No tokens in logs or URL history (only base64 encoded in email)
    4. Rate limiting: Implement at reverse proxy/middleware level in production
    """
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Check if user exists - silently succeed either way to prevent enumeration
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = None
            
            # Only send email if user exists
            if user:
                # Generate secure token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Build reset link
                reset_link = request.build_absolute_uri(
                    f'/auth/password-reset-confirm/{uid}/{token}/'
                )
                
                # Prepare email
                subject = 'Password Reset Request for Taremwa UAS'
                message = f"""
Hello {user.username},

You requested a password reset for your Taremwa UAS account.

Click the link below to reset your password:
{reset_link}

This link will expire in 24 hours.

If you did not request this password reset, please ignore this email.
Your password will not change until you visit the link above and create a new one.

Best regards,
Taremwa UAS Team
                """
                
                try:
                    send_mail(
                        subject,
                        message,
                        'noreply@devsec-demo.local',  # From email
                        [user.email],  # To emails
                        fail_silently=False,
                    )
                except Exception as e:
                    # Log error but still show success to prevent enumeration
                    print(f"Error sending password reset email: {e}")
            
            # Always show success message (prevents user enumeration through UI)
            messages.success(
                request,
                'If an account exists for this email, you will receive '
                'password reset instructions. Please check your email.'
            )
            return redirect('taremwa:password_reset_done')
    else:
        form = PasswordResetRequestForm()
    
    return render(request, 'taremwa/password_reset_request.html', {'form': form})


def password_reset_done(request):
    """
    Display confirmation message after password reset request.
    
    This page doesn't expose whether the email was found in the system.
    """
    return render(request, 'taremwa/password_reset_done.html')


def password_reset_confirm(request, uidb64, token):
    """
    Handle password reset confirmation with token validation.
    
    Security considerations:
    1. Token validation: Verifies token hasn't been modified and hasn't expired
    2. User state binding: Token becomes invalid after any password change,
       preventing attacker use of leaked tokens
    3. One-time token: Token is only valid once (regenerated for each request)
    4. HTTPS only in production: Tokens should not be sent over HTTP
    """
    try:
        # Decode user ID from base64
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    # Validate token
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = PasswordResetConfirmForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(
                    request,
                    'Your password has been successfully reset. '
                    'You can now log in with your new password.'
                )
                return redirect('taremwa:login')
        else:
            form = PasswordResetConfirmForm(user)
        
        return render(request, 'taremwa/password_reset_confirm.html', {
            'form': form,
            'uidb64': uidb64,
            'token': token,
            'valid_link': True,
        })
    else:
        # Token is invalid or expired
        messages.error(
            request,
            'The password reset link is invalid or has expired. '
            'Please request a new password reset.'
        )
        return render(request, 'taremwa/password_reset_invalid.html', {
            'valid_link': False,
        })
