import mimetypes

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.core.mail import send_mail
from django.db import IntegrityError
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .audit import get_actor_label, hash_identifier, log_security_event
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
from .redirect_utils import get_safe_redirect_url, get_next_parameter_for_template
from .upload_security import safe_download_name


def register(request):
    """
    User registration view with safe redirect handling.
    
    Security features:
    - Validates email uniqueness
    - Validates username uniqueness
    - Creates associated UserProfile
    - Validates 'next' parameter to prevent open redirects
    - Redirects to login or specified safe URL
    """
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                # Create associated UserProfile
                UserProfile.objects.get_or_create(user=user)
                log_security_event(
                    'auth.registration',
                    actor='anonymous',
                    target_user_id=user.pk,
                    target_username=user.username,
                    email_hash=hash_identifier(user.email),
                )
                messages.success(request, 'Registration successful! Please log in.')
                
                # Redirect to login (or safe next URL if provided)
                # Open Redirect Prevention: get_safe_redirect_url validates the URL
                next_url = get_safe_redirect_url(request, 'taremwa:login', 'next')
                return redirect(next_url)
            except IntegrityError:
                messages.error(request, 'An error occurred during registration. Please try again.')
    else:
        form = RegistrationForm()
    
    return render(request, 'taremwa/register.html', {'form': form})


def user_login(request):
    """
    User login view with brute-force protection and safe redirect handling.
    
    Security features:
    - Tracks failed login attempts per account
    - Tracks failed attempts per IP address
    - Temporarily locks account after 5 failed attempts
    - 15-minute lockout period
    - Validates 'next' parameter to prevent open redirects
    
    Redirect Validation:
    - Accepts optional 'next' parameter via GET or POST
    - Validates redirect target is internal (same domain)
    - Rejects external URLs, protocol changes, and malicious redirects
    - Falls back to dashboard if 'next' parameter is unsafe
    """
    if request.user.is_authenticated:
        return redirect('taremwa:dashboard')
    
    # Get client IP for throttling
    client_ip = get_client_ip(request)
    # Get next parameter for redirect (will be validated at redirect time)
    next_param = get_next_parameter_for_template(request)
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            # Check if account/IP is throttled
            if LoginThrottler.is_throttled(username, client_ip):
                throttle_reason = LoginThrottler.get_throttle_reason(username, client_ip)
                log_security_event(
                    'auth.login_throttled',
                    actor='anonymous',
                    attempted_username=username,
                    ip_address=client_ip,
                    reason=throttle_reason,
                )
                
                # Show generic message to prevent information leakage
                messages.error(
                    request,
                    'Too many failed login attempts. Please try again later.'
                )
                return render(request, 'taremwa/login.html', {'form': form, 'next': next_param})
            
            # Attempt authentication
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Successful login
                login(request, user)
                LoginThrottler.record_attempt(username, client_ip, successful=True)
                # Clear failure counters on success
                LoginThrottler.clear_failures(username=username, ip_address=client_ip)
                log_security_event(
                    'auth.login',
                    actor=get_actor_label(user),
                    outcome='success',
                    target_user_id=user.pk,
                    target_username=user.username,
                    ip_address=client_ip,
                )
                
                messages.success(request, f'Welcome back, {user.username}!')
                
                # Redirect to safe next URL or dashboard
                # Open Redirect Prevention: get_safe_redirect_url validates the URL
                next_url = get_safe_redirect_url(request, 'taremwa:dashboard', 'next')
                return redirect(next_url)
            else:
                # Failed login - record and check throttle
                LoginThrottler.record_attempt(username, client_ip, successful=False)
                failures_account, failures_ip = LoginThrottler.get_failure_count(username, client_ip)
                log_security_event(
                    'auth.login',
                    actor='anonymous',
                    outcome='failure',
                    attempted_username=username,
                    ip_address=client_ip,
                    failures_for_account=failures_account,
                    failures_for_ip=failures_ip,
                )
                
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
                
                # Return form with next parameter preserved for UX
                return render(request, 'taremwa/login.html', {'form': form, 'next': next_param})
    else:
        form = LoginForm()
    
    return render(request, 'taremwa/login.html', {'form': form, 'next': next_param})


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
        
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
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
def download_profile_upload(request, user_id, upload_kind):
    """
    Serve private profile uploads through application authorization checks.

    Files are stored outside any public media URL and are only returned after
    verifying the requesting user is allowed to view the owning profile.
    """
    target_user = get_viewable_user(request.user, user_id)
    if target_user is None:
        return HttpResponseForbidden('Forbidden: You cannot access this file.')

    profile = get_object_or_404(UserProfile, user=target_user)
    field_map = {
        'avatar': ('avatar', True, 'avatar'),
        'document': ('document', False, 'document.pdf'),
    }
    if upload_kind not in field_map:
        raise Http404('Upload not found.')

    field_name, is_inline, fallback_name = field_map[upload_kind]
    stored_file = getattr(profile, field_name)
    if not stored_file:
        raise Http404('Upload not found.')

    guessed_type, _ = mimetypes.guess_type(stored_file.name)
    response = FileResponse(
        stored_file.open('rb'),
        content_type=guessed_type or 'application/octet-stream',
        as_attachment=not is_inline,
        filename=safe_download_name(stored_file, fallback_name),
    )
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'private, no-store'
    return response


@login_required(login_url='taremwa:login')
def change_password(request):
    """Password change view"""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            log_security_event(
                'auth.password_change',
                actor=get_actor_label(request.user),
                outcome='success',
                target_user_id=request.user.pk,
                target_username=request.user.username,
            )
            messages.success(request, 'Password changed successfully!')
            return redirect('taremwa:profile')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'taremwa/change_password.html', {'form': form})


def user_logout(request):
    """
    User logout view with safe redirect handling.
    
    Security features:
    - Logs out the user
    - Validates 'next' parameter to prevent open redirects
    - Redirects to login page or specified safe URL
    """
    actor_label = get_actor_label(request.user)
    user_id = request.user.pk if request.user.is_authenticated else None
    username = request.user.username if request.user.is_authenticated else None
    logout(request)
    log_security_event(
        'auth.logout',
        actor=actor_label,
        target_user_id=user_id,
        target_username=username,
    )
    messages.info(request, 'You have been logged out successfully.')
    
    # Get safe redirect URL - defaults to login page
    # Open Redirect Prevention: get_safe_redirect_url validates the URL
    next_url = get_safe_redirect_url(request, 'taremwa:login', 'next')
    return redirect(next_url)


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
    
    CSRF Protection: Requires explicit user confirmation (typing username) to delete.
    This works in conjunction with Django's CSRF middleware to ensure:
    1. Request comes from user's own browser (CSRF token)
    2. User explicitly confirms deletion (confirmation field validation)
    """
    # IDOR check: Use atomic access control function
    target_user = get_deletable_user(request.user, user_id)
    if target_user is None:
        messages.error(request, 'User not found or you do not have permission to delete this user.')
        return redirect('taremwa:view_all_users')
    
    if request.method == 'POST':
        # CSRF Protection: Validate confirmation field matches username
        # This ensures the user explicitly confirmed the deletion
        confirm_input = request.POST.get('confirm', '').strip()
        target_username = target_user.username
        
        if confirm_input != target_username:
            # Confirmation field doesn't match - abort deletion
            # This prevents CSRF attacks that try to delete without proper confirmation
            messages.error(
                request,
                f'Confirmation failed. Please type "{target_username}" exactly to confirm deletion.'
            )
            context = {
                'target_user': target_user,
                'user_role': get_user_role(request.user),
            }
            return render(request, 'taremwa/confirm_delete_user.html', context)
        
        # Confirmation validated - proceed with deletion
        log_security_event(
            'privilege.account_deleted',
            actor=get_actor_label(request.user),
            target_user_id=target_user.pk,
            target_username=target_user.username,
        )
        target_user.delete()
        messages.success(request, f'User {target_username} has been deleted.')
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
                log_security_event(
                    'auth.password_reset_request',
                    actor='anonymous',
                    outcome='account_found',
                    target_user_id=user.pk,
                    target_username=user.username,
                    email_hash=hash_identifier(email),
                )
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
                    log_security_event(
                        'auth.password_reset_request',
                        actor='anonymous',
                        outcome='email_delivery_failed',
                        target_user_id=user.pk,
                        target_username=user.username,
                        email_hash=hash_identifier(email),
                        error_type=type(e).__name__,
                    )
            else:
                log_security_event(
                    'auth.password_reset_request',
                    actor='anonymous',
                    outcome='account_not_found',
                    email_hash=hash_identifier(email),
                )
            
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
                log_security_event(
                    'auth.password_reset_confirm',
                    actor='anonymous',
                    outcome='success',
                    target_user_id=user.pk,
                    target_username=user.username,
                )
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
        log_security_event(
            'auth.password_reset_confirm',
            actor='anonymous',
            outcome='invalid_or_expired',
            target_user_id=user.pk if user else None,
            uid_hint=uidb64[:12],
        )
        messages.error(
            request,
            'The password reset link is invalid or has expired. '
            'Please request a new password reset.'
        )
        return render(request, 'taremwa/password_reset_invalid.html', {
            'valid_link': False,
        })
