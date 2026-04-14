from functools import wraps
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden


def staff_required(view_func):
    """
    Decorator to require staff group membership or admin status.
    Redirects to login if not authenticated, shows 403 if not staff.
    """
    @wraps(view_func)
    @login_required(login_url='taremwa:login')
    def wrapper(request, *args, **kwargs):
        if request.user.is_staff or request.user.groups.filter(name='staff').exists():
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You do not have permission to access this page.')
        return HttpResponseForbidden('Forbidden: Insufficient permissions')
    return wrapper


def instructor_required(view_func):
    """
    Decorator to require instructor group membership or staff/admin status.
    """
    @wraps(view_func)
    @login_required(login_url='taremwa:login')
    def wrapper(request, *args, **kwargs):
        if (request.user.is_staff or 
            request.user.groups.filter(name__in=['staff', 'instructor']).exists()):
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You do not have permission to access this page.')
        return HttpResponseForbidden('Forbidden: Insufficient permissions')
    return wrapper


def permission_required_with_message(perm, message='You do not have permission to access this resource.'):
    """
    Enhanced permission_required decorator that shows a message before 403.
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url='taremwa:login')
        def wrapper(request, *args, **kwargs):
            if request.user.has_perm(perm):
                return view_func(request, *args, **kwargs)
            messages.error(request, message)
            return HttpResponseForbidden('Forbidden: Insufficient permissions')
        return wrapper
    return decorator


class AuthorizationMixin:
    """
    Mixin for authorization checks in class-based views.
    Set required_group, required_permission, or is_owner_required.
    """
    required_group = None
    required_permission = None
    is_owner_required = False
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('taremwa:login')
        
        # Check group requirement
        if self.required_group:
            if not (request.user.is_staff or 
                    request.user.groups.filter(name=self.required_group).exists()):
                return HttpResponseForbidden('Forbidden: Insufficient permissions')
        
        # Check permission requirement
        if self.required_permission:
            if not request.user.has_perm(self.required_permission):
                return HttpResponseForbidden('Forbidden: Insufficient permissions')
        
        # Check if user is accessing their own resource
        if self.is_owner_required:
            user_id = kwargs.get('user_id')
            if user_id and user_id != request.user.id and not request.user.is_staff:
                return HttpResponseForbidden('Forbidden: You can only access your own profile')
        
        return super().dispatch(request, *args, **kwargs)


def can_view_profile(user, target_user):
    """
    Check if user can view target_user's profile.
    Rules:
    - Users can view their own profile
    - Staff can view anyone
    - Instructors can view anyone
    - Others cannot view other profiles
    """
    if user == target_user:
        return True
    if user.is_staff:
        return True
    if user.groups.filter(name__in=['staff', 'instructor']).exists():
        return True
    return False


def can_edit_profile(user, target_user):
    """
    Check if user can edit target_user's profile.
    Rules:
    - Users can edit their own profile
    - Staff can edit anyone
    - Admins can edit anyone
    - Others cannot edit other profiles
    """
    if user == target_user:
        return True
    if user.is_staff or user.is_superuser:
        return True
    return False


def can_delete_user(user, target_user):
    """
    Check if user can delete target_user.
    
    Rules:
    - Users cannot delete anyone
    - Staff can only delete regular users
    - Admins can delete anyone
    - No one can delete themselves
    """
    # Cannot delete yourself
    if user == target_user:
        return False
    
    # Only admins and superusers can delete
    if user.is_superuser:
        return True
    
    # Staff can delete, but not other staff or admins
    if user.is_staff:
        # Staff can only delete regular users, not staff or admins
        if target_user.is_staff or target_user.is_superuser:
            return False
        return True
    
    # Regular users cannot delete anyone
    return False


def get_user_role(user):
    """
    Get the primary role of a user.
    Returns: 'admin', 'staff', 'instructor', 'user', or 'anonymous'
    """
    if not user.is_authenticated:
        return 'anonymous'
    if user.is_superuser:
        return 'admin'
    if user.is_staff:
        return 'staff'
    if user.groups.filter(name='instructor').exists():
        return 'instructor'
    return 'user'


# ============================================================================
# IDOR (Insecure Direct Object Reference) Prevention Functions
# ============================================================================
# These functions enforce object-level access control to prevent IDOR attacks.
# They should be used in any view that retrieves a user or profile by ID.
# ============================================================================


def get_viewable_user(current_user, user_id):
    """
    Atomically get a user and verify the current user can view it.
    
    IDOR Prevention: This function prevents unauthorized viewing of user data
    by checking ownership at retrieval time. Returns None if access is denied.
    
    Rules:
    - Users can view their own profile
    - Staff can view any user
    - Instructors can view any user
    - Regular users cannot view other users
    
    Args:
        current_user: The user making the request
        user_id: The ID of the user to retrieve
        
    Returns:
        User object if access is allowed, None if denied
    """
    from django.contrib.auth.models import User
    
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None
    
    # Check permission
    if not can_view_profile(current_user, target_user):
        return None
    
    return target_user


def get_editable_user(current_user, user_id):
    """
    Atomically get a user and verify the current user can edit it.
    
    IDOR Prevention: This function prevents unauthorized modification of user data.
    Returns None if access is denied.
    
    Rules:
    - Users can edit their own profile
    - Staff can edit any user
    - Only admins can edit admin accounts
    
    Args:
        current_user: The user making the request
        user_id: The ID of the user to retrieve
        
    Returns:
        User object if access is allowed, None if denied
    """
    from django.contrib.auth.models import User
    
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None
    
    # Check permission
    if not can_edit_profile(current_user, target_user):
        return None
    
    return target_user


def get_deletable_user(current_user, user_id):
    """
    Atomically get a user and verify the current user can delete it.
    
    IDOR Prevention: This function prevents unauthorized deletion of user accounts.
    Enforces granular deletion rules:
    - Users cannot delete anyone
    - Staff cannot delete other staff
    - Staff cannot delete admins
    - Staff cannot delete their own account
    - Only admins can delete anyone (including other admins)
    
    Returns None if access is denied.
    
    Args:
        current_user: The user making the request
        user_id: The ID of the user to delete
        
    Returns:
        User object if deletion is allowed, None if denied
    """
    from django.contrib.auth.models import User
    
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None
    
    # Check permission (updated to prevent staff from deleting staff)
    if not can_delete_user(current_user, target_user):
        return None
    
    # Additional rule: Staff cannot delete other staff (only admins can)
    if current_user.is_staff and not current_user.is_superuser:
        if target_user.is_staff or target_user.is_superuser:
            return None
    
    return target_user
