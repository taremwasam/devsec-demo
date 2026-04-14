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
    Only admins can delete users.
    """
    if user == target_user:
        return False  # Cannot delete yourself
    if user.is_superuser:
        return True
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
