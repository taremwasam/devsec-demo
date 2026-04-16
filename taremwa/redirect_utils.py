"""
Redirect validation utilities for safe post-authentication navigation.

This module provides utilities to validate redirect destinations and prevent
open redirect vulnerabilities in authentication workflows.

Open Redirect Vulnerability:
- User clicks: /login/?next=https://evil.com
- After login, user is redirected to evil.com
- Attacker can phish credentials by making the evil.com look like our site

Solution:
- Validate that redirect targets are internal (same domain)
- Reject external URLs and protocol changes
- Use Django's url_has_allowed_host_and_scheme for validation
"""

from django.http import QueryDict
from urllib.parse import urlparse
from django.utils.http import url_has_allowed_host_and_scheme


def is_safe_redirect_url(url, allowed_hosts=None, require_https=False):
    """
    Validate that a redirect URL is safe to use.
    
    This function prevents open redirect attacks by validating:
    1. URL is not external (same host as request)
    2. Protocol is not changed (http/https)
    3. URL doesn't contain dangerous characters
    
    Args:
        url (str): The redirect URL to validate
        allowed_hosts (list): List of allowed hosts (Django's ALLOWED_HOSTS format)
        require_https (bool): Whether to require HTTPS (for production)
    
    Returns:
        bool: True if URL is safe for redirect, False otherwise
    
    Examples:
        >>> is_safe_redirect_url('/dashboard/')
        True
        
        >>> is_safe_redirect_url('/profile/1/')
        True
        
        >>> is_safe_redirect_url('https://evil.com')
        False
        
        >>> is_safe_redirect_url('//evil.com')
        False
        
        >>> is_safe_redirect_url('javascript:alert("xss")')
        False
    """
    if not url:
        return False
    
    # Reject URLs with dangerous schemes
    if url.startswith(('javascript:', 'data:', 'vbscript:')):
        return False
    
    # Check for protocol-relative URLs (//evil.com)
    # These can be used for open redirects
    if url.startswith('//'):
        return False
    
    # Use Django's built-in validator for safe redirect URLs
    # This checks that the URL is relative or has an allowed host
    try:
        # allowed_hosts defaults to None which uses ALLOWED_HOSTS from settings
        return url_has_allowed_host_and_scheme(
            url=url,
            allowed_hosts=allowed_hosts,
            require_https=require_https
        )
    except Exception:
        return False


def get_safe_redirect_url(request, default_url, parameter_name='next'):
    """
    Extract and validate a redirect URL from request parameters.
    
    This function safely gets a 'next' parameter from GET or POST,
    validates it, and returns either the validated redirect or a default.
    
    Args:
        request: Django request object
        default_url (str): URL to redirect to if no valid 'next' parameter
        parameter_name (str): Name of parameter to check (default: 'next')
    
    Returns:
        str: Validated redirect URL or default_url if parameter is unsafe
    
    Examples:
        # Safe redirect in GET parameter
        # /login/?next=/profile/
        url = get_safe_redirect_url(request, '/dashboard/', 'next')
        # Returns: '/profile/'
        
        # Unsafe redirect attempt (external URL)
        # /login/?next=https://evil.com
        url = get_safe_redirect_url(request, '/dashboard/', 'next')
        # Returns: '/dashboard/' (the default)
    """
    # Get 'next' parameter from GET or POST (POST for forms, GET for links)
    next_url = request.GET.get(parameter_name) or request.POST.get(parameter_name)
    
    if not next_url:
        return default_url
    
    # Validate the redirect URL
    if is_safe_redirect_url(next_url):
        return next_url
    
    # If validation fails, use the default
    return default_url


def get_next_parameter_for_template(request, parameter_name='next'):
    """
    Get the 'next' parameter value to embed in a form for redirect.
    
    This function safely extracts the 'next' parameter from request
    to pass it back to the form/template without validation errors.
    
    Unlike get_safe_redirect_url, this returns the value even if unsafe
    because the form won't actually use it - it's only rendered in HTML
    for the next request to validate. This prevents leaking security issues.
    
    Args:
        request: Django request object
        parameter_name (str): Name of parameter to check (default: 'next')
    
    Returns:
        str: The 'next' parameter value (validated at redirect time)
    
    Example in view:
        next_param = get_next_parameter_for_template(request, 'next')
        return render(request, 'login.html', {'next': next_param})
    
    Example in template:
        <form method="POST">
            {% csrf_token %}
            ...form fields...
            {% if next %}
                <input type="hidden" name="next" value="{{ next }}">
            {% endif %}
            <button type="submit">Login</button>
        </form>
    """
    # Get from GET or POST
    next_url = request.GET.get(parameter_name) or request.POST.get(parameter_name)
    
    # Only return if it's safe (we validate at redirect time anyway)
    if next_url and is_safe_redirect_url(next_url):
        return next_url
    
    return ''


def add_next_parameter_to_url(base_url, next_url):
    """
    Safely add a 'next' parameter to a URL for redirects to login.
    
    Used to redirect unauthenticated users to login but remember where
    they came from so they can be redirected back after login.
    
    Args:
        base_url (str): Base URL (e.g., '/auth/login/')
        next_url (str): URL to redirect to after completion
    
    Returns:
        str: base_url with 'next' parameter added (if next_url is safe)
    
    Example:
        # User tries to access /profile/ but needs to login first
        # Redirect to: /auth/login/?next=/profile/
        redirect_url = add_next_parameter_to_url('/auth/login/', '/profile/')
        return redirect(redirect_url)
    """
    if not next_url:
        return base_url
    
    # Only add 'next' if it's safe
    if is_safe_redirect_url(next_url):
        # Use ? or & depending on whether base_url already has parameters
        separator = '&' if '?' in base_url else '?'
        return f"{base_url}{separator}next={next_url}"
    
    return base_url
