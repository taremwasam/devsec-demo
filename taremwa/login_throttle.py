"""
Login throttling and brute-force protection utilities.

Implements hybrid throttling:
- Account-based: Track failed attempts per username
- IP-based: Track failed attempts per IP address
- Temporary lockout: After N failed attempts
"""

from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from .models import LoginAttempt


# Configuration
MAX_LOGIN_ATTEMPTS = 5  # Failed attempts before lockout
LOCKOUT_DURATION = 900  # 15 minutes in seconds
ATTEMPT_WINDOW = 1800  # 30 minutes - window for counting attempts


class LoginThrottler:
    """
    Manages brute-force detection and mitigation for login attempts.
    
    Tracks failed login attempts per username and IP address.
    Implements temporary account lockout after repeated failures.
    """
    
    @staticmethod
    def _get_cache_key(key_type: str, identifier: str) -> str:
        """Generate cache key for throttle tracking."""
        return f"login_throttle:{key_type}:{identifier}"

    @staticmethod
    def _get_ip_accounts_key(ip_address: str) -> str:
        """Generate cache key for usernames seen failing from an IP."""
        return LoginThrottler._get_cache_key('ip_accounts', ip_address)
    
    @staticmethod
    def record_attempt(username: str, ip_address: str, successful: bool) -> None:
        """
        Record a login attempt in the database.
        
        Args:
            username: The username attempting to login
            ip_address: The IP address of the attempt
            successful: Whether the login was successful
        """
        LoginAttempt.objects.create(
            username=username,
            ip_address=ip_address,
            successful=successful
        )
        
        # Only track failures for throttling
        if not successful:
            LoginThrottler._increment_failure_count(username, ip_address)
    
    @staticmethod
    def _increment_failure_count(username: str, ip_address: str) -> None:
        """Increment failure counts in cache for both account and IP."""
        username_key = LoginThrottler._get_cache_key('username', username)
        ip_key = LoginThrottler._get_cache_key('ip', ip_address)
        ip_accounts_key = LoginThrottler._get_ip_accounts_key(ip_address)

        # Initialize counters if missing, then increment safely.
        if cache.get(username_key) is None:
            cache.set(username_key, 0, ATTEMPT_WINDOW)
        if cache.get(ip_key) is None:
            cache.set(ip_key, 0, ATTEMPT_WINDOW)
        usernames_for_ip = cache.get(ip_accounts_key) or []
        if username not in usernames_for_ip:
            usernames_for_ip.append(username)
            cache.set(ip_accounts_key, usernames_for_ip, ATTEMPT_WINDOW)

        cache.incr(username_key, 1)
        cache.incr(ip_key, 1)
    
    @staticmethod
    def get_failure_count(username: str, ip_address: str) -> tuple:
        """
        Get current failure counts.
        
        Returns:
            Tuple of (username_failures, ip_failures)
        """
        username_key = LoginThrottler._get_cache_key('username', username)
        ip_key = LoginThrottler._get_cache_key('ip', ip_address)
        
        username_failures = cache.get(username_key, 0)
        ip_failures = cache.get(ip_key, 0)
        
        return username_failures, ip_failures
    
    @staticmethod
    def is_throttled(username: str, ip_address: str) -> bool:
        """
        Check if login should be throttled for this account or IP.
        
        Uses hybrid approach:
        - Account is throttled if it has too many failures
        - IP is throttled if it has too many failures
        
        Returns:
            True if login should be denied, False if allowed
        """
        username_failures, ip_failures = LoginThrottler.get_failure_count(
            username, ip_address
        )
        usernames_for_ip = cache.get(LoginThrottler._get_ip_accounts_key(ip_address), [])

        # Throttle if either username or IP exceeds limit
        return (
            username_failures >= MAX_LOGIN_ATTEMPTS
            or len(usernames_for_ip) >= MAX_LOGIN_ATTEMPTS
        )
    
    @staticmethod
    def get_throttle_reason(username: str, ip_address: str) -> str:
        """
        Get reason for throttle (for logging/debugging).
        
        Returns:
            String describing which throttle(s) are active
        """
        username_failures, ip_failures = LoginThrottler.get_failure_count(
            username, ip_address
        )
        usernames_for_ip = cache.get(LoginThrottler._get_ip_accounts_key(ip_address), [])
        
        reasons = []
        if username_failures >= MAX_LOGIN_ATTEMPTS:
            reasons.append(f"account ({username_failures} failures)")
        if len(usernames_for_ip) >= MAX_LOGIN_ATTEMPTS:
            reasons.append(f"IP ({ip_failures} failures across {len(usernames_for_ip)} accounts)")
        
        return " + ".join(reasons) if reasons else "unknown"
    
    @staticmethod
    def clear_failures(username: str = None, ip_address: str = None) -> None:
        """
        Clear failure counts for a user or IP.
        
        Called after successful login to reset the counter.
        
        Args:
            username: Username to clear (or None to skip)
            ip_address: IP address to clear (or None to skip)
        """
        if username:
            username_key = LoginThrottler._get_cache_key('username', username)
            cache.delete(username_key)
        
        if ip_address:
            ip_key = LoginThrottler._get_cache_key('ip', ip_address)
            cache.delete(ip_key)
            cache.delete(LoginThrottler._get_ip_accounts_key(ip_address))
    
    @staticmethod
    def get_recent_attempts(username: str = None, ip_address: str = None, 
                           limit: int = 10) -> list:
        """
        Get recent login attempts from database.
        
        Useful for security auditing and investigation.
        
        Args:
            username: Filter by username (optional)
            ip_address: Filter by IP address (optional)
            limit: Maximum number of records to return
        
        Returns:
            List of LoginAttempt objects
        """
        queryset = LoginAttempt.objects.all().order_by('-attempted_at')
        
        if username:
            queryset = queryset.filter(username=username)
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)
        
        return list(queryset[:limit])


def get_client_ip(request) -> str:
    """
    Extract client IP from request.
    
    Handles proxies and X-Forwarded-For headers.
    
    Args:
        request: Django request object
    
    Returns:
        Client IP address as string
    """
    # Check for IP from proxy
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs; take the first
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    return ip
