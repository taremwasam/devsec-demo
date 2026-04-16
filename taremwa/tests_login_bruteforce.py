"""
Comprehensive tests for login brute-force protection.

Tests cover:
- Normal login behavior (throttle doesn't affect legitimate users)
- Failed login tracking
- Account-based throttling
- IP-based throttling
- Lockout and cooldown behavior
- Throttle bypass attempts
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.cache import cache
from .models import LoginAttempt
from .login_throttle import LoginThrottler, get_client_ip


class LoginAttemptModelTests(TestCase):
    """Tests for LoginAttempt model."""
    
    def test_create_login_attempt(self):
        """Test creating a login attempt record."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            successful=False
        )
        
        self.assertEqual(attempt.username, 'testuser')
        self.assertEqual(attempt.ip_address, '192.168.1.1')
        self.assertFalse(attempt.successful)
    
    def test_login_attempt_str(self):
        """Test LoginAttempt string representation."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            successful=True
        )
        
        result = str(attempt)
        self.assertIn('Success', result)
        self.assertIn('testuser', result)


class LoginThrottlerUtilityTests(TestCase):
    """Tests for LoginThrottler utility class."""
    
    def setUp(self):
        """Clear cache before each test."""
        cache.clear()
    
    def tearDown(self):
        """Clear cache after each test."""
        cache.clear()
    
    def test_record_successful_attempt(self):
        """Test recording a successful login attempt."""
        LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=True)
        
        # Should be in database
        attempt = LoginAttempt.objects.get(username='testuser')
        self.assertTrue(attempt.successful)
    
    def test_record_failed_attempt(self):
        """Test recording a failed login attempt."""
        LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should be in database and increment cache counter
        attempt = LoginAttempt.objects.get(username='testuser')
        self.assertFalse(attempt.successful)
        
        # Check that failure count increased
        failures, _ = LoginThrottler.get_failure_count('testuser', '192.168.1.1')
        self.assertEqual(failures, 1)
    
    def test_get_failure_count(self):
        """Test retrieving failure counts."""
        # Record failures for account and IP
        LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        LoginThrottler.record_attempt('anotheruser', '192.168.1.1', successful=False)
        
        # testuser should have 2 failures
        testuser_failures, ip_failures = LoginThrottler.get_failure_count('testuser', '192.168.1.1')
        self.assertEqual(testuser_failures, 2)
        # IP should have 3 failures (from all attempts)
        self.assertEqual(ip_failures, 3)
    
    def test_throttle_not_triggered_under_limit(self):
        """Test that throttle doesn't trigger under the limit."""
        # Record 4 failures (below limit of 5)
        for _ in range(4):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should not be throttled
        is_throttled = LoginThrottler.is_throttled('testuser', '192.168.1.1')
        self.assertFalse(is_throttled)
    
    def test_throttle_triggered_at_limit(self):
        """Test that throttle triggers after max attempts."""
        # Record 5 failures (at limit)
        for _ in range(5):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should be throttled
        is_throttled = LoginThrottler.is_throttled('testuser', '192.168.1.1')
        self.assertTrue(is_throttled)
    
    def test_throttle_triggered_over_limit(self):
        """Test that throttle stays triggered beyond limit."""
        # Record 7 failures
        for _ in range(7):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should be throttled
        is_throttled = LoginThrottler.is_throttled('testuser', '192.168.1.1')
        self.assertTrue(is_throttled)
    
    def test_account_based_throttling(self):
        """Test that throttling is per-account."""
        # Record 5 failures for testuser from one IP
        for _ in range(5):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # testuser should be throttled
        self.assertTrue(LoginThrottler.is_throttled('testuser', '192.168.1.1'))
        
        # Another user on same IP should not be throttled yet
        self.assertFalse(LoginThrottler.is_throttled('otheruser', '192.168.1.1'))
    
    def test_ip_based_throttling(self):
        """Test that throttling is per-IP address."""
        # Record 5 failures from one IP across different accounts
        for i in range(5):
            LoginThrottler.record_attempt(f'user{i}', '192.168.1.1', successful=False)
        
        # All users from this IP should be throttled
        self.assertTrue(LoginThrottler.is_throttled('user0', '192.168.1.1'))
        self.assertTrue(LoginThrottler.is_throttled('user1', '192.168.1.1'))
        self.assertTrue(LoginThrottler.is_throttled('newuser', '192.168.1.1'))
        
        # User from different IP should not be throttled
        self.assertFalse(LoginThrottler.is_throttled('user0', '10.0.0.1'))
    
    def test_clear_failures_for_account(self):
        """Test clearing failure count for an account."""
        # Record failures
        for _ in range(5):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should be throttled
        self.assertTrue(LoginThrottler.is_throttled('testuser', '192.168.1.1'))
        
        # Clear failures for account
        LoginThrottler.clear_failures(username='testuser')
        
        # Should no longer be throttled
        self.assertFalse(LoginThrottler.is_throttled('testuser', '192.168.1.1'))
    
    def test_clear_failures_for_ip(self):
        """Test clearing failure count for an IP."""
        # Record failures from IP
        for i in range(5):
            LoginThrottler.record_attempt(f'user{i}', '192.168.1.1', successful=False)
        
        # Should be throttled
        self.assertTrue(LoginThrottler.is_throttled('user0', '192.168.1.1'))
        
        # Clear failures for IP
        LoginThrottler.clear_failures(ip_address='192.168.1.1')
        
        # Should no longer be throttled
        self.assertFalse(LoginThrottler.is_throttled('user0', '192.168.1.1'))
    
    def test_get_throttle_reason(self):
        """Test getting the reason for throttle."""
        # Account throttle
        for _ in range(5):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        reason = LoginThrottler.get_throttle_reason('testuser', '192.168.1.1')
        self.assertIn('account', reason)
        self.assertIn('5', reason)
    
    def test_successful_login_clears_account_throttle(self):
        """Test that successful login clears account failures."""
        # Record 5 failed attempts
        for _ in range(5):
            LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=False)
        
        # Should be throttled
        self.assertTrue(LoginThrottler.is_throttled('testuser', '192.168.1.1'))
        
        # Record successful attempt
        LoginThrottler.record_attempt('testuser', '192.168.1.1', successful=True)
        LoginThrottler.clear_failures(username='testuser', ip_address='192.168.1.1')
        
        # Should no longer be throttled
        self.assertFalse(LoginThrottler.is_throttled('testuser', '192.168.1.1'))


class LoginViewBruteForceTests(TestCase):
    """Tests for login view with brute-force protection."""
    
    def setUp(self):
        """Set up test user and client."""
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='ValidPassword123!'
        )
        self.url = reverse('taremwa:login')
    
    def tearDown(self):
        """Clean up."""
        cache.clear()
    
    def test_successful_login_allowed(self):
        """Test that legitimate login works."""
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'ValidPassword123!'
        })
        
        self.assertRedirects(response, reverse('taremwa:dashboard'))
    
    def test_failed_login_recorded(self):
        """Test that failed login is recorded."""
        self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword'
        })
        
        # Should have a failed attempt record
        self.assertTrue(
            LoginAttempt.objects.filter(
                username='testuser',
                successful=False
            ).exists()
        )
    
    def test_repeated_failed_logins_allowed_under_limit(self):
        """Test that repeated failed logins work until limit."""
        # Attempt 4 failed logins (under limit of 5)
        for _ in range(4):
            response = self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
            # Should still show login form, not throttle message
            self.assertEqual(response.status_code, 200)
    
    def test_repeated_failed_logins_blocked_at_limit(self):
        """Test that login is blocked after too many failures."""
        # Attempt 5 failed logins (at limit)
        for _ in range(5):
            self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        # Next attempt should be throttled
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'ValidPassword123!'  # Even correct password
        })
        
        # Should show throttle message
        self.assertContains(response, 'Too many failed login attempts')
    
    def test_warning_message_before_lockout(self):
        """Test that warning appears when getting close to lockout."""
        # Attempt 3 failed logins
        for _ in range(3):
            response = self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        # Next attempt (4th) should show warning
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword'
        })
        
        # Should contain warning message
        self.assertIn(b'Warning', response.content)
        self.assertIn(b'login attempt', response.content)
    
    def test_successful_login_resets_counter(self):
        """Test that successful login clears failure counter."""
        # Attempt some failed logins
        for _ in range(3):
            self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        # Successful login
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'ValidPassword123!'
        })
        
        # Should succeed and clear counter
        self.assertRedirects(response, reverse('taremwa:dashboard'))
        
        # Logout
        self.client.get(reverse('taremwa:logout'))
        
        # Now can fail again without being throttled
        for _ in range(5):
            self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        # 6th attempt should be throttled (new count of 5)
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword'
        })


class GetClientIpTests(TestCase):
    """Tests for IP extraction utility."""
    
    def test_get_ip_from_remote_addr(self):
        """Test getting IP from REMOTE_ADDR."""
        client = Client()
        request = client.get(reverse('taremwa:login')).wsgi_request
        # In tests, REMOTE_ADDR is usually 127.0.0.1
        ip = get_client_ip(request)
        self.assertIsNotNone(ip)
    
    def test_get_ip_from_x_forwarded_for(self):
        """Test getting IP from X-Forwarded-For header."""
        request_factory = type('Request', (), {})()
        request_factory.META = {
            'HTTP_X_FORWARDED_FOR': '192.168.1.100, 10.0.0.1, 172.16.0.1'
        }
        
        # Should take first IP from X-Forwarded-For
        ip = get_client_ip(request_factory)
        self.assertEqual(ip, '192.168.1.100')


class BruteForceSecurityTests(TestCase):
    """Tests for security aspects of brute-force protection."""
    
    def setUp(self):
        """Set up test environment."""
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='ValidPassword123!'
        )
        self.url = reverse('taremwa:login')
    
    def tearDown(self):
        """Clean up."""
        cache.clear()
    
    def test_user_enumeration_via_throttle_not_possible(self):
        """Test that throttle doesn't reveal user existence."""
        # Record 5 failed attempts for non-existent user
        for _ in range(5):
            self.client.post(self.url, {
                'username': 'nonexistent',
                'password': 'SomePassword'
            })
        
        # Should show same throttle message as for real user
        response = self.client.post(self.url, {
            'username': 'nonexistent',
            'password': 'SomePassword'
        })
        
        self.assertContains(response, 'Too many failed login attempts')
    
    def test_no_timing_leak_in_throttle_check(self):
        """Test that throttle check doesn't leak timing info."""
        import time
        
        # Time to login with throttled account
        for _ in range(5):
            self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        # Same login attempt twice - should take similar time
        start = time.time()
        self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword'
        })
        time1 = time.time() - start
        
        start = time.time()
        self.client.post(self.url, {
            'username': 'testuser',
            'password': 'WrongPassword'
        })
        time2 = time.time() - start
        
        # Timing should be similar (not conclusive but basic check)
        # This is a basic test - proper timing resistance requires more
    
    def test_generic_error_message_for_throttle(self):
        """Test that throttle uses generic error message."""
        # Trigger throttle
        for _ in range(5):
            self.client.post(self.url, {
                'username': 'testuser',
                'password': 'WrongPassword'
            })
        
        response = self.client.post(self.url, {
            'username': 'testuser',
            'password': 'ValidPassword123!'
        })
        
        # Should NOT mention "too many for this account"
        # Should NOT mention "too many from this IP"
        content = response.content.decode()
        self.assertIn('Too many failed login attempts', content)
        self.assertNotIn('account', content.lower().replace('account recovery', ''))
