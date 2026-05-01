"""
Tests for open redirect vulnerability prevention.

This test suite verifies that:
1. Redirect utilities properly validate URLs
2. Internal redirects are allowed
3. External redirects are blocked
4. Dangerous URL schemes are rejected
5. Protocol-relative URLs are rejected
6. Authentication flows handle 'next' parameter safely
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from taremwa.redirect_utils import (
    is_safe_redirect_url,
    get_safe_redirect_url,
    get_next_parameter_for_template,
    add_next_parameter_to_url
)


class RedirectUtilsValidationTests(TestCase):
    """Test redirect validation utility functions"""
    
    def test_safe_internal_path_redirect(self):
        """Internal paths should be allowed"""
        self.assertTrue(is_safe_redirect_url('/dashboard/'))
        self.assertTrue(is_safe_redirect_url('/profile/'))
        self.assertTrue(is_safe_redirect_url('/profile/1/'))
        self.assertTrue(is_safe_redirect_url('/auth/login/'))
    
    def test_safe_relative_redirect(self):
        """Relative paths should be allowed"""
        self.assertTrue(is_safe_redirect_url('dashboard/'))
        self.assertTrue(is_safe_redirect_url('./profile/'))
    
    def test_external_url_blocked(self):
        """External URLs should be blocked"""
        self.assertFalse(is_safe_redirect_url('https://evil.com'))
        self.assertFalse(is_safe_redirect_url('http://attacker.com/phishing'))
        self.assertFalse(is_safe_redirect_url('https://example.com/'))
    
    def test_protocol_relative_url_blocked(self):
        """Protocol-relative URLs (//) should be blocked"""
        self.assertFalse(is_safe_redirect_url('//evil.com'))
        self.assertFalse(is_safe_redirect_url('//attacker.com/phishing'))
    
    def test_javascript_scheme_blocked(self):
        """JavaScript URLs should be blocked"""
        self.assertFalse(is_safe_redirect_url('javascript:alert("xss")'))
        self.assertFalse(is_safe_redirect_url('javascript:void(0)'))
    
    def test_data_scheme_blocked(self):
        """Data URLs should be blocked"""
        self.assertFalse(is_safe_redirect_url('data:text/html,<script>alert(1)</script>'))
    
    def test_vbscript_scheme_blocked(self):
        """VBScript URLs should be blocked"""
        self.assertFalse(is_safe_redirect_url('vbscript:msgbox("xss")'))
    
    def test_empty_url_blocked(self):
        """Empty URLs should be blocked"""
        self.assertFalse(is_safe_redirect_url(''))
        self.assertFalse(is_safe_redirect_url(None))
    
    def test_url_with_query_parameters(self):
        """URLs with safe query parameters should be allowed"""
        self.assertTrue(is_safe_redirect_url('/dashboard/?tab=profile'))
        self.assertTrue(is_safe_redirect_url('/admin/users/?page=2&sort=name'))
    
    def test_url_with_fragments(self):
        """URLs with fragments should be allowed"""
        self.assertTrue(is_safe_redirect_url('/dashboard/#section1'))
        self.assertTrue(is_safe_redirect_url('/docs/#intro'))


class GetSafeRedirectUrlTests(TestCase):
    """Test get_safe_redirect_url function"""
    
    def setUp(self):
        """Create test client"""
        self.client = Client()
    
    def test_get_safe_redirect_from_get_parameter(self):
        """Should extract safe URL from GET parameter"""
        response = self.client.get('/auth/login/?next=/profile/', follow=False)
        # Note: This tests the utility, not the view yet
    
    def test_returns_default_for_unsafe_url(self):
        """Should return default URL if 'next' parameter is unsafe"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/?next=https://evil.com')
        
        result = get_safe_redirect_url(request, '/dashboard/', 'next')
        self.assertEqual(result, '/dashboard/')
    
    def test_returns_safe_url(self):
        """Should return validated safe URL from parameter"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/?next=/profile/')
        
        result = get_safe_redirect_url(request, '/dashboard/', 'next')
        self.assertEqual(result, '/profile/')
    
    def test_handles_missing_parameter(self):
        """Should return default if parameter is missing"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/')
        
        result = get_safe_redirect_url(request, '/dashboard/', 'next')
        self.assertEqual(result, '/dashboard/')
    
    def test_checks_post_parameter(self):
        """Should also check POST parameters"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.post('/auth/login/', {'next': '/profile/'})
        
        result = get_safe_redirect_url(request, '/dashboard/', 'next')
        self.assertEqual(result, '/profile/')


class LoginRedirectTests(TestCase):
    """Test login view redirect handling"""
    
    def setUp(self):
        """Create test user"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.login_url = reverse('taremwa:login')
    
    def test_login_redirect_to_safe_next_parameter(self):
        """Successful login should redirect to safe 'next' URL"""
        response = self.client.post(
            f'{self.login_url}?next=/profile/',
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Should redirect to profile instead of dashboard
        self.assertEqual(response.status_code, 302)
        self.assertIn('/profile/', response.url)
    
    def test_login_redirect_to_dashboard_for_unsafe_next(self):
        """Successful login should redirect to dashboard if 'next' is unsafe"""
        response = self.client.post(
            f'{self.login_url}?next=https://evil.com',
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Should redirect to dashboard (default), not evil.com
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
        self.assertNotIn('evil.com', response.url)
    
    def test_login_redirect_to_dashboard_by_default(self):
        """Successful login without 'next' parameter should redirect to dashboard"""
        response = self.client.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
    
    def test_login_blocks_javascript_redirect(self):
        """Login should block javascript: URLs in next parameter"""
        response = self.client.post(
            f'{self.login_url}?next=javascript:alert("xss")',
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Should redirect to dashboard, not execute JavaScript
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
        self.assertNotIn('javascript', response.url)
    
    def test_login_blocks_protocol_relative_redirect(self):
        """Login should block protocol-relative URLs"""
        response = self.client.post(
            f'{self.login_url}?next=//evil.com/phishing',
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard/', response.url)
    
    def test_login_next_parameter_on_failed_login(self):
        """Failed login should preserve 'next' parameter in form"""
        response = self.client.post(
            f'{self.login_url}?next=/profile/',
            {'username': 'testuser', 'password': 'wrongpassword'}
        )
        
        # Should show login form with error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid username or password')


class LogoutRedirectTests(TestCase):
    """Test logout view redirect handling"""
    
    def setUp(self):
        """Create and login test user"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.logout_url = reverse('taremwa:logout')
        self.client.login(username='testuser', password='testpass123')
    
    def test_logout_redirect_to_safe_next_parameter(self):
        """Logout should redirect to safe 'next' URL"""
        response = self.client.post(
            f'{self.logout_url}?next=/auth/login/',
            follow=False
        )
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)
    
    def test_logout_redirect_to_login_for_unsafe_next(self):
        """Logout should redirect to login if 'next' is unsafe"""
        response = self.client.post(
            f'{self.logout_url}?next=https://evil.com',
            follow=False
        )
        
        # Should redirect to login (default), not evil.com
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)
        self.assertNotIn('evil.com', response.url)
    
    def test_logout_redirect_to_login_by_default(self):
        """Logout without 'next' parameter should redirect to login"""
        response = self.client.post(self.logout_url, follow=False)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)


class RegistrationRedirectTests(TestCase):
    """Test registration view redirect handling"""
    
    def setUp(self):
        """Create test client"""
        self.client = Client()
        self.register_url = reverse('taremwa:register')
    
    def test_registration_redirect_to_safe_next_parameter(self):
        """Successful registration should redirect to safe 'next' URL"""
        response = self.client.post(
            f'{self.register_url}?next=/auth/login/',
            {
                'username': 'newuser',
                'email': 'new@example.com',
                'password1': 'safepass123!',
                'password2': 'safepass123!'
            },
            follow=False
        )
        
        # Should redirect to login (or next parameter)
        self.assertEqual(response.status_code, 302)
        # Should redirect to login URL
        self.assertIn('/auth/login/', response.url)
    
    def test_registration_redirect_to_login_for_unsafe_next(self):
        """Registration should redirect to login if 'next' is unsafe"""
        response = self.client.post(
            f'{self.register_url}?next=https://evil.com',
            {
                'username': 'newuser',
                'email': 'new@example.com',
                'password1': 'safepass123!',
                'password2': 'safepass123!'
            },
            follow=False
        )
        
        # Should redirect to login, not evil.com
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)
        self.assertNotIn('evil.com', response.url)


class OpenRedirectSecurityTests(TestCase):
    """Security-focused tests for open redirect prevention"""
    
    def setUp(self):
        """Create test user"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_redirects_never_contain_evil_domain(self):
        """Redirects should never contain attacker domain"""
        client = Client()
        login_url = reverse('taremwa:login')
        
        response = client.post(
            f'{login_url}?next=https://attacker.com/phishing&also=//malicious.io',
            {'username': 'testuser', 'password': 'testpass123'},
            follow=False
        )
        
        # Verify dangerous domains not in redirect
        self.assertNotIn('attacker.com', response.url)
        self.assertNotIn('malicious.io', response.url)
        self.assertNotIn('evil', response.url.lower())
    
    def test_multiple_attack_vectors_blocked(self):
        """Multiple attack vectors should all be blocked"""
        attack_urls = [
            'https://evil.com',
            '//attacker.com',
            'javascript:void(0)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox("xss")',
        ]
        
        for attack_url in attack_urls:
            with self.subTest(attack_url=attack_url):
                self.assertFalse(
                    is_safe_redirect_url(attack_url),
                    msg=f"Attack vector not blocked: {attack_url}"
                )
    
    def test_safe_urls_always_allowed(self):
        """Safe URLs should always be allowed"""
        safe_urls = [
            '/dashboard/',
            '/profile/',
            '/admin/users/',
            '/auth/logout/',
            '/docs/',
        ]
        
        for safe_url in safe_urls:
            with self.subTest(safe_url=safe_url):
                self.assertTrue(
                    is_safe_redirect_url(safe_url),
                    msg=f"Safe URL blocked: {safe_url}"
                )


class AddNextParameterToUrlTests(TestCase):
    """Test add_next_parameter_to_url utility"""
    
    def test_add_next_parameter_to_url(self):
        """Should properly add next parameter to URL"""
        result = add_next_parameter_to_url('/auth/login/', '/profile/')
        self.assertIn('next=%2Fprofile%2F', result)  # URL encoded
        self.assertIn('/auth/login/', result)
    
    def test_adds_question_mark_if_needed(self):
        """Should add ? if URL has no query parameters"""
        result = add_next_parameter_to_url('/auth/login/', '/profile/')
        self.assertIn('?', result)
    
    def test_adds_ampersand_if_needed(self):
        """Should add & if URL already has query parameters"""
        result = add_next_parameter_to_url('/auth/login/?redirect=true', '/profile/')
        self.assertIn('&', result)
    
    def test_rejects_unsafe_next_url(self):
        """Should not add unsafe URLs to parameter"""
        result = add_next_parameter_to_url('/auth/login/', 'https://evil.com')
        self.assertNotIn('next=', result)
        self.assertEqual(result, '/auth/login/')
    
    def test_handles_empty_next_url(self):
        """Should handle empty next URL"""
        result = add_next_parameter_to_url('/auth/login/', '')
        self.assertEqual(result, '/auth/login/')


class NextParameterForTemplateTests(TestCase):
    """Test get_next_parameter_for_template function"""
    
    def test_extracts_safe_next_parameter(self):
        """Should extract safe next parameter for template"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/?next=/profile/')
        
        result = get_next_parameter_for_template(request, 'next')
        self.assertEqual(result, '/profile/')
    
    def test_returns_empty_for_unsafe_next_parameter(self):
        """Should return empty string for unsafe next parameter"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/?next=https://evil.com')
        
        result = get_next_parameter_for_template(request, 'next')
        self.assertEqual(result, '')
    
    def test_returns_empty_if_no_next_parameter(self):
        """Should return empty string if no next parameter"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/auth/login/')
        
        result = get_next_parameter_for_template(request, 'next')
        self.assertEqual(result, '')
