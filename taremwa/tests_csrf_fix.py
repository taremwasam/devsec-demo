"""
Tests for CSRF protection fix in delete_user endpoint.

This test suite verifies that:
1. CSRF tokens are required on POST requests
2. Confirmation field must match username exactly
3. Deletion only proceeds with valid CSRF token AND correct confirmation
4. Generic CSRF attacks without confirmation field fail
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.middleware.csrf import get_token


class DeleteUserCSRFTests(TestCase):
    """Test CSRF protection in delete_user view"""
    
    def setUp(self):
        """Create test users with staff permissions"""
        self.client = Client(enforce_csrf_checks=True)
        
        # Create regular user to delete
        self.target_user = User.objects.create_user(
            username='target_user',
            email='target@example.com',
            password='testpass123'
        )
        
        # Create admin/staff user who can delete
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )
        self.admin_user.is_staff = True
        self.admin_user.is_superuser = True
        self.admin_user.save()
        
        self.delete_url = reverse('taremwa:delete_user', args=[self.target_user.id])
    
    def test_csrf_token_required_on_post(self):
        """POST without CSRF token should be rejected"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Try POST without CSRF token - should fail
        response = self.client.post(
            self.delete_url,
            {'confirm': 'target_user'},
            HTTP_X_CSRFTOKEN='invalid_token'  # Invalid token
        )
        
        # Should get 403 Forbidden due to CSRF validation
        self.assertEqual(response.status_code, 403)
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_deletion_fails_without_confirmation(self):
        """Deletion should fail if confirmation field is missing or empty"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token from GET request
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try POST without confirmation field
        response = self.client.post(
            self.delete_url,
            {},  # No confirmation field
            HTTP_X_CSRFTOKEN=csrftoken
        )
        
        # Should return 200 (redisplay form) not delete
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Confirmation failed')
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_deletion_fails_with_wrong_confirmation(self):
        """Deletion should fail if confirmation doesn't match username"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try POST with wrong confirmation
        response = self.client.post(
            self.delete_url,
            {'confirm': 'wrong_username'},  # Wrong confirmation
            HTTP_X_CSRFTOKEN=csrftoken
        )
        
        # Should return form with error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Confirmation failed')
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_deletion_fails_with_partial_confirmation(self):
        """Deletion should fail with partial username match"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try with partial match (case sensitivity and exact match required)
        response = self.client.post(
            self.delete_url,
            {'confirm': 'target'},  # Partial match
            HTTP_X_CSRFTOKEN=csrftoken
        )
        
        # Should fail
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Confirmation failed')
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_deletion_fails_with_extra_whitespace(self):
        """Confirmation should be trimmed but exact match required"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try with extra whitespace (should be trimmed by view)
        response = self.client.post(
            self.delete_url,
            {'confirm': '  target_user  '},  # Extra whitespace
            HTTP_X_CSRFTOKEN=csrftoken
        )
        
        # Should succeed because view strips whitespace
        self.assertEqual(response.status_code, 302)  # Redirect after deletion
        
        # User should be deleted
        self.assertFalse(User.objects.filter(username='target_user').exists())
    
    def test_deletion_succeeds_with_valid_csrf_and_confirmation(self):
        """Deletion should succeed with valid CSRF token and correct confirmation"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # POST with valid confirmation
        response = self.client.post(
            self.delete_url,
            {'confirm': 'target_user'},  # Correct confirmation
            HTTP_X_CSRFTOKEN=csrftoken,
            follow=True
        )
        
        # Should redirect to user list
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'All Users')
        
        # User should be deleted
        self.assertFalse(User.objects.filter(username='target_user').exists())
    
    def test_success_message_shown_after_deletion(self):
        """Success message should be displayed after successful deletion"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # POST with valid data
        response = self.client.post(
            self.delete_url,
            {'confirm': 'target_user'},
            HTTP_X_CSRFTOKEN=csrftoken,
            follow=True
        )
        
        # Check for success message
        self.assertContains(response, 'has been deleted')


class CSRFTokenRenderingTests(TestCase):
    """Test that CSRF tokens are properly rendered in templates"""
    
    def setUp(self):
        """Create test users"""
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )
        self.admin_user.is_staff = True
        self.admin_user.is_superuser = True
        self.admin_user.save()
        
        self.target_user = User.objects.create_user(
            username='target_user',
            email='target@example.com',
            password='testpass123'
        )
        
        self.delete_url = reverse('taremwa:delete_user', args=[self.target_user.id])
    
    def test_csrf_token_in_delete_template(self):
        """CSRF token should be rendered in delete confirmation template"""
        self.client.login(username='admin_user', password='adminpass123')
        
        response = self.client.get(self.delete_url)
        
        # Should render successfully
        self.assertEqual(response.status_code, 200)
        
        # Should contain CSRF token
        self.assertContains(response, 'csrf')
        self.assertContains(response, 'csrfmiddlewaretoken')
        
        # Should contain confirmation form
        self.assertContains(response, 'confirm')
    
    def test_csrf_token_in_all_forms(self):
        """All POST forms should have CSRF tokens"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Check key endpoints with POST forms
        urls_to_check = [
            reverse('taremwa:profile'),  # Edit profile
            reverse('taremwa:change_password'),  # Change password
            self.delete_url,  # Delete user
        ]
        
        for url in urls_to_check:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'csrf', msg_prefix=f"CSRF token missing in {url}")


class ConfirmationFieldValidationTests(TestCase):
    """Test confirmation field validation logic"""
    
    def setUp(self):
        """Create test users"""
        self.client = Client(enforce_csrf_checks=True)
        
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )
        self.admin_user.is_staff = True
        self.admin_user.is_superuser = True
        self.admin_user.save()
        
        # Create user with special characters in username
        self.target_user = User.objects.create_user(
            username='test.user-123',
            email='target@example.com',
            password='testpass123'
        )
        
        self.delete_url = reverse('taremwa:delete_user', args=[self.target_user.id])
    
    def test_confirmation_case_sensitive(self):
        """Username confirmation should be case-sensitive"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try with different case
        response = self.client.post(
            self.delete_url,
            {'confirm': 'TEST.USER-123'},  # Wrong case
            HTTP_X_CSRFTOKEN=csrftoken
        )
        
        # Should fail - Django usernames are case-sensitive
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Confirmation failed')
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='test.user-123').exists())
    
    def test_confirmation_with_special_characters(self):
        """Usernames with special characters must match exactly"""
        self.client.login(username='admin_user', password='adminpass123')
        
        # Get CSRF token
        get_response = self.client.get(self.delete_url)
        csrftoken = get_response.cookies['csrftoken'].value
        
        # Try with correct special characters
        response = self.client.post(
            self.delete_url,
            {'confirm': 'test.user-123'},  # Correct with special chars
            HTTP_X_CSRFTOKEN=csrftoken,
            follow=True
        )
        
        # Should succeed
        self.assertEqual(response.status_code, 200)
        
        # User should be deleted
        self.assertFalse(User.objects.filter(username='test.user-123').exists())


class CSRFBypassAttempts(TestCase):
    """Test various CSRF attack scenarios"""
    
    def setUp(self):
        """Create test users"""
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )
        self.admin_user.is_staff = True
        self.admin_user.is_superuser = True
        self.admin_user.save()
        
        self.target_user = User.objects.create_user(
            username='target_user',
            email='target@example.com',
            password='testpass123'
        )
        
        self.delete_url = reverse('taremwa:delete_user', args=[self.target_user.id])
    
    def test_empty_csrf_token_rejected(self):
        """Request with empty CSRF token should be rejected"""
        client = Client(enforce_csrf_checks=True)
        client.login(username='admin_user', password='adminpass123')
        
        response = client.post(
            self.delete_url,
            {'confirm': 'target_user'},
            HTTP_X_CSRFTOKEN=''  # Empty token
        )
        
        # Should reject
        self.assertEqual(response.status_code, 403)
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_missing_csrf_token_rejected(self):
        """Request without CSRF token should be rejected"""
        client = Client(enforce_csrf_checks=True)
        client.login(username='admin_user', password='adminpass123')
        
        # Don't include CSRF token at all
        response = client.post(
            self.delete_url,
            {'confirm': 'target_user'}
        )
        
        # Should reject
        self.assertEqual(response.status_code, 403)
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_confirmation_without_csrf_still_requires_token(self):
        """Even with correct confirmation, CSRF token is still required"""
        client = Client(enforce_csrf_checks=True)
        client.login(username='admin_user', password='adminpass123')
        
        # Correct confirmation but no CSRF token
        response = client.post(
            self.delete_url,
            {'confirm': 'target_user'}
            # No CSRF token
        )
        
        # Should still reject due to missing CSRF token
        self.assertEqual(response.status_code, 403)
        
        # User should not be deleted
        self.assertTrue(User.objects.filter(username='target_user').exists())


class DefaultClientCSRFBehavior(TestCase):
    """Test behavior with standard Django test client (auto-adds CSRF token)"""
    
    def setUp(self):
        """Create test users"""
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )
        self.admin_user.is_staff = True
        self.admin_user.is_superuser = True
        self.admin_user.save()
        
        self.target_user = User.objects.create_user(
            username='target_user',
            email='target@example.com',
            password='testpass123'
        )
        
        self.delete_url = reverse('taremwa:delete_user', args=[self.target_user.id])
    
    def test_standard_client_auto_adds_csrf_token(self):
        """Standard Client (enforce_csrf_checks=False) auto-adds CSRF tokens"""
        # Default client without CSRF enforcement
        self.client.login(username='admin_user', password='adminpass123')
        
        # POST with wrong confirmation
        response = self.client.post(
            self.delete_url,
            {'confirm': 'wrong'},
            follow=True
        )
        
        # Should get specific error about confirmation, not CSRF error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Confirmation failed')
        
        # User not deleted due to wrong confirmation
        self.assertTrue(User.objects.filter(username='target_user').exists())
    
    def test_standard_client_with_correct_confirmation(self):
        """Standard client with correct confirmation should delete user"""
        self.client.login(username='admin_user', password='adminpass123')
        
        response = self.client.post(
            self.delete_url,
            {'confirm': 'target_user'},
            follow=True
        )
        
        # Should succeed
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'has been deleted')
        
        # User should be deleted
        self.assertFalse(User.objects.filter(username='target_user').exists())
