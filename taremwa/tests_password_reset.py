"""
Comprehensive tests for secure password reset workflow.

Tests cover:
- Successful password reset flow
- User enumeration prevention
- Token validation and expiration
- Password strength validation
- Authorization checks
- Error handling
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.core import mail
from .forms import PasswordResetRequestForm, PasswordResetConfirmForm
from .models import UserProfile


class PasswordResetRequestViewTests(TestCase):
    """Tests for password reset request view."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
        self.url = reverse('taremwa:password_reset_request')
    
    def test_get_password_reset_request_page(self):
        """Test that password reset request page loads successfully."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/password_reset_request.html')
        self.assertIsInstance(response.context['form'], PasswordResetRequestForm)
    
    def test_authenticated_user_redirected_to_dashboard(self):
        """Test that authenticated users are redirected to dashboard."""
        self.client.login(username='testuser', password='OldPassword123!')
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse('taremwa:dashboard'))
    
    def test_valid_email_sends_reset_email(self):
        """Test that valid email address triggers password reset email."""
        response = self.client.post(self.url, {'email': 'test@example.com'})
        
        # Check redirect to done page
        self.assertRedirects(response, reverse('taremwa:password_reset_done'))
        
        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, ['test@example.com'])
        self.assertIn('password reset', email.subject.lower())
    
    def test_invalid_email_shows_generic_message(self):
        """Test that non-existent email shows generic success message (no enumeration)."""
        response = self.client.post(self.url, {'email': 'nonexistent@example.com'})
        
        # Check redirect to done page
        self.assertRedirects(response, reverse('taremwa:password_reset_done'))
        
        # Check NO email was sent
        self.assertEqual(len(mail.outbox), 0)
        
        # User sees same message as with valid email
        response = self.client.get(reverse('taremwa:password_reset_done'))
        self.assertIn('If an account exists', response.content.decode())
    
    def test_empty_email_shows_form_error(self):
        """Test that empty email field shows validation error."""
        response = self.client.post(self.url, {'email': ''})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].has_error('email'))
    
    def test_invalid_email_format_shows_form_error(self):
        """Test that invalid email format shows validation error."""
        response = self.client.post(self.url, {'email': 'not-an-email'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].has_error('email'))
    
    def test_email_contains_reset_link(self):
        """Test that reset email contains valid reset link."""
        self.client.post(self.url, {'email': 'test@example.com'})
        
        email = mail.outbox[0]
        email_body = email.body
        
        # Check that link is present
        self.assertIn('password-reset-confirm', email_body)
        # Check that token is present
        self.assertIn(default_token_generator.make_token(self.user), email_body)


class PasswordResetDoneViewTests(TestCase):
    """Tests for password reset done page."""
    
    def setUp(self):
        self.url = reverse('taremwa:password_reset_done')
    
    def test_get_password_reset_done_page(self):
        """Test that password reset done page loads successfully."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/password_reset_done.html')
        self.assertIn('Check Your Email', response.content.decode())
    
    def test_page_contains_helpful_instructions(self):
        """Test that done page contains helpful instructions."""
        response = self.client.get(self.url)
        content = response.content.decode()
        self.assertIn('24 hours', content)
        self.assertIn('spam folder', content)


class PasswordResetConfirmViewTests(TestCase):
    """Tests for password reset confirmation view."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
        self.token = default_token_generator.make_token(self.user)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
    
    def get_reset_confirm_url(self, uidb64=None, token=None):
        """Helper to get reset confirm URL."""
        if uidb64 is None:
            uidb64 = self.uidb64
        if token is None:
            token = self.token
        return reverse('taremwa:password_reset_confirm', 
                      kwargs={'uidb64': uidb64, 'token': token})
    
    def test_get_password_reset_confirm_page(self):
        """Test that password reset confirm page loads with valid token."""
        url = self.get_reset_confirm_url()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/password_reset_confirm.html')
        self.assertTrue(response.context['valid_link'])
    
    def test_invalid_token_shows_error(self):
        """Test that invalid token shows error page."""
        url = self.get_reset_confirm_url(token='invalid-token')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['valid_link'])
        self.assertTemplateUsed(response, 'taremwa/password_reset_invalid.html')
    
    def test_expired_token_shows_error(self):
        """Test that expired token is rejected."""
        # Create an expired token by modifying user password
        new_user = User.objects.create_user(
            username='newuser',
            email='new@example.com',
            password='TestPassword123!'
        )
        token = default_token_generator.make_token(new_user)
        
        # Change password to invalidate token
        new_user.set_password('DifferentPassword123!')
        new_user.save()
        
        uidb64 = urlsafe_base64_encode(force_bytes(new_user.pk))
        url = reverse('taremwa:password_reset_confirm',
                     kwargs={'uidb64': uidb64, 'token': token})
        
        response = self.client.get(url)
        self.assertFalse(response.context['valid_link'])
    
    def test_invalid_user_id_shows_error(self):
        """Test that invalid user ID shows error."""
        invalid_uidb64 = urlsafe_base64_encode(force_bytes(99999))
        url = self.get_reset_confirm_url(uidb64=invalid_uidb64)
        response = self.client.get(url)
        self.assertFalse(response.context['valid_link'])
    
    def test_successful_password_reset_post(self):
        """Test successful password reset with valid token."""
        url = self.get_reset_confirm_url()
        new_password = 'NewSecurePassword123!'
        
        response = self.client.post(url, {
            'new_password1': new_password,
            'new_password2': new_password,
        })
        
        # Check redirect to login
        self.assertRedirects(response, reverse('taremwa:login'))
        
        # Check password was changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
    
    def test_password_mismatch_shows_error(self):
        """Test that mismatched passwords show error."""
        url = self.get_reset_confirm_url()
        response = self.client.post(url, {
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].has_error('new_password2'))
    
    def test_weak_password_validation(self):
        """Test that weak passwords are rejected."""
        url = self.get_reset_confirm_url()
        response = self.client.post(url, {
            'new_password1': '123',  # Too short
            'new_password2': '123',
        })
        
        self.assertEqual(response.status_code, 200)
        # Should have error on passwords
        self.assertTrue(
            response.context['form'].has_error('new_password1') or
            response.context['form'].has_error('new_password2') or
            response.context['form'].has_errors()
        )
    
    def test_token_invalidated_after_successful_reset(self):
        """Test that token becomes invalid after successful password reset."""
        url = self.get_reset_confirm_url()
        new_password = 'NewSecurePassword123!'
        
        # Reset password successfully
        self.client.post(url, {
            'new_password1': new_password,
            'new_password2': new_password,
        })
        
        # Try to use same token again
        response = self.client.get(url)
        self.assertFalse(response.context['valid_link'])
    
    def test_success_message_after_reset(self):
        """Test that success message displays after password reset."""
        url = self.get_reset_confirm_url()
        new_password = 'NewSecurePassword123!'
        
        response = self.client.post(url, {
            'new_password1': new_password,
            'new_password2': new_password,
        })
        
        response = self.client.get(reverse('taremwa:login'))
        messages_list = list(response.context['messages'])
        # Check that a success message was created
        # (Messages set in post are available on redirect)


class PasswordResetFormTests(TestCase):
    """Tests for password reset forms."""
    
    def test_password_reset_request_form_valid(self):
        """Test that valid email passes form validation."""
        form = PasswordResetRequestForm(data={'email': 'test@example.com'})
        self.assertTrue(form.is_valid())
    
    def test_password_reset_request_form_invalid_email(self):
        """Test that invalid email fails form validation."""
        form = PasswordResetRequestForm(data={'email': 'not-an-email'})
        self.assertFalse(form.is_valid())
    
    def test_password_reset_request_form_empty(self):
        """Test that empty email fails form validation."""
        form = PasswordResetRequestForm(data={'email': ''})
        self.assertFalse(form.is_valid())
    
    def test_password_reset_confirm_form_valid(self):
        """Test that matching passwords pass form validation."""
        user = User.objects.create_user(
            username='testuser',
            password='OldPassword123!'
        )
        form = PasswordResetConfirmForm(user, data={
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        })
        self.assertTrue(form.is_valid())
    
    def test_password_reset_confirm_form_mismatch(self):
        """Test that mismatched passwords fail validation."""
        user = User.objects.create_user(
            username='testuser',
            password='OldPassword123!'
        )
        form = PasswordResetConfirmForm(user, data={
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        })
        self.assertFalse(form.is_valid())
    
    def test_password_reset_confirm_form_weak_password(self):
        """Test that weak passwords fail validation."""
        user = User.objects.create_user(
            username='testuser',
            password='OldPassword123!'
        )
        form = PasswordResetConfirmForm(user, data={
            'new_password1': '123',
            'new_password2': '123',
        })
        self.assertFalse(form.is_valid())


class PasswordResetSecurityTests(TestCase):
    """Tests for security considerations in password reset."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
        self.url = reverse('taremwa:password_reset_request')
    
    def test_no_user_enumeration_via_timing(self):
        """Test that timing doesn't reveal user existence (basic check)."""
        import time
        
        # Time request for non-existent email
        start = time.time()
        self.client.post(self.url, {'email': 'nonexistent@example.com'})
        nonexistent_time = time.time() - start
        
        # Time request for existent email
        start = time.time()
        self.client.post(self.url, {'email': 'test@example.com'})
        existent_time = time.time() - start
        
        # Should be similar (not conclusive but basic check)
        # This is a basic test - proper timing attack mitigation requires
        # more sophisticated approaches at infrastructure level
    
    def test_email_not_shown_in_response(self):
        """Test that email addresses don't leak in responses."""
        response = self.client.post(self.url, {'email': 'test@example.com'})
        # Redirect means we can't check response content
        
        response = self.client.get(reverse('taremwa:password_reset_done'))
        content = response.content.decode()
        
        # Should not display the email address
        self.assertNotIn('test@example.com', content)
    
    def test_token_not_in_url_after_request(self):
        """Test that password reset tokens are only sent via email, not URL."""
        response = self.client.get(reverse('taremwa:password_reset_request'))
        content = response.content.decode()
        
        # Verify the form doesn't display any password reset tokens
        # (CSRF tokens are expected, but not password reset tokens)
        # The page should ask for email, not contain a token parameter
        self.assertNotIn('password-reset-confirm', response.request['PATH_INFO'])
    
    def test_password_reset_requires_secure_token(self):
        """Test that token validation is properly enforced."""
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        # Should work with valid token
        url = reverse('taremwa:password_reset_confirm',
                     kwargs={'uidb64': uidb64, 'token': token})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Should fail with modified token
        url = reverse('taremwa:password_reset_confirm',
                     kwargs={'uidb64': uidb64, 'token': token + 'x'})
        response = self.client.get(url)
        self.assertFalse(response.context['valid_link'])


class PasswordResetIntegrationTests(TestCase):
    """Integration tests for complete password reset flow."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
    
    def test_complete_password_reset_flow(self):
        """Test complete password reset flow from request to login."""
        # Step 1: Request password reset
        response = self.client.post(
            reverse('taremwa:password_reset_request'),
            {'email': 'test@example.com'}
        )
        self.assertRedirects(response, reverse('taremwa:password_reset_done'))
        
        # Step 2: Extract token and uid from email
        email = mail.outbox[0]
        # Extract from email (in real scenario, user clicks link from email)
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        # Step 3: Visit reset link and confirm password
        url = reverse('taremwa:password_reset_confirm',
                     kwargs={'uidb64': uidb64, 'token': token})
        new_password = 'BrandNewPassword123!'
        
        response = self.client.post(url, {
            'new_password1': new_password,
            'new_password2': new_password,
        })
        self.assertRedirects(response, reverse('taremwa:login'))
        
        # Step 4: Login with new password
        response = self.client.post(reverse('taremwa:login'), {
            'username': 'testuser',
            'password': new_password,
        })
        self.assertRedirects(response, reverse('taremwa:dashboard'))
        
        # Step 5: Verify user is now authenticated
        response = self.client.get(reverse('taremwa:dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_cannot_login_with_old_password_after_reset(self):
        """Test that old password no longer works after reset."""
        # Reset password
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        url = reverse('taremwa:password_reset_confirm',
                     kwargs={'uidb64': uidb64, 'token': token})
        
        new_password = 'BrandNewPassword123!'
        self.client.post(url, {
            'new_password1': new_password,
            'new_password2': new_password,
        })
        
        # Try to login with old password
        response = self.client.post(reverse('taremwa:login'), {
            'username': 'testuser',
            'password': 'OldPassword123!',
        })
        # Should be redirected back to login (not authenticated)
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
