from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from .models import UserProfile
from .forms import RegistrationForm, LoginForm, PasswordChangeForm, UserProfileForm


class UserRegistrationTest(TestCase):
    """Test user registration functionality"""

    def setUp(self):
        self.client = Client()
        self.register_url = reverse('taremwa:register')

    def test_register_page_loads(self):
        """Test that registration page loads"""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/register.html')

    def test_successful_registration(self):
        """Test successful user registration"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
            'first_name': 'Test',
            'last_name': 'User',
        }
        response = self.client.post(self.register_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.filter(username='testuser').exists())
        self.assertTrue(UserProfile.objects.filter(user__username='testuser').exists())

    def test_duplicate_username(self):
        """Test that duplicate usernames are rejected"""
        User.objects.create_user(username='testuser', email='test1@example.com', password='pass123')
        data = {
            'username': 'testuser',
            'email': 'test2@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('username', response.context['form'].errors)
        self.assertIn('already taken', str(response.context['form'].errors['username']))

    def test_duplicate_email(self):
        """Test that duplicate emails are rejected"""
        User.objects.create_user(username='testuser1', email='test@example.com', password='pass123')
        data = {
            'username': 'testuser2',
            'email': 'test@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('email', response.context['form'].errors)
        self.assertIn('already registered', str(response.context['form'].errors['email']))

    def test_password_mismatch(self):
        """Test that mismatched passwords are rejected"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='testuser').exists())


class UserLoginTest(TestCase):
    """Test user login functionality"""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse('taremwa:login')
        self.dashboard_url = reverse('taremwa:dashboard')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_login_page_loads(self):
        """Test that login page loads"""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/login.html')

    def test_successful_login(self):
        """Test successful user login"""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!'
        }
        response = self.client.post(self.login_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)


class ProtectedAreaTest(TestCase):
    """Test protected authenticated areas"""

    def setUp(self):
        self.client = Client()
        self.dashboard_url = reverse('taremwa:dashboard')
        self.profile_url = reverse('taremwa:profile')
        self.change_password_url = reverse('taremwa:change_password')
        self.login_url = reverse('taremwa:login')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_dashboard_requires_login(self):
        """Test that dashboard requires authentication"""
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)

    def test_profile_requires_login(self):
        """Test that profile requires authentication"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)

    def test_authenticated_dashboard_access(self):
        """Test accessing dashboard when authenticated"""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/dashboard.html')

    def test_authenticated_profile_access(self):
        """Test accessing profile when authenticated"""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/profile.html')


class PasswordChangeTest(TestCase):
    """Test password change functionality"""

    def setUp(self):
        self.client = Client()
        self.change_password_url = reverse('taremwa:change_password')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
        self.client.login(username='testuser', password='OldPassword123!')

    def test_change_password_requires_login(self):
        """Test that password change requires authentication"""
        self.client.logout()
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, 302)

    def test_successful_password_change(self):
        """Test successful password change"""
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.change_password_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        # Refresh user from database
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPassword123!'))

    def test_wrong_old_password(self):
        """Test password change with wrong old password"""
        data = {
            'old_password': 'WrongPassword',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.change_password_url, data)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('OldPassword123!'))

    def test_new_passwords_mismatch(self):
        """Test password change with mismatched new passwords"""
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.change_password_url, data)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('OldPassword123!'))


class UserLogoutTest(TestCase):
    """Test user logout functionality"""

    def setUp(self):
        self.client = Client()
        self.logout_url = reverse('taremwa:logout')
        self.login_url = reverse('taremwa:login')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_successful_logout(self):
        """Test successful logout"""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.logout_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)


class UserProfileModelTest(TestCase):
    """Test UserProfile model"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_profile_created_on_user_save(self):
        """Test that profile is created when user is saved"""
        # Profile should be created by signal
        self.assertTrue(UserProfile.objects.filter(user=self.user).exists())

    def test_profile_string_representation(self):
        """Test profile string representation"""
        profile = self.user.taremwa_profile
        self.assertEqual(str(profile), f"Profile of {self.user.username}")

    def test_profile_update_timestamps(self):
        """Test that profile timestamps are updated"""
        profile = self.user.taremwa_profile
        profile.bio = 'Original bio'
        profile.save()
        created_at = profile.created_at
        profile.bio = 'Updated bio'
        profile.save()
        profile.refresh_from_db()
        self.assertEqual(profile.created_at, created_at)
        self.assertEqual(profile.bio, 'Updated bio')
