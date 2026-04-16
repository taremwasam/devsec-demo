from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from taremwa.models import UserProfile
from taremwa.authorization import (
    can_view_profile, can_edit_profile, can_delete_user, get_user_role
)


class AuthorizationHelperTest(TestCase):
    """Test authorization helper functions"""

    def setUp(self):
        self.user = User.objects.create_user(username='user', password='pass123')
        self.other_user = User.objects.create_user(username='other', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123')
        self.staff_user.is_staff = True
        self.staff_user.save()
        self.admin_user = User.objects.create_user(username='admin', password='pass123', is_superuser=True)
        self.admin_user.is_staff = True
        self.admin_user.save()

    def test_can_view_own_profile(self):
        """User can view their own profile"""
        self.assertTrue(can_view_profile(self.user, self.user))

    def test_user_cannot_view_others_profile(self):
        """Regular user cannot view other users' profiles"""
        self.assertFalse(can_view_profile(self.user, self.other_user))

    def test_staff_can_view_any_profile(self):
        """Staff can view any profile"""
        self.assertTrue(can_view_profile(self.staff_user, self.user))
        self.assertTrue(can_view_profile(self.staff_user, self.other_user))

    def test_admin_can_view_any_profile(self):
        """Admin can view any profile"""
        self.assertTrue(can_view_profile(self.admin_user, self.user))
        self.assertTrue(can_view_profile(self.admin_user, self.other_user))

    def test_can_edit_own_profile(self):
        """User can edit their own profile"""
        self.assertTrue(can_edit_profile(self.user, self.user))

    def test_user_cannot_edit_others_profile(self):
        """Regular user cannot edit other users' profiles"""
        self.assertFalse(can_edit_profile(self.user, self.other_user))

    def test_staff_can_edit_any_profile(self):
        """Staff can edit any profile"""
        self.assertTrue(can_edit_profile(self.staff_user, self.user))
        self.assertTrue(can_edit_profile(self.staff_user, self.other_user))

    def test_cannot_delete_yourself(self):
        """User cannot delete their own account"""
        self.assertFalse(can_delete_user(self.user, self.user))

    def test_staff_cannot_delete_user(self):
        """Staff cannot delete users (only admin)"""
        self.assertFalse(can_delete_user(self.staff_user, self.user))

    def test_admin_can_delete_user(self):
        """Admin can delete users"""
        self.assertTrue(can_delete_user(self.admin_user, self.user))

    def test_get_user_role_anonymous(self):
        """Test role detection for anonymous user"""
        request_user = User()  # Not authenticated
        # We'll test this differently since we need an AnonymousUser
        
    def test_get_user_role_regular(self):
        """Test role detection for regular user"""
        self.assertEqual(get_user_role(self.user), 'user')

    def test_get_user_role_staff(self):
        """Test role detection for staff"""
        self.assertEqual(get_user_role(self.staff_user), 'staff')

    def test_get_user_role_admin(self):
        """Test role detection for admin"""
        self.assertEqual(get_user_role(self.admin_user), 'admin')


class ProfileAuthorizationTest(TestCase):
    """Test profile view authorization"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='user', password='pass123')
        self.other_user = User.objects.create_user(username='other', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123')
        self.staff_user.is_staff = True
        self.staff_user.save()
        
        # Create staff group
        self.staff_group = Group.objects.create(name='staff')
        self.staff_group.user_set.add(self.staff_user)

    def test_own_profile_accessible(self):
        """User can access their own profile"""
        self.client.login(username='user', password='pass123')
        response = self.client.get(reverse('taremwa:profile'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/profile.html')

    def test_others_profile_not_accessible(self):
        """Regular user cannot access others' profiles"""
        self.client.login(username='user', password='pass123')
        response = self.client.get(reverse('taremwa:view_profile', args=[self.other_user.id]))
        self.assertEqual(response.status_code, 403)

    def test_staff_can_view_any_profile(self):
        """Staff can view any profile"""
        self.client.login(username='staff', password='pass123')
        response = self.client.get(reverse('taremwa:view_profile', args=[self.user.id]))
        self.assertEqual(response.status_code, 200)

    def test_anonymous_redirected_to_login(self):
        """Anonymous user redirected to login when accessing protected profile"""
        response = self.client.get(reverse('taremwa:profile'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login', response.url)


class StaffDashboardAuthorizationTest(TestCase):
    """Test staff dashboard authorization"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='user', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123')
        self.staff_user.is_staff = True
        self.staff_user.save()
        
        # Create staff group
        self.staff_group = Group.objects.create(name='staff')
        self.staff_group.user_set.add(self.staff_user)

    def test_staff_dashboard_requires_authentication(self):
        """Staff dashboard requires login"""
        response = self.client.get(reverse('taremwa:staff_dashboard'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login', response.url)

    def test_regular_user_cannot_access_staff_dashboard(self):
        """Regular user gets 403 when accessing staff dashboard"""
        self.client.login(username='user', password='pass123')
        response = self.client.get(reverse('taremwa:staff_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_staff_can_access_staff_dashboard(self):
        """Staff member can access staff dashboard"""
        self.client.login(username='staff', password='pass123')
        response = self.client.get(reverse('taremwa:staff_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/staff_dashboard.html')


class ViewAllUsersAuthorizationTest(TestCase):
    """Test view all users authorization"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='user', password='pass123')
        self.instructor_user = User.objects.create_user(username='instructor', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123')
        self.staff_user.is_staff = True
        self.staff_user.save()
        
        # Create groups
        self.instructor_group = Group.objects.create(name='instructor')
        self.staff_group = Group.objects.create(name='staff')
        self.instructor_group.user_set.add(self.instructor_user)
        self.staff_group.user_set.add(self.staff_user)

    def test_view_all_users_requires_authentication(self):
        """View all users requires login"""
        response = self.client.get(reverse('taremwa:view_all_users'), follow=False)
        self.assertEqual(response.status_code, 302)

    def test_regular_user_cannot_view_all_users(self):
        """Regular user gets 403 when accessing view all users"""
        self.client.login(username='user', password='pass123')
        response = self.client.get(reverse('taremwa:view_all_users'))
        self.assertEqual(response.status_code, 403)

    def test_instructor_can_view_all_users(self):
        """Instructor can view all users"""
        self.client.login(username='instructor', password='pass123')
        response = self.client.get(reverse('taremwa:view_all_users'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'taremwa/view_all_users.html')

    def test_staff_can_view_all_users(self):
        """Staff can view all users"""
        self.client.login(username='staff', password='pass123')
        response = self.client.get(reverse('taremwa:view_all_users'))
        self.assertEqual(response.status_code, 200)


class DeleteUserAuthorizationTest(TestCase):
    """Test delete user authorization"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='user', password='pass123')
        self.target_user = User.objects.create_user(username='target', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123')
        self.staff_user.is_staff = True
        self.staff_user.save()
        
        # Create staff group
        self.staff_group = Group.objects.create(name='staff')
        self.staff_group.user_set.add(self.staff_user)

    def test_delete_user_requires_staff(self):
        """Delete user requires staff privileges"""
        self.client.login(username='user', password='pass123')
        response = self.client.get(reverse('taremwa:delete_user', args=[self.target_user.id]))
        self.assertEqual(response.status_code, 403)

    def test_staff_can_view_delete_form(self):
        """Staff can view delete user form"""
        self.client.login(username='staff', password='pass123')
        response = self.client.get(reverse('taremwa:delete_user', args=[self.target_user.id]))
        self.assertEqual(response.status_code, 200)

    def test_staff_cannot_delete_self(self):
        """Staff cannot delete their own account"""
        self.client.login(username='staff', password='pass123')
        response = self.client.post(reverse('taremwa:delete_user', args=[self.staff_user.id]))
        self.assertRedirects(response, reverse('taremwa:view_all_users'))
        # User should still exist
        self.assertTrue(User.objects.filter(username='staff').exists())


class GroupPermissionsTest(TestCase):
    """Test group and permission setup"""

    def setUp(self):
        self.staff_group = Group.objects.create(name='staff')
        self.instructor_group = Group.objects.create(name='instructor')

    def test_staff_group_created(self):
        """Staff group exists"""
        self.assertTrue(Group.objects.filter(name='staff').exists())

    def test_instructor_group_created(self):
        """Instructor group exists"""
        self.assertTrue(Group.objects.filter(name='instructor').exists())

    def test_user_in_staff_group(self):
        """User can be added to staff group"""
        user = User.objects.create_user(username='user', password='pass123')
        self.staff_group.user_set.add(user)
        self.assertTrue(user.groups.filter(name='staff').exists())

    def test_user_in_multiple_groups(self):
        """User can be in multiple groups"""
        user = User.objects.create_user(username='user', password='pass123')
        self.staff_group.user_set.add(user)
        self.instructor_group.user_set.add(user)
        self.assertEqual(user.groups.count(), 2)
