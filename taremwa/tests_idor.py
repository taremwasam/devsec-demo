"""
IDOR (Insecure Direct Object Reference) Prevention Tests

This test suite validates that the application prevents users from accessing
or modifying resources they don't own by manipulating URLs or identifiers.

Each test attempts common IDOR attacks and verifies they are blocked.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from .models import UserProfile


class IDORViewAccessTests(TestCase):
    """
    Test that users cannot access other users' data via IDOR attacks.
    Common IDOR attack: Change URL parameter to access another user's data.
    """
    
    def setUp(self):
        """Create test users with different roles"""
        # Regular users
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        
        # Staff user
        self.staff_user = User.objects.create_user(username='staff', password='pass123', is_staff=True)
        
        # Instructor user
        self.instructor_user = User.objects.create_user(username='instructor', password='pass123')
        instructor_group = Group.objects.create(name='instructor')
        self.instructor_user.groups.add(instructor_group)
        
        # Admin user
        self.admin_user = User.objects.create_user(
            username='admin', password='pass123', is_staff=True, is_superuser=True
        )
        
        # Update profiles for all users (signals create them automatically)
        for user in [self.user1, self.user2, self.staff_user, self.instructor_user, self.admin_user]:
            profile = user.taremwa_profile
            profile.bio = f'Bio of {user.username}'
            profile.save()
        
        self.client = Client()
    
    def test_regular_user_cannot_view_other_profile_via_id(self):
        """
        IDOR Attack: User1 tries to view User2's profile by changing URL ID
        Expected: Access denied (403)
        """
        self.client.login(username='user1', password='pass123')
        
        # Try to access user2's profile directly
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user2.id})
        response = self.client.get(url)
        
        # Should be 403 Forbidden or redirect
        self.assertIn(response.status_code, [403, 302])
        self.assertNotIn('User2 Bio', str(response.content))
    
    def test_regular_user_can_view_own_profile_by_id(self):
        """
        Valid access: User can view their own profile even with user_id
        Expected: Access allowed (200)
        """
        self.client.login(username='user1', password='pass123')
        
        # Access own profile with ID
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.get(url)
        
        # Should be accessible
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user1.username, str(response.content))
    
    def test_staff_cannot_view_profile_of_nonexistent_user(self):
        """
        IDOR Attack: Try to access profile of user ID that doesn't exist
        Expected: Access denied (gracefully)
        Prevents information leakage that user doesn't exist
        """
        self.client.login(username='staff', password='pass123')
        
        # Try to access nonexistent user
        fake_user_id = 99999
        url = reverse('taremwa:view_profile', kwargs={'user_id': fake_user_id})
        response = self.client.get(url)
        
        # Should return 404 or similar
        self.assertIn(response.status_code, [403, 404])
    
    def test_staff_can_view_any_profile(self):
        """
        Valid access: Staff can view any user's profile
        Expected: Access allowed (200)
        """
        self.client.login(username='staff', password='pass123')
        
        # Staff should be able to view user1's profile
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user1.username, str(response.content))
    
    def test_instructor_can_view_any_profile(self):
        """
        Valid access: Instructor can view any user's profile (read-only)
        Expected: Access allowed (200)
        """
        self.client.login(username='instructor', password='pass123')
        
        # Instructor should be able to view user1's profile
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user1.username, str(response.content))
    
    def test_anonymous_cannot_view_any_profile(self):
        """
        IDOR Attack: Anonymous user tries to view profiles
        Expected: Redirected to login
        """
        # Not logged in
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.get(url, follow=False)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)


class IDORProfileEditingTests(TestCase):
    """
    Test that users cannot edit other users' profiles via IDOR attacks.
    """
    
    def setUp(self):
        """Create test users"""
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        self.staff_user = User.objects.create_user(username='staff', password='pass123', is_staff=True)
        
        # Update profiles (created automatically by signals)
        self.user1.taremwa_profile.bio = 'User1 Bio'
        self.user1.taremwa_profile.save()
        
        self.user2.taremwa_profile.bio = 'User2 Bio'
        self.user2.taremwa_profile.save()
        
        self.staff_user.taremwa_profile.bio = 'Staff Bio'
        self.staff_user.taremwa_profile.save()
        
        self.client = Client()
    
    def test_user_cannot_edit_other_profile_via_POST(self):
        """
        IDOR Attack: User1 sends POST to edit User2's profile
        Expected: Edit fails, User2's profile unchanged
        """
        self.client.login(username='user1', password='pass123')
        
        # Try to submit form editing user2's profile
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user2.id})
        response = self.client.post(url, {
            'bio': 'Hacked by user1!'
        })
        
        # Request should fail (403)
        self.assertIn(response.status_code, [403, 302])
        
        # User2's profile should not be changed
        user2_profile = UserProfile.objects.get(user=self.user2)
        self.assertEqual(user2_profile.bio, 'User2 Bio')
    
    def test_user_can_edit_own_profile_by_id(self):
        """
        Valid edit: User can edit their own profile with user_id
        Expected: Edit succeeds
        """
        self.client.login(username='user1', password='pass123')
        
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.post(url, {
            'bio': 'Updated bio'
        }, follow=True)
        
        # Should succeed
        self.assertEqual(response.status_code, 200)
        
        # Profile should be updated
        user1_profile = UserProfile.objects.get(user=self.user1)
        self.assertEqual(user1_profile.bio, 'Updated bio')
    
    def test_staff_can_edit_any_profile(self):
        """
        Valid edit: Staff can edit any user's profile
        Expected: Edit succeeds
        """
        self.client.login(username='staff', password='pass123')
        
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user1.id})
        response = self.client.post(url, {
            'bio': 'Edited by staff'
        }, follow=True)
        
        # Should succeed
        self.assertEqual(response.status_code, 200)
        
        # Profile should be updated
        user1_profile = UserProfile.objects.get(user=self.user1)
        self.assertEqual(user1_profile.bio, 'Edited by staff')
    
    def test_user_cannot_edit_profile_directly_without_id(self):
        """
        Verify: Profile endpoint without ID protects against IDOR
        Only your own profile is accessible
        """
        self.client.login(username='user1', password='pass123')
        
        # Access own profile (no user_id)
        url = reverse('taremwa:profile')
        response = self.client.get(url)
        
        # Should show own profile
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user1.username, str(response.content))


class IDORUserDeletionTests(TestCase):
    """
    Test that users cannot delete other users via IDOR attacks.
    Also test granular deletion permissions (staff cannot delete staff, etc.)
    """
    
    def setUp(self):
        """Create test users with different roles"""
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        
        # Staff users
        self.staff1 = User.objects.create_user(username='staff1', password='pass123', is_staff=True)
        self.staff2 = User.objects.create_user(username='staff2', password='pass123', is_staff=True)
        
        # Admin
        self.admin = User.objects.create_user(
            username='admin', password='pass123', is_staff=True, is_superuser=True
        )
        
        # Profiles automatically created by signals, no need to manually create
        self.client = Client()
    
    def test_regular_user_cannot_delete_any_user(self):
        """
        IDOR Attack: Regular user tries to delete another user
        Expected: Access denied
        """
        self.client.login(username='user1', password='pass123')
        
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.user2.id})
        response = self.client.get(url)
        
        # Should be 403 Forbidden
        self.assertEqual(response.status_code, 403)
        
        # User should still exist
        self.assertTrue(User.objects.filter(username='user2').exists())
    
    def test_staff_can_delete_regular_user(self):
        """
        Valid deletion: Staff can delete regular users
        Expected: Deletion succeeds
        """
        self.client.login(username='staff1', password='pass123')
        
        # GET the confirmation page
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.user1.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # POST to confirm deletion
        response = self.client.post(url, follow=True)
        
        # User should be deleted
        self.assertFalse(User.objects.filter(username='user1').exists())
    
    def test_staff_cannot_delete_other_staff(self):
        """
        IDOR Attack: Staff1 tries to delete Staff2
        Expected: Deletion denied (CRITICAL IDOR PREVENTION)
        """
        self.client.login(username='staff1', password='pass123')
        
        # Try to access deletion page for another staff member
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.staff2.id})
        response = self.client.get(url)
        
        # Should be 403 Forbidden
        self.assertEqual(response.status_code, 403)
        
        # Staff2 should still exist
        self.assertTrue(User.objects.filter(username='staff2').exists())
    
    def test_staff_cannot_delete_admin(self):
        """
        IDOR Attack: Staff tries to delete Admin
        Expected: Deletion denied
        """
        self.client.login(username='staff1', password='pass123')
        
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.admin.id})
        response = self.client.get(url)
        
        # Should be 403 Forbidden
        self.assertEqual(response.status_code, 403)
        
        # Admin should still exist
        self.assertTrue(User.objects.filter(username='admin').exists())
    
    def test_staff_cannot_delete_themselves(self):
        """
        IDOR Attack: Staff tries to delete their own account
        Expected: Deletion denied
        """
        self.client.login(username='staff1', password='pass123')
        
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.staff1.id})
        response = self.client.get(url)
        
        # Should be 403 or error
        self.assertIn(response.status_code, [403, 302])
        
        # Staff1 should still exist
        self.assertTrue(User.objects.filter(username='staff1').exists())
    
    def test_admin_can_delete_staff(self):
        """
        Valid deletion: Admin can delete staff members
        Expected: Deletion succeeds
        """
        self.client.login(username='admin', password='pass123')
        
        url = reverse('taremwa:delete_user', kwargs={'user_id': self.staff1.id})
        response = self.client.post(url, follow=True)
        
        # Staff should be deleted
        self.assertFalse(User.objects.filter(username='staff1').exists())
    
    def test_admin_can_delete_other_admin(self):
        """
        Valid deletion: Admin can delete other admins
        Expected: Deletion succeeds
        """
        # Create another admin
        admin2 = User.objects.create_user(
            username='admin2', password='pass123', is_staff=True, is_superuser=True
        )
        # Profile created automatically by signals
        
        self.client.login(username='admin', password='pass123')
        
        url = reverse('taremwa:delete_user', kwargs={'user_id': admin2.id})
        response = self.client.post(url, follow=True)
        
        # Admin2 should be deleted
        self.assertFalse(User.objects.filter(username='admin2').exists())


class IDORAuthorizationFunctionTests(TestCase):
    """
    Test the object-level IDOR prevention functions directly.
    """
    
    def setUp(self):
        """Create test users"""
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        self.staff = User.objects.create_user(username='staff', password='pass123', is_staff=True)
        self.admin = User.objects.create_user(
            username='admin', password='pass123', is_staff=True, is_superuser=True
        )
        
        # Profiles automatically created by signals
    
    def test_get_viewable_user_allows_own_access(self):
        """Test get_viewable_user allows users to view own profile"""
        from .authorization import get_viewable_user
        
        result = get_viewable_user(self.user1, self.user1.id)
        self.assertEqual(result, self.user1)
    
    def test_get_viewable_user_denies_unauthorized_access(self):
        """Test get_viewable_user denies regular user viewing other user"""
        from .authorization import get_viewable_user
        
        result = get_viewable_user(self.user1, self.user2.id)
        self.assertIsNone(result)
    
    def test_get_viewable_user_allows_staff_access(self):
        """Test get_viewable_user allows staff to view any user"""
        from .authorization import get_viewable_user
        
        result = get_viewable_user(self.staff, self.user1.id)
        self.assertEqual(result, self.user1)
    
    def test_get_editable_user_denies_unauthorized_access(self):
        """Test get_editable_user denies editing other user's profile"""
        from .authorization import get_editable_user
        
        result = get_editable_user(self.user1, self.user2.id)
        self.assertIsNone(result)
    
    def test_get_editable_user_allows_own_access(self):
        """Test get_editable_user allows editing own profile"""
        from .authorization import get_editable_user
        
        result = get_editable_user(self.user1, self.user1.id)
        self.assertEqual(result, self.user1)
    
    def test_get_deletable_user_denies_regular_user(self):
        """Test get_deletable_user denies regular users from deleting"""
        from .authorization import get_deletable_user
        
        result = get_deletable_user(self.user1, self.user2.id)
        self.assertIsNone(result)
    
    def test_get_deletable_user_denies_self_deletion(self):
        """Test get_deletable_user prevents self-deletion"""
        from .authorization import get_deletable_user
        
        result = get_deletable_user(self.admin, self.admin.id)
        self.assertIsNone(result)
    
    def test_get_deletable_user_staff_cannot_delete_staff(self):
        """Test staff cannot delete other staff members"""
        from .authorization import get_deletable_user
        
        result = get_deletable_user(self.staff, self.admin.id)
        self.assertIsNone(result)
    
    def test_get_deletable_user_staff_can_delete_regular_user(self):
        """Test staff can delete regular users"""
        from .authorization import get_deletable_user
        
        result = get_deletable_user(self.staff, self.user1.id)
        self.assertEqual(result, self.user1)
    
    def test_get_deletable_user_admin_can_delete_anyone(self):
        """Test admin can delete any user"""
        from .authorization import get_deletable_user
        
        result = get_deletable_user(self.admin, self.staff.id)
        self.assertEqual(result, self.staff)


class IDORURLManipulationTests(TestCase):
    """
    Test various URL manipulation IDOR attacks.
    """
    
    def setUp(self):
        """Create test users"""
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        
        # Update profiles (created automatically by signals)
        self.user1.taremwa_profile.bio = 'User1 Bio'
        self.user1.taremwa_profile.save()
        
        self.user2.taremwa_profile.bio = 'User2 Bio'
        self.user2.taremwa_profile.save()
        
        self.client = Client()
    
    def test_sequential_id_enumeration_attack(self):
        """
        IDOR Attack: Try sequential user IDs to enumerate users
        Expected: Unauthorized access denied even with valid IDs
        """
        self.client.login(username='user1', password='pass123')
        
        # Try to access user2 (sequential ID)
        url = reverse('taremwa:view_profile', kwargs={'user_id': self.user2.id})
        response = self.client.get(url)
        
        # Should fail
        self.assertIn(response.status_code, [403, 302])
    
    def test_negative_id_idor_attack(self):
        """
        IDOR Attack: Try negative ID
        Expected: Graceful handling
        """
        self.client.login(username='user1', password='pass123')
        
        # Negative IDs should not exist
        url = reverse('taremwa:view_profile', kwargs={'user_id': -1})
        response = self.client.get(url)
        
        # Should return 404 or similar
        self.assertIn(response.status_code, [403, 404])
    
    def test_zero_id_idor_attack(self):
        """
        IDOR Attack: Try zero ID
        Expected: Graceful handling
        """
        self.client.login(username='user1', password='pass123')
        
        url = reverse('taremwa:view_profile', kwargs={'user_id': 0})
        response = self.client.get(url)
        
        # Should return 404 or similar
        self.assertIn(response.status_code, [403, 404])


class IDORPrivilegeEscalationTests(TestCase):
    """
    Test IDOR attacks combined with privilege escalation attempts.
    """
    
    def setUp(self):
        """Create test users"""
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        self.staff = User.objects.create_user(username='staff', password='pass123', is_staff=True)
        
        # Profiles automatically created by signals
        self.client = Client()
    
    def test_cannot_escalate_via_profile_editing(self):
        """
        Privilege Escalation Attack: User tries to edit admin flag via profile
        Expected: Form doesn't include admin fields (even if user tries to modify)
        """
        self.client.login(username='user1', password='pass123')
        
        # Try to submit profile form with is_staff flag
        url = reverse('taremwa:profile')
        response = self.client.post(url, {
            'bio': 'Updated',
            'is_staff': 'True',  # Shouldn't be in form
        }, follow=True)
        
        # User1 should still not be staff
        user1_refreshed = User.objects.get(username='user1')
        self.assertFalse(user1_refreshed.is_staff)
