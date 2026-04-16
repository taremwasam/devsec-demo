from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.tokens import default_token_generator
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


class AuditLoggingViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='audituser',
            email='audit@example.com',
            password='OldPassword123!',
        )

    def test_registration_logs_without_passwords(self):
        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(reverse('taremwa:register'), {
                'username': 'newuser',
                'email': 'new@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password1': 'StrongPassword123!',
                'password2': 'StrongPassword123!',
            })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(any('event=auth.registration' in entry for entry in captured.output))
        self.assertFalse(any('StrongPassword123!' in entry for entry in captured.output))

    def test_login_success_logs_without_passwords(self):
        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(reverse('taremwa:login'), {
                'username': 'audituser',
                'password': 'OldPassword123!',
            })

        self.assertEqual(response.status_code, 302)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.login', joined)
        self.assertIn('outcome=success', joined)
        self.assertNotIn('OldPassword123!', joined)

    def test_login_failure_logs_attempt_without_passwords(self):
        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(reverse('taremwa:login'), {
                'username': 'audituser',
                'password': 'WrongPassword!',
            })

        self.assertEqual(response.status_code, 200)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.login', joined)
        self.assertIn('outcome=failure', joined)
        self.assertNotIn('WrongPassword!', joined)

    def test_logout_logs_authenticated_actor(self):
        self.client.login(username='audituser', password='OldPassword123!')

        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.get(reverse('taremwa:logout'))

        self.assertEqual(response.status_code, 302)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.logout', joined)
        self.assertIn(f'target_user_id={self.user.pk}', joined)

    def test_password_change_logs_success_without_new_password(self):
        self.client.login(username='audituser', password='OldPassword123!')

        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(reverse('taremwa:change_password'), {
                'old_password': 'OldPassword123!',
                'new_password1': 'BrandNewPassword123!',
                'new_password2': 'BrandNewPassword123!',
            })

        self.assertEqual(response.status_code, 302)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.password_change', joined)
        self.assertIn('outcome=success', joined)
        self.assertNotIn('BrandNewPassword123!', joined)

    def test_password_reset_request_logs_outcome_without_email_body(self):
        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(reverse('taremwa:password_reset_request'), {
                'email': 'audit@example.com',
            })

        self.assertEqual(response.status_code, 302)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.password_reset_request', joined)
        self.assertIn('outcome=account_found', joined)
        self.assertNotIn('audit@example.com', joined)

    def test_password_reset_confirm_logs_success(self):
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        with self.assertLogs('security.audit', level='INFO') as captured:
            response = self.client.post(
                reverse('taremwa:password_reset_confirm', args=[uidb64, token]),
                {
                    'new_password1': 'ResetPassword123!',
                    'new_password2': 'ResetPassword123!',
                },
            )

        self.assertEqual(response.status_code, 302)
        joined = '\n'.join(captured.output)
        self.assertIn('event=auth.password_reset_confirm', joined)
        self.assertIn('outcome=success', joined)
        self.assertNotIn('ResetPassword123!', joined)


class AuditLoggingPrivilegeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='targetuser',
            email='target@example.com',
            password='Password123!',
        )

    def test_group_membership_changes_are_logged(self):
        group = Group.objects.create(name='instructor')

        with self.assertLogs('security.audit', level='INFO') as captured:
            self.user.groups.add(group)

        joined = '\n'.join(captured.output)
        self.assertIn('event=privilege.groups_changed', joined)
        self.assertIn('groups=instructor', joined)

    def test_user_permission_changes_are_logged(self):
        permission = Permission.objects.get(codename='view_user')

        with self.assertLogs('security.audit', level='INFO') as captured:
            self.user.user_permissions.add(permission)

        joined = '\n'.join(captured.output)
        self.assertIn('event=privilege.permissions_changed', joined)
        self.assertIn('permissions=view_user', joined)

    def test_privilege_flag_changes_are_logged(self):
        with self.assertLogs('security.audit', level='INFO') as captured:
            self.user.is_staff = True
            self.user.save()

        joined = '\n'.join(captured.output)
        self.assertIn('event=privilege.flags_changed', joined)
        self.assertIn('changes=is_staff:False->True', joined)
