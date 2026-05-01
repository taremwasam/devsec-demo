from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from .forms import UserProfileForm


class StoredXssProfileContentTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='xssuser',
            email='xss@example.com',
            password='SafePassword123!',
            first_name='Xss',
        )
        self.client.login(username='xssuser', password='SafePassword123!')

    def test_profile_form_strips_html_tags_from_bio(self):
        form = UserProfileForm(
            data={
                'email': self.user.email,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'bio': '<script>alert("owned")</script>Hello <b>friend</b>',
            },
            instance=self.user.taremwa_profile,
        )

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['bio'], 'alert("owned")Hello friend')

    def test_dashboard_renders_bio_as_inert_text(self):
        payload = '<script>alert("owned")</script>Hello\n<img src=x onerror=alert(1)>World'

        response = self.client.post(
            reverse('taremwa:profile'),
            {
                'email': self.user.email,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'bio': payload,
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.taremwa_profile.bio, 'alert("owned")Hello\nWorld')

        dashboard = self.client.get(reverse('taremwa:dashboard'))
        content = dashboard.content.decode()

        self.assertNotIn('<script>', content)
        self.assertNotIn('<img', content)
        self.assertIn('alert(&quot;owned&quot;)Hello<br>World', content)

    def test_legitimate_plain_text_bio_keeps_line_breaks(self):
        response = self.client.post(
            reverse('taremwa:profile'),
            {
                'email': self.user.email,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'bio': 'Line one\nLine two',
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        dashboard = self.client.get(reverse('taremwa:dashboard'))
        self.assertContains(dashboard, 'Line one<br>Line two', html=True)
