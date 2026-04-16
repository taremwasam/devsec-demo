import shutil
from pathlib import Path

from django.contrib.auth.models import Group, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse


TEST_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde"
)
TEST_PDF_BYTES = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"


class SecureFileUploadTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_upload_dir = Path.cwd() / '.test_private_uploads'
        shutil.rmtree(cls._temp_upload_dir, ignore_errors=True)
        cls._temp_upload_dir.mkdir(exist_ok=True)
        cls._override = override_settings(PRIVATE_UPLOAD_ROOT=cls._temp_upload_dir)
        cls._override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        shutil.rmtree(cls._temp_upload_dir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='uploaduser',
            email='upload@example.com',
            password='SafePassword123!',
        )
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='SafePassword123!',
        )
        self.staff_user = User.objects.create_user(
            username='staffuser',
            email='staff@example.com',
            password='SafePassword123!',
            is_staff=True,
        )
        Group.objects.create(name='staff').user_set.add(self.staff_user)

    def _avatar(self, name='avatar.png', content=TEST_PNG_BYTES, content_type='image/png'):
        return SimpleUploadedFile(name, content, content_type=content_type)

    def _document(self, name='notes.pdf', content=TEST_PDF_BYTES, content_type='application/pdf'):
        return SimpleUploadedFile(name, content, content_type=content_type)

    def _profile_payload(self, **extra):
        payload = {
            'email': self.user.email,
            'first_name': '',
            'last_name': '',
            'bio': 'Secure bio',
        }
        payload.update(extra)
        return payload

    def test_profile_accepts_valid_avatar_and_document_uploads(self):
        self.client.login(username='uploaduser', password='SafePassword123!')

        response = self.client.post(
            reverse('taremwa:profile'),
            self._profile_payload(
                avatar=self._avatar(),
                document=self._document(),
            ),
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.taremwa_profile.avatar.name.startswith('avatars/'))
        self.assertTrue(self.user.taremwa_profile.document.name.startswith('documents/'))
        self.assertTrue(Path(self._temp_upload_dir, self.user.taremwa_profile.avatar.name).exists())
        self.assertTrue(Path(self._temp_upload_dir, self.user.taremwa_profile.document.name).exists())

    def test_profile_rejects_avatar_with_only_image_extension(self):
        self.client.login(username='uploaduser', password='SafePassword123!')

        response = self.client.post(
            reverse('taremwa:profile'),
            self._profile_payload(
                avatar=self._avatar(
                    name='avatar.png',
                    content=b'<script>alert(1)</script>',
                    content_type='image/png',
                ),
            ),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Avatar file contents do not match the allowed file type.')

    def test_profile_rejects_document_with_wrong_signature(self):
        self.client.login(username='uploaduser', password='SafePassword123!')

        response = self.client.post(
            reverse('taremwa:profile'),
            self._profile_payload(
                document=self._document(
                    name='report.pdf',
                    content=b'not really a pdf',
                    content_type='application/pdf',
                ),
            ),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Document file contents do not match the allowed file type.')

    def test_profile_rejects_oversized_document(self):
        self.client.login(username='uploaduser', password='SafePassword123!')

        response = self.client.post(
            reverse('taremwa:profile'),
            self._profile_payload(
                document=self._document(content=TEST_PDF_BYTES + (b'A' * (5 * 1024 * 1024))),
            ),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Document files must be 5 MB or smaller.')

    def test_uploaded_document_requires_authorized_access(self):
        self.user.taremwa_profile.document = self._document()
        self.user.taremwa_profile.save()

        self.client.login(username='otheruser', password='SafePassword123!')
        forbidden = self.client.get(
            reverse('taremwa:download_profile_upload', args=[self.user.id, 'document'])
        )
        self.assertEqual(forbidden.status_code, 403)

        self.client.logout()
        self.client.login(username='staffuser', password='SafePassword123!')
        allowed = self.client.get(
            reverse('taremwa:download_profile_upload', args=[self.user.id, 'document'])
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(allowed['Cache-Control'], 'private, no-store')
        self.assertIn('attachment;', allowed['Content-Disposition'])
