from __future__ import annotations

import importlib
import os
import sys
import unittest
from contextlib import contextmanager

from django.core.exceptions import ImproperlyConfigured


MODULE_NAME = 'devsec_demo.settings'


@contextmanager
def settings_env(**updates):
    original = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_settings_module():
    importlib.invalidate_caches()
    sys.modules.pop(MODULE_NAME, None)
    return importlib.import_module(MODULE_NAME)


class DjangoSecuritySettingsTests(unittest.TestCase):
    def test_debug_false_requires_secret_key(self) -> None:
        with settings_env(
            DJANGO_READ_DOTENV='False',
            DJANGO_DEBUG='False',
            DJANGO_SECRET_KEY=None,
            DJANGO_ALLOWED_HOSTS='example.com',
        ):
            with self.assertRaises(ImproperlyConfigured):
                load_settings_module()

    def test_debug_false_requires_allowed_hosts(self) -> None:
        with settings_env(
            DJANGO_READ_DOTENV='False',
            DJANGO_DEBUG='False',
            DJANGO_SECRET_KEY='production-secret-key',
            DJANGO_ALLOWED_HOSTS=None,
        ):
            with self.assertRaises(ImproperlyConfigured):
                load_settings_module()

    def test_debug_true_uses_local_defaults(self) -> None:
        with settings_env(
            DJANGO_READ_DOTENV='False',
            DJANGO_DEBUG='True',
            DJANGO_SECRET_KEY=None,
            DJANGO_ALLOWED_HOSTS=None,
        ):
            settings = load_settings_module()

        self.assertTrue(settings.DEBUG)
        self.assertEqual(settings.SECRET_KEY, settings.DEVELOPMENT_SECRET_KEY)
        self.assertEqual(settings.ALLOWED_HOSTS, settings.LOCALHOSTS)
        self.assertFalse(settings.SESSION_COOKIE_SECURE)
        self.assertFalse(settings.CSRF_COOKIE_SECURE)
        self.assertFalse(settings.SECURE_SSL_REDIRECT)
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 0)

    def test_production_defaults_enable_security_controls(self) -> None:
        with settings_env(
            DJANGO_READ_DOTENV='False',
            DJANGO_DEBUG='False',
            DJANGO_SECRET_KEY='production-secret-key',
            DJANGO_ALLOWED_HOSTS='example.com,.example.com',
            DJANGO_CSRF_TRUSTED_ORIGINS='https://example.com,https://admin.example.com',
        ):
            settings = load_settings_module()

        self.assertFalse(settings.DEBUG)
        self.assertEqual(settings.ALLOWED_HOSTS, ['example.com', '.example.com'])
        self.assertEqual(
            settings.CSRF_TRUSTED_ORIGINS,
            ['https://example.com', 'https://admin.example.com'],
        )
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)
        self.assertTrue(settings.SECURE_SSL_REDIRECT)
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')
        self.assertEqual(settings.SECURE_REFERRER_POLICY, 'strict-origin-when-cross-origin')
        self.assertEqual(settings.SECURE_CROSS_ORIGIN_OPENER_POLICY, 'same-origin')
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 31536000)
        self.assertTrue(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)

    def test_proxy_and_cookie_settings_can_be_overridden_explicitly(self) -> None:
        with settings_env(
            DJANGO_READ_DOTENV='False',
            DJANGO_DEBUG='False',
            DJANGO_SECRET_KEY='production-secret-key',
            DJANGO_ALLOWED_HOSTS='example.com',
            DJANGO_SESSION_COOKIE_SECURE='False',
            DJANGO_CSRF_COOKIE_SECURE='False',
            DJANGO_SECURE_SSL_REDIRECT='False',
            DJANGO_TRUST_X_FORWARDED_PROTO='True',
            DJANGO_USE_X_FORWARDED_HOST='True',
            DJANGO_SECURE_HSTS_SECONDS='86400',
            DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS='False',
            DJANGO_SECURE_HSTS_PRELOAD='True',
        ):
            settings = load_settings_module()

        self.assertFalse(settings.SESSION_COOKIE_SECURE)
        self.assertFalse(settings.CSRF_COOKIE_SECURE)
        self.assertFalse(settings.SECURE_SSL_REDIRECT)
        self.assertTrue(settings.USE_X_FORWARDED_HOST)
        self.assertEqual(settings.SECURE_PROXY_SSL_HEADER, ('HTTP_X_FORWARDED_PROTO', 'https'))
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 86400)
        self.assertFalse(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)
        self.assertTrue(settings.SECURE_HSTS_PRELOAD)


if __name__ == '__main__':
    unittest.main()
