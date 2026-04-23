Production-Grade Django Security Settings Design Note

This note explains the deployment-oriented hardening applied in `devsec_demo/settings.py`.

Threat model

- Development defaults like `DEBUG=True` or empty host validation are unsafe in production.
- Weak environment handling can accidentally boot a production-style deployment with a missing secret key or missing host restrictions.
- Missing secure-cookie and transport settings can expose authenticated sessions to downgrade or interception risks.
- Deployment settings should be explicit and readable so reviewers can see what assumptions the app makes.

Chosen controls

1. Explicit environment parsing

- Added small helpers to parse booleans and comma-separated lists from environment variables.
- This avoids hidden truthiness bugs and keeps deployment configuration readable.
- Dotenv loading is now explicit and can be disabled with `DJANGO_READ_DOTENV=False` for production environments that supply configuration directly.

2. Safe defaults for development and strict requirements for production

- `DJANGO_DEBUG` now controls debug mode instead of a hard-coded development default.
- If debug is disabled, the app now requires both `DJANGO_SECRET_KEY` and `DJANGO_ALLOWED_HOSTS`.
- In debug mode only, the app falls back to a development-only secret key and localhost hosts so the project remains easy to run locally.

3. Cookie hardening

- Session cookies are `HttpOnly` and `SameSite=Lax`.
- CSRF cookies are `HttpOnly` and `SameSite=Lax`.
- Both session and CSRF cookies default to `Secure` when debug is off.

4. Browser and response hardening

- Enabled `SECURE_CONTENT_TYPE_NOSNIFF`.
- Set `X_FRAME_OPTIONS = 'DENY'`.
- Set `SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'`.
- Set `SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'`.

5. HTTPS and proxy awareness

- `SECURE_SSL_REDIRECT` defaults to enabled when debug is off.
- HSTS defaults are enabled in production-style mode with a one-year max age.
- Proxy settings are explicit through environment flags instead of being silently assumed.

Validation

- Added tests that verify production mode refuses to start without a secret key.
- Added tests that verify production mode refuses to start without allowed hosts.
- Added tests that verify local development defaults still work in debug mode.
- Added tests that verify secure cookie, HTTPS, HSTS, and proxy settings behave as expected.
