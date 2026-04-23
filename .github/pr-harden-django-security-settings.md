## Assignment Summary
- Hardened the Django settings module for production-style deployment by replacing development defaults with explicit environment parsing, stricter production requirements, and safer cookie, host, and transport settings.

## Related Issue
- Closes #42

## Target Assignment Branch
- `assignment/harden-django-security-settings`

## Design Note
- I kept the hardening inside `devsec_demo/settings.py` so the project remains easy to audit and explain. The goal was to keep local development simple while making production assumptions explicit: debug mode must be opt-in, production requires a secret key and allowed hosts, and security-sensitive settings default to safer values when debug is off.

## Security Impact
- Prevents production-style startup with missing `SECRET_KEY` or missing host restrictions.
- Removes the unsafe hard-coded debug assumption by parsing `DJANGO_DEBUG` explicitly.
- Hardens session and CSRF cookies with `HttpOnly`, `SameSite`, and production-default `Secure` behavior.
- Enables safer browser and transport headers such as `nosniff`, frame denial, stricter referrer policy, SSL redirect, and HSTS.
- Makes dotenv loading explicit so production environments can disable local `.env` loading and rely only on managed environment variables.

## Changes Made
- Added explicit boolean and list parsing helpers for environment-driven settings.
- Changed `DJANGO_DEBUG` handling from implicit/stringy behavior to explicit boolean parsing.
- Required `DJANGO_SECRET_KEY` and `DJANGO_ALLOWED_HOSTS` when debug is disabled.
- Added localhost development fallbacks only for debug mode.
- Added `CSRF_TRUSTED_ORIGINS` parsing from environment variables.
- Enabled secure defaults for session and CSRF cookie settings.
- Enabled `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS`, `SECURE_REFERRER_POLICY`, and `SECURE_CROSS_ORIGIN_OPENER_POLICY`.
- Added production-style defaults for `SECURE_SSL_REDIRECT` and HSTS, with explicit proxy-related environment flags.
- Made dotenv loading controllable with `DJANGO_READ_DOTENV`.
- Added focused tests for development and production configuration behavior.
- Added a short design note in `SECURITY_DESIGN_DJANGO_SETTINGS.md`.

## Validation
- Ran `python -m unittest tests.test_security_settings`
- Ran `python manage.py check`
- Result: both passed locally after the settings hardening.

## AI Assistance Used
- Yes. I used Codex for repository analysis, implementation support, test creation, validation, and drafting the PR summary.

## What AI Helped With
- Reviewing the existing settings module against the task requirements.
- Structuring explicit environment parsing and production-safe setting defaults.
- Drafting focused tests that verify the intended development and production behavior.
- Preparing the PR body and design note.

## What I Changed From AI Output
- Kept the final configuration aligned with this repository’s actual bootstrap flow instead of applying a generic checklist unchanged.
- Added explicit dotenv-loading control after the first test pass showed hidden coupling to the local `.env` file.
- Limited the final change set to settings hardening and validation that I can explain directly.

## Security Decisions I Made Myself
- Required `SECRET_KEY` and `ALLOWED_HOSTS` in non-debug mode because these are foundational production controls.
- Defaulted cookie `Secure` flags, SSL redirect, and HSTS to production-on rather than relying on manual enablement.
- Used explicit environment-variable parsing to avoid surprising truthiness behavior from raw strings.
- Kept local development usable with localhost-only fallbacks in debug mode instead of weakening the production path.
- Made proxy trust opt-in so the app does not silently trust forwarded headers unless deployment is configured for that.

## Authorship Affirmation
- I understand every security-relevant setting changed in this PR and can explain the environment assumptions, browser protections, cookie settings, transport controls, and validation steps without assistance.

## Checklist
- [x] I linked the related issue
- [x] I linked exactly one assignment issue in the Related Issue section
- [x] I started from the active assignment branch for this task
- [x] My pull request targets the exact assignment branch named in the linked issue
- [x] I included a short design note and meaningful validation details
- [x] I disclosed any AI assistance used for this submission
- [x] I can explain the key code paths, security decisions, and tests in this PR
- [x] I tested the change locally
- [x] I updated any directly related documentation or configuration, or none was required
