# Secure Password Reset Design

## Overview
This document explains the security design decisions behind the password reset workflow implemented in the Taremwa UAS (User Authentication System). The implementation follows Django's built-in secure patterns and OWASP recommendations for account recovery flows.

## Security Goals
1. **Account Recovery**: Enable users to regain access to compromised or forgotten accounts
2. **No User Enumeration**: Prevent attackers from discovering which email addresses are registered
3. **Token Security**: Use cryptographically secure, time-limited tokens
4. **Integrity**: Ensure only the account owner can reset their password
5. **Usability**: Provide clear, user-friendly error messaging without revealing sensitive info

## Implementation Details

### 1. Password Reset Request Flow

#### Security: User Enumeration Prevention
**Challenge**: Password reset forms are easy targets for user enumeration attacks. Attackers can determine if an email is registered by observing timing differences or error message variations.

**Solution**: 
- Always display the same generic success message regardless of whether the email exists or not
- If email doesn't exist in database, silently skip email sending but show same message
- Response timing is kept consistent through Django's password hashing operations

```python
# Example from password_reset_request view:
if user:
    send_mail(...)  # Send reset email
else:
    pass  # Silently continue

# Always show same message:
messages.success(request, 'If an account exists for this email, you will receive...')
```

**Trade-off**: Users with invalid emails get no feedback, but this is the secure choice that prevents account enumeration.

### 2. Token Generation & Validation

#### Technology: Django's `default_token_generator`
**Why not custom tokens?**
- Django's token generator uses cryptographic HMAC with SHA256
- Tokens are bound to user state (password hash, last login)
- Tokens automatically become invalid after password change (preventing reuse)
- Time-limited by PASSWORD_RESET_TIMEOUT setting (default: 24 hours)

**Token Format**:
- Generated: `default_token_generator.make_token(user)`
- User ID: Encoded in base64 to prevent direct ID disclosure
- Not stored in database, reducing attack surface
- Mathematically cryptographic validation, no database lookup needed

```python
# Token validation in password_reset_confirm:
if user is not None and default_token_generator.check_token(user, token):
    # Token is valid and not expired
    # Proceed with password reset
```

#### Anti-Replay Protection
- Token becomes invalid after ANY password change
- Prevents attackers from reusing leaked password reset tokens
- Forces legitimate user to request a new token

### 3. Email Transport

#### Security Considerations
- Token sent only via email (not logged in URLs or browser history)
- Email body includes reset link with properly encoded UID and token
- Email subject line is generic (doesn't reveal security reasons)

```
Email Subject: Password Reset Request for Taremwa UAS

Request includes:
- Full reset link: /auth/password-reset-confirm/{uid}/{token}/
- Token expiration info: "This link will expire in 24 hours"
- Security disclaimer: "If you didn't request this, ignore"
```

#### Email Backend Configuration
```python
# Development: Console backend (prints to stdout, doesn't send real emails)
if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Production: SMTP backend (configure via environment variables)
else:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    # Further config from environment
```

### 4. Password Reset Confirmation

#### Security: Token Validation
When resetting password, system:
1. Decodes user ID from base64
2. Validates token hasn't been modified (HMAC check)
3. Validates token hasn't expired (timestamp check)
4. Validates token matches current user state (password hash)

```python
uid = force_str(urlsafe_base64_decode(uidb64))
user = User.objects.get(pk=uid)
if default_token_generator.check_token(user, token):
    # Only reached if ALL validations pass
    allow_password_reset()
```

#### Password Strength Validation
Uses Django's AUTH_PASSWORD_VALIDATORS:
- UserAttributeSimilarityValidator: Prevents passwords like username/email
- MinimumLengthValidator: Enforces minimum length
- CommonPasswordValidator: Blocks common passwords from database
- NumericPasswordValidator: Blocks all-numeric passwords

**New Password Form** (`PasswordResetConfirmForm`):
- Extends Django's `SetPasswordForm`
- Provides password strength error messages
- Validates both passwords match
- Uses Bootstrap styling for consistency

### 5. URL Design & Security

#### Token in URL?
**Decision**: Yes, but safely

**Why tokens must be in URL**:
- Links must work when clicked from email
- Can't store state server-side for stateless email flow

**How to make it safe**:
- Use Django's built-in encoding (base64)
- Combine with time-limited tokens
- Regenerate tokens after use
- Token depends on password hash (changes after reset)

**HTTP vs HTTPS**:
- In production: MUST use HTTPS only
- Configure `SECURE_SSL_REDIRECT = True` in settings.py
- Tokens in URLs are only safe over HTTPS

### 6. Error Handling

#### Information Disclosure Prevention
**Bad Error Messages** ❌:
- "User not found"
- "Invalid token - user ID doesn't exist"
- "Email not registered"

**Good Error Messages** ✅:
- "The password reset link is invalid or has expired"
- "If an account exists for this email, check your inbox"
- No mention of whether user exists or not

**Implementation**:
```python
# Don't reveal user existence
if user is None:
    messages.error(request, 'Link invalid or expired')
    # vs revealing: "User {email} not found"
```

### 7. Rate Limiting Considerations

**Not implemented at application level** (should be at infrastructure level):
- Middleware/Reverse Proxy should rate-limit password reset requests
- Example: 5 requests per hour per IP address
- Prevents attackers from brute-forcing email addresses

**Why infrastructure level?**:
- More efficient (blocks traffic before Django)
- Works for all endpoints uniformly
- Can't be bypassed by application changes

### 8. Account Protection During Reset

#### No Account Lock During Reset
- Username/password login still works during reset period
- User can have multiple concurrent reset requests
- Reset tokens are independent of active sessions

#### Use Case: Account Compromise
If attacker compromises account:
1. Legitimate user requests password reset
2. Receives email with reset link
3. Resets password - automatically invalidates attacker's session
4. Sets new password - invalidates any stolen password reset tokens

​### 9. Testing Strategy

**30 comprehensive tests** cover:

1. **Happy Path**:
   - E2E complete reset flow (request → email → confirm → login)
   - Email sent with valid token
   - New password works after reset
   - Old password stops working

2. **Security Tests**:
   - No user enumeration (invalid email shows same message)
   - Token validation (invalid token rejected)
   - Token expiration (old token doesn't work)
   - Token one-time use (can't reuse after reset)

3. **Validation Tests**:
   - Password strength enforcement
   - Password matching validation
   - Empty field handling
   - Invalid email format

4. **Authorization Tests**:
   - Authenticated users redirected to dashboard
   - Non-existent user IDs handled safely
   - Modified tokens rejected

## Security Assumptions

1. **HTTPS in Production**: All password reset links must be served over HTTPS
2. **Email Security**: System assumes email provider is trustworthy (not modified in transit)
3. **Database Security**: Password hashes are secure and stored safely
4. **Environment Variables**: Email settings (SMTP credentials) are stored securely
5. **Django Updates**: Security patches are applied regularly

## Production Recommendations

1. **Enable HTTPS** (required):
   ```python
   SECURE_SSL_REDIRECT = True
   SESSION_COOKIE_SECURE = True
   CSRF_COOKIE_SECURE = True
   ```

2. **Configure Email Backend**:
   ```python
   EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
   EMAIL_HOST = os.environ.get('EMAIL_HOST')
   EMAIL_PORT = 587
   EMAIL_USE_TLS = True
   EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
   EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
   ```

3. **Set Appropriate Timeout**:
   ```python
   PASSWORD_RESET_TIMEOUT = 3600  # 1 hour for higher security
   # vs 86400 for 24 hours (current default)
   ```

4. **Rate Limiting** (at reverse proxy):
   - Limit password reset requests per IP
   - Implement CAPTCHA for multiple failures
   - Monitor for brute force attacks

5. **Logging & Monitoring**:
   - Log password reset attempts (failures only)
   - Alert on repeated reset attempts for same account
   - Monitor email delivery failures

## OWASP Alignment

This implementation addresses OWASP recommendations:

✅ **OWASP A06:2021 - Broken Access Control**
- User can only reset their own password
- User ID validation prevents ID manipulation

✅ **OWASP A07:2021 - Identification & Authentication Failures**
- Secure token generation (cryptographic)
- Secure storage (not logged, not persisted unnecessarily)
- Time-limited tokens

✅ **OWASP A04:2021 - Insecure Deserialization**
- Base64 encoding for UID (not pickle/JSON unserialization)
- Safe decode with error handling

✅ **OWASP A01:2021 - Broken Access Control (User Enumeration)**
- Generic error messages prevent enumeration
- Consistent response times for requests

## References

- Django Security Documentation: https://docs.djangoproject.com/en/stable/topics/security/
- Django Password Reset Implementation: https://docs.djangoproject.com/en/stable/contrib/auth/#django.contrib.auth.tokens
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html

## Future Enhancements

1. **Two-Factor Authentication**: Require 2FA for password reset
2. **Security Questions**: Add optional security question verification
3. **Email Confirmation**: Require clicking link in confirmation email
4. **SMS Backup Codes**: Alternative recovery methods
5. **Biometric Support**: Fingerprint/Face ID for mobile app
6. **Breach Detection**: Monitor for compromised passwords and force reset

---

**Author**: Security Team  
**Date**: 2026-04-15  
**Status**: Implemented in assignment/secure-password-reset branch
