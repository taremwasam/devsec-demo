# Taremwa UAS - Quick Start Guide

## 🚀 Getting Started

### 1. Verify Installation

All required files are already in place. Check Django recognizes the app:

```bash
cd c:\Users\USER\Desktop\devsec\devsec-demo
python manage.py check
```

Expected output: `System check identified no issues (0 silenced).`

### 2. Create Django Superuser

```bash
python manage.py createsuperuser
```

Follow the prompts to create admin account:
- Username: your choice
- Email: your@email.com
- Password: secure password (won't be echoed)

### 3. Run the Development Server

```bash
python manage.py runserver
```

Navigate to: `http://localhost:8000`

### 4. Test the Application

#### Via Web Browser
- **Register**: `http://localhost:8000/auth/register/`
- **Login**: `http://localhost:8000/auth/login/`
- **Dashboard**: `http://localhost:8000/auth/dashboard/` (requires login)
- **Profile**: `http://localhost:8000/auth/profile/` (requires login)
- **Admin**: `http://localhost:8000/admin/` (requires superuser)

#### Via Test Suite

Run all tests:
```bash
python manage.py test taremwa
```

Run specific test class:
```bash
python manage.py test taremwa.tests.UserRegistrationTest
```

Run with verbose output:
```bash
python manage.py test taremwa -v 2
```

## 📋 User Workflows

### Workflow 1: New User Registration
1. Go to `http://localhost:8000/auth/register/`
2. Enter username, email, first/last name, password
3. Submit form
4. See success message
5. Redirected to login page

### Workflow 2: User Login
1. Go to `http://localhost:8000/auth/login/`
2. Enter username and password
3. Submit form
4. Redirected to dashboard
5. See personalized welcome message

### Workflow 3: Edit Profile
1. Be logged in (complete Workflow 2)
2. Go to `http://localhost:8000/auth/profile/`
3. Update email, name, or bio
4. Click "Save Changes"
5. See success message

### Workflow 4: Change Password
1. Be logged in
2. From profile page, click "Change Password"
3. Or go directly to `http://localhost:8000/auth/change-password/`
4. Enter old password, new password (twice)
5. Click "Change Password"
6. See success message

### Workflow 5: Logout
1. Be logged in
2. Click "Logout" in navigation bar
3. Redirected to login page
4. Session cleared

## 🔒 Security Features to Verify

✅ **Password Hashing**: 
- Login with wrong password fails
- Try SQL injection in username field - blocked

✅ **CSRF Protection**:
- Right-click form → Inspect → Change CSRF token → Submit fails

✅ **Authentication Required**:
- Try accessing `/auth/dashboard/` without login - redirected to login

✅ **Session Management**:
- Close browser/clear cookies → Dashboard access denied

## 🧪 Test Coverage Summary

**Total: 20 Tests**
- ✅ Registration: 5 tests
- ✅ Login: 3 tests  
- ✅ Protected Areas: 4 tests
- ✅ Password Change: 4 tests
- ✅ Logout: 1 test
- ✅ Profile Model: 3 tests

All tests verify:
- Happy path (valid inputs)
- Error handling (invalid inputs)
- Security (auth required, permission checks)
- Database integrity (no duplicates)

## 📁 Key Files to Review

| File | Purpose |
|------|---------|
| `taremwa/models.py` | UserProfile model definition |
| `taremwa/forms.py` | All authentication forms with validation |
| `taremwa/views.py` | View functions for all workflows |
| `taremwa/urls.py` | URL routing with namespacing |
| `taremwa/templates/taremwa/base.html` | Base template with navigation |
| `taremwa/admin.py` | Django admin configuration |
| `taremwa/tests.py` | Comprehensive test suite |
| `TAREMWA_README.md` | Full documentation |

## 🎯 Required Deliverables Checklist

- [x] Django app named `taremwa`
- [x] Models for authentication (UserProfile)
- [x] Forms for registration, login, password change
- [x] Views and URL routes for all flows
- [x] Templates for user-facing pages
- [x] Admin integration with user management
- [x] Access control for protected pages (login required)
- [x] Validation and error handling
- [x] Tests covering main auth behaviors (20 tests)
- [x] Clear documentation in TAREMWA_README.md
- [x] Django conventions followed throughout
- [x] Built-in auth features leveraged (User model, auth middleware)
- [x] Secure defaults (CSRF, password hashing)
- [x] Modular, maintainable code
- [x] No breaking changes to existing repo

## 🔧 Troubleshooting

### Server won't start
```bash
# Kill any existing process
# Restart:
python manage.py runserver
```

### Can't login after registration
- Verify user was created: Check admin at `/admin/`
- Verify password was typed correctly at registration
- Check password doesn't have special chars that need escaping

### Tests fail
```bash
# Fresh database
python manage.py migrate

# Re-run tests
python manage.py test taremwa
```

### Page says "Page not found"
- Ensure dev server is running
- Check URL exactly matches (case-sensitive in Linux)
- Verify taremwa app is in INSTALLED_APPS in settings.py

## 📝 Next Steps

1. **Test the flows manually** (all 5 workflows above)
2. **Run the test suite** to verify 20/20 pass
3. **Review code quality** for readability and style
4. **Create meaningful commits** with clear messages
5. **Prepare pull request** with:
   - Feature description
   - Testing performed
   - Security review notes
   - Any AI assistance disclosure

## 📚 Reference Documentation

- Django Auth: https://docs.djangoproject.com/en/6.0/topics/auth/
- Django Forms: https://docs.djangoproject.com/en/6.0/topics/forms/
- Django Views: https://docs.djangoproject.com/en/6.0/topics/http/views/
- Django Tests: https://docs.djangoproject.com/en/6.0/topics/testing/
- OWASP Auth: https://owasp.org/www-project-top-ten/
- Django Security: https://docs.djangoproject.com/en/6.0/topics/security/

---

**Last Updated**: 2026-04-14  
**Status**: Ready for Testing ✅
