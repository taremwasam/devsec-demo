# Role-Based Access Control (RBAC) for Taremwa UAS

## Overview

This document describes the role-based access control system implemented in the Taremwa User Authentication Service. It provides clear authorization rules separating what anonymous users, normal users, instructors, staff, and admins can do.

## Authorization Model

### User Roles

The system defines 5 user roles with increasing privilege levels:

| Role | Authentication | Group | Permissions | Access Level |
|------|---|---|---|---|
| **Anonymous** | ❌ No | None | None | Public pages only (register, login) |
| **User** | ✅ Yes | None | Basic auth | Own data only |
| **Instructor** | ✅ Yes | `instructor` | View all profiles | View-only access |
| **Staff** | ✅ Yes (is_staff=True) | `staff` | View/edit all profiles, manage users | Full admin capabilities |
| **Admin** | ✅ Yes (is_superuser=True) | N/A | All permissions | Complete system control |

### Authorization Rules

#### Anonymous Users (Not Authenticated)
```
✅ CAN:
  - Register new account
  - View login page
  - View public error pages

❌ CANNOT:
  - Access any protected pages (dashboard, profile, etc.)
  - View other users' information
  - Redirected to login when accessing protected views
```

#### Regular Authenticated Users
```
✅ CAN:
  - View their own profile
  - Edit their own profile
  - Change their own password
  - Access personal dashboard
  - View user list (staff/instructors only)

❌ CANNOT:
  - View other users' profiles (even other users)
  - Edit other users' profiles
  - Delete users
  - Access staff dashboard
  - Manage system
```

#### Instructors
```
✅ CAN:
  - View ALL user profiles (view-only)
  - Access view-all-users page
  - Edit own profile
  - Change own password
  - View user information for teaching purposes

❌ CANNOT:
  - Edit other users' profiles
  - Delete users
  - Access staff  dashboard
  - Access admin panel
```

#### Staff Members
```
✅ CAN:
  - View ALL user profiles
  - Edit ALL user profiles
  - Delete user accounts
  - Access staff dashboard
  - View admin statistics
  - Perform user management tasks
  - View admin panel

❌ CANNOT:
  - Delete admin/superuser accounts
  - Access superuser-only features
  - Delete their own account
```

#### Administrators (Superusers)
```
✅ CAN:
  - Do EVERYTHING
  - Access entire admin interface
  - Create/modify groups and permissions
  - Delete any user including staff
  - System-wide configuration

```

## Implementation

### Groups and Permissions

Groups are created by running:

```bash
python manage.py setup_rbac
```

This creates:
- **staff** group
- **instructor** group

And custom permissions:
- `taremwa.view_all_profiles` - Can view other users' profiles
- `taremwa.edit_other_profiles` - Can edit other users' profiles
- `taremwa.view_admin_dashboard` - Can access admin dashboard

### Authorization Decorators

#### `@staff_required`
```python
@staff_required
def staff_dashboard(request):
    # Only staff/admins can access
    pass
```

Redirects to login if not authenticated, returns 403 if not staff.

#### `@instructor_required`
```python
@instructor_required
def view_all_users(request):
    # Instructors and staff can access
    pass
```

Allows both instructors and staff members.

### Authorization Helper Functions

#### `can_view_profile(user, target_user)`
```python
# Determines if user can view target_user's profile
# - Users can view own profile
# - Staff can view anyone
# - Instructors can view anyone
# - Others: False

if can_view_profile(request.user, target_user):
    # Show profile
```

#### `can_edit_profile(user, target_user)`
```python
# Determines if user can edit target_user's profile
# - Users can edit own profile
# - Staff can edit anyone
# - Others: False
```

#### `can_delete_user(user, target_user)`
```python
# Determines if user can delete target_user
# - Only admins can delete
# - Cannot delete self
# - Cannot delete other admins (unless superuser)
```

#### `get_user_role(user)`
```python
# Returns role: 'admin', 'staff', 'instructor', 'user', or 'anonymous'
role = get_user_role(request.user)
```

Use in templates with `{% if user_role == 'staff' %}`

## Available URLs

### Public (Unauthenticated)
- `GET /auth/register/` - Register page
- `GET /auth/login/` - Login page
- `POST /auth/login/` - Login submission

### Authenticated Users
- `GET /auth/logout/` - Logout
- `GET /auth/dashboard/` - Personal dashboard
- `GET /auth/profile/` - Own profile
- `POST /auth/profile/` - Edit own profile
- `GET /auth/change-password/` - Change password page
- `POST /auth/change-password/` - Change password

### Instructors & Staff
- `GET /auth/staff/users/` - View all users
- `GET /auth/profile/<user_id>/` - View specific user profile (with auth check)

### Staff Only
- `GET /auth/staff/dashboard/` - Staff dashboard with statistics
- `GET /auth/staff/delete-user/<user_id>/` - Delete user confirmation
- `POST /auth/staff/delete-user/<user_id>/` - Delete user

## Views with Authorization

### Public Views
```python
def register(request):
    # Anyone can register (no auth required)
```

```python
def user_login(request):
    # Anyone can login (no auth required)
```

### Protected Views - Own Data Only
```python
@login_required
def profile(request, user_id=None):
    # Users can view/edit own profile
    # Staff can view/edit any profile
```

### Protected Views - Staff Only
```python
@staff_required
def staff_dashboard(request):
    # Staff and admins only
```

```python
@instructor_required
def view_all_users(request):
    # Instructors and staff can view all users
```

```python
@staff_required
def delete_user(request, user_id):
    # Staff can delete users (with permission checks)
```

## Template Role Checks

### Show Navigation Based on Role
```django
{% if user.is_authenticated %}
    <a href="dashboard">Dashboard</a>
    <a href="profile">Profile</a>
    
    {% if user.is_staff or user.groups.all|icontains:"staff" %}
        <a href="staff_dashboard">Staff Dashboard</a>
        <a href="view_all_users">View Users</a>
    {% elif user.groups.all|icontains:"instructor" %}
        <a href="view_all_users">View Users</a>
    {% endif %}
{% endif %}
```

### Show/Hide Content Based on Permission
```django
{% if can_edit %}
    <button>Edit Profile</button>
{% endif %}
```

## Testing Authorization

Run authorization tests:

```bash
python manage.py test taremwa.tests_authorization
```

### Test Categories

**AuthorizationHelperTest** - Test helper functions
- `test_can_view_own_profile()` - Users can view own profile
- `test_staff_can_view_any_profile()` - Staff can view others
- `test_user_cannot_view_others_profile()` - Users blocked from viewing others
- etc.

**ProfileAuthorizationTest** - Test profile view authorization
- `test_own_profile_accessible()` - Can access own profile
- `test_others_profile_not_accessible()` - Cannot access others (users)
- `test_staff_can_view_any_profile()` - Staff can view any
- `test_anonymous_redirected_to_login()` - Anonymous redirected

**StaffDashboardAuthorizationTest** - Test staff-only views
- `test_staff_dashboard_requires_authentication()` - Login required
- `test_regular_user_cannot_access_staff_dashboard()` - 403 for users
- `test_staff_can_access_staff_dashboard()` - Staff can access

**DeleteUserAuthorizationTest** - Test user deletion authorization
- `test_delete_user_requires_staff()` - Only staff can delete
- `test_staff_cannot_delete_self()` - Cannot delete yourself
- `test_staff_can_view_delete_form()` - Staff sees delete form

**ViewAllUsersAuthorizationTest** - Test user listing
- `test_regular_user_cannot_view_all_users()` - 403 for regular users
- `test_instructor_can_view_all_users()` - Instructor can view
- `test_staff_can_view_all_users()` - Staff can view

## Security Considerations

### Access Control Enforcement
1. **Views** - `@login_required`, `@staff_required` decorators
2. **Templates** - Role-based UI rendering
3. **Helper Functions** - Explicit permission checks before operations
4. **Error Handling** - 403 Forbidden for denied access

### Principle of Least Privilege
- Users get minimum required permissions
- Staff cannot delete admins
- Instructors have read-only access
- Regular users only see own data

### Attack Prevention
✅ **Vertical Privilege Escalation** - Users cannot access staff features
✅ **Horizontal Privilege Escalation** - Users cannot view other users' data
✅ **Resource-Based Access** - Permission checked for specific resources
✅ **Information Leakage** - Errors don't reveal system details

### Authorization vs Authentication
- **Authentication** (UAS) - "Are you who you claim to be?"
  - Login/registration handled by UAS
  - Session management via Django sessions
  
- **Authorization** (RBAC) - "Are you allowed to do this?"
  - Handled by this RBAC system
  - Enforced via decorators and helper functions

## Setup Instructions

### 1. Initialize RBAC
```bash
python manage.py setup_rbac
```

Creates `staff` and `instructor` groups with appropriate permissions.

### 2. Create Users and Assign Roles

Via Django admin:
- Create user normally
- Add to `staff` group for staff privileges
- Add to `instructor` group for instructor privileges
- Make superuser for admin privileges

Or via shell:
```python
from django.contrib.auth.models import User, Group

user = User.objects.get(username='john')
staff_group = Group.objects.get(name='staff')
user.groups.add(staff_group)
```

### 3. Test Authorization
```bash
python manage.py test taremwa.tests_authorization
```

## Troubleshooting

### "Forbidden: Insufficient permissions"
- User lacks required role
- Check group membership in admin
- Verify decorators on view

### Can't access staff dashboard
- Ensure user is in `staff` group or is superuser
- Run `setup_rbac` to create groups
- Check `is_staff` flag

### View all users not working for instructor
- Ensure user is in `instructor` group
- Run `setup_rbac`
- Check view decorator

### Profile view returning 403
- Trying to view another user's profile
- Must be staff/instructor to view others
- Can always view own profile

## Best Practices

1. **Use Decorators** - Apply `@staff_required`, `@instructor_required` consistently
2. **Check Permissions** - Use helper functions before operations
3. **Template Checks** - Hide UI elements users can't access anyways
4. **Test All Paths** - Test with different user roles
5. **Log Access** - Consider logging who accessed what
6. **Document Rules** - Clear authorization policy documentation
7. **Principle of Least Privilege** - Grant minimum necessary permissions

## Related Files

- [taremwa/authorization.py](taremwa/authorization.py) - Decorators and helper functions
- [taremwa/views.py](taremwa/views.py) - Views with authorization logic
- [taremwa/tests_authorization.py](taremwa/tests_authorization.py) - Comprehensive test suite
- [taremwa/management/commands/setup_rbac.py](taremwa/management/commands/setup_rbac.py) - RBAC setup command

---

**Last Updated**: April 14, 2026  
**Status**: Production Ready ✅
