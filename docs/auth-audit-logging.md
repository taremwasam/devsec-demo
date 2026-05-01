# Authentication Audit Logging Design

This change adds a dedicated `security.audit` logger for security-relevant events in the authentication and privilege-management flows.

Events currently logged:

- `auth.registration`
- `auth.login`
- `auth.login_throttled`
- `auth.logout`
- `auth.password_change`
- `auth.password_reset_request`
- `auth.password_reset_confirm`
- `privilege.flags_changed`
- `privilege.groups_changed`
- `privilege.permissions_changed`
- `privilege.account_deleted`

Each audit record uses a consistent key/value format so reviewers can quickly filter on `event`, `actor`, `target_user_id`, `target_username`, `outcome`, and related metadata such as `ip_address`.

Privacy and safety decisions:

- Raw passwords are never logged.
- Password reset tokens are never logged.
- Email addresses in password reset and registration audit events are stored only as a short SHA-256 hash prefix (`email_hash`) so the logs stay useful without exposing the address itself.
- Failed login responses remain generic in the UI to avoid user enumeration, while the logs still preserve reviewable event details for defenders.
