Secure File Upload Handling Design Note

This document explains the security controls added for avatar and document uploads in the Taremwa profile workflow.

Threat model

- Attackers may upload files with misleading names or client-provided MIME types.
- Uploaded content may become dangerous if the application serves it directly from a public media directory.
- Oversized uploads can be abused for denial-of-service or disk consumption.
- Access to personal uploads must respect the same authorization rules as profile access.

Chosen controls

1. Server-side validation before saving

- Avatar uploads are limited to `.jpg`, `.jpeg`, and `.png`.
- Document uploads are limited to `.pdf`.
- The application validates file extension, reported content type, and file signature bytes.
- This avoids trusting only browser metadata and blocks simple extension-spoofing attempts.

2. Explicit size limits

- Avatars are capped at 2 MB.
- Documents are capped at 5 MB.
- Requests that exceed those limits are rejected at form validation time.

3. Private storage with randomized names

- Uploaded files are stored under `PRIVATE_UPLOAD_ROOT`, not under a public `MEDIA_URL`.
- Filenames are replaced with random tokens, reducing filename disclosure and preventing unsafe original names from becoming storage paths.
- Replaced uploads clean up the previously stored file to reduce leftover sensitive content.

4. Controlled download path

- Files are only returned through an authenticated Django view.
- The view reuses profile-view authorization checks, so only the owner or an already-authorized privileged user can access a file.
- Responses set `X-Content-Type-Options: nosniff`.
- Documents are served as attachments to reduce inline execution risk.

Validation and test coverage

- Tests cover successful uploads for allowed files.
- Tests verify that spoofed avatar/document payloads are rejected based on file contents.
- Tests verify that oversized files are rejected.
- Tests verify that unauthorized users cannot download another user's uploaded document.
