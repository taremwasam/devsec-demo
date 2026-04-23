# Secure File Upload Review Prep

Use this note to explain the security decisions in PR #443 clearly and briefly.

## 1. What problem does this PR fix?

This PR hardens avatar and document uploads so the application does not trust user-supplied files by default. The main risks were:

- uploading a dangerous file disguised as an image or PDF
- serving uploaded files from a public location
- accepting oversized files that waste storage or resources
- letting unauthorized users access another user's uploaded content

## 2. Why is checking only the file extension not enough?

Because an attacker can rename a file like `payload.html` to `avatar.png` or `report.pdf`. The name alone does not prove the file contents are safe.

## 3. Why is checking only the MIME type not enough?

Because the client controls the upload request metadata. A browser or attacker can send `image/png` or `application/pdf` even when the file content is not really that type.

## 4. What extra validation was added?

The upload validation is layered:

- extension allowlist
- reported content type check
- file signature or magic-byte validation
- file size limit

This defense-in-depth approach makes simple spoofing much harder.

## 5. What files are allowed?

- avatars: `.jpg`, `.jpeg`, `.png`
- documents: `.pdf`

## 6. What size limits are enforced?

- avatars: 2 MB maximum
- documents: 5 MB maximum

## 7. Why use magic-byte or file-signature checks?

They help verify that the file contents look like the type the application expects. This is stronger than trusting the filename or request header alone.

## 8. Why store uploads privately?

Private storage prevents uploaded files from being directly reachable through a public media URL. That reduces accidental exposure and makes the application enforce authorization before serving files.

## 9. How are uploads served back to users?

Uploads are downloaded through a Django view, not a public static file path. That view:

- requires authentication
- checks whether the requester is allowed to view the owning profile
- sets `X-Content-Type-Options: nosniff`
- serves documents as attachments

## 10. Why serve documents as attachments?

It reduces inline rendering risk in the browser and is safer for user-uploaded files than trying to display everything directly.

## 11. How are filenames handled safely?

The stored filename is replaced with a randomized token plus the safe extension. This avoids exposing user-controlled filenames as storage paths and reduces path-related abuse.

## 12. What tests prove the behavior?

The upload-specific tests cover:

- valid avatar and document uploads are accepted
- fake image content with an allowed extension is rejected
- fake PDF content is rejected
- oversized documents are rejected
- unauthorized users cannot download another user's document
- authorized staff can access the protected document path

## 13. What local validation did I run?

- `python manage.py test taremwa.tests_file_uploads`
- `python manage.py test tests.test_validate_pr_submission`

The targeted upload tests passed. The full project test suite still has unrelated pre-existing failures in authorization, IDOR, and open-redirect areas outside this task.

## 14. Short version for verbal explanation

"I treated file uploads as a security boundary. I did not trust the filename or client MIME type alone. I added layered validation with extension, content type, signature, and size checks; stored files in a private location with randomized names; and served them only through authenticated, authorization-checked views with safer response headers."
