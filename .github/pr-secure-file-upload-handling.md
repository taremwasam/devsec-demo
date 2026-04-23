## Assignment Summary
- Hardened avatar and document uploads in the profile workflow by validating file type and size, storing uploads outside public media paths, and serving them only through authenticated authorization-checked views.

## Related Issue
- Closes #417

## Target Assignment Branch
- `assignment/secure-file-upload-handling`

## Design Note
- I kept upload controls close to the profile workflow so validation happens before model save and download authorization stays aligned with existing profile access rules. I chose layered validation instead of trusting any single signal: extension, reported content type, file signature bytes, private storage, randomized filenames, and controlled download responses.

## Security Impact
- Prevents simple extension spoofing and weak client-MIME trust from letting dangerous files through.
- Reduces exposure by storing uploaded content under a private root instead of a public media URL.
- Limits abuse with explicit avatar and document size caps.
- Applies authorization checks to download access and uses safer response headers for served files.

## Changes Made
- Added upload security helpers for size checks, extension allowlists, content-type checks, file-signature validation, randomized private paths, and safe download filenames.
- Updated `UserProfile` avatar and document fields to use private storage and randomized `upload_to` paths.
- Validated avatar and document uploads in `UserProfileForm`.
- Added a gated download view and route for private profile uploads with `nosniff`, private caching, and attachment handling for documents.
- Updated the profile template to document allowed file rules and link to controlled download endpoints.
- Added focused tests for valid uploads, spoofed content rejection, size enforcement, and authorization on document access.
- Added a short design note in `SECURITY_DESIGN_FILE_UPLOADS.md`.

## Validation
- Ran `python manage.py test taremwa.tests_file_uploads`
- Ran `python manage.py test tests.test_validate_pr_submission`
- Ran `python manage.py test`
- Result: targeted upload tests passed and the PR-body validator tests passed. The full suite still has pre-existing failures in authorization, IDOR, and open-redirect tests outside this upload task branch.

## AI Assistance Used
- Yes. I used Codex for repository analysis, implementation review, validation, and drafting the PR summary.

## What AI Helped With
- Inspecting the current upload hardening implementation against the issue acceptance criteria.
- Running the relevant local tests and identifying which failures were unrelated to this task.
- Drafting a structured PR body that matches the repository validator requirements.

## What I Changed From AI Output
- Kept the final submission grounded in the repository's actual code paths and test results instead of using generic upload-security recommendations.
- Limited the PR narrative to the implemented controls in this branch and explicitly separated unrelated failing tests from task-specific validation.

## Security Decisions I Made Myself
- Used a defense-in-depth upload policy instead of trusting only extensions or only MIME types.
- Stored uploads in a private root with randomized names so user-controlled filenames do not become public paths.
- Reused profile-view authorization for downloads so file access follows the same access-control model as profile access.
- Served documents as attachments and added `X-Content-Type-Options: nosniff` to reduce content-sniffing and inline execution risk.

## Authorship Affirmation
- I understand the code submitted in this PR and can explain the upload threat model, validation layers, storage decisions, authorization checks, and local validation steps without assistance.

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
