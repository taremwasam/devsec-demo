# Stored XSS Mitigation for Profile Content

This change treats profile bios as plain text instead of user-supplied HTML.

Mitigation choices:

- Strip submitted HTML tags from the bio before storing it.
- Render the saved bio with Django escaping intact.
- Preserve normal line breaks in the dashboard display with `linebreaksbr` so ordinary text still reads naturally.

Why this closes the risk:

- Script tags and event-handler markup such as `<img onerror=...>` are removed before the content is saved.
- The remaining text is still escaped by Django templates when rendered, so browser-executable markup is not reintroduced.

Allowed behavior:

- Normal plain-text bios still work.
- Multi-line bios still render across multiple lines.

Disallowed behavior:

- Stored HTML formatting is no longer supported for profile bios.
- Unsafe rendering shortcuts are not used for profile content.
