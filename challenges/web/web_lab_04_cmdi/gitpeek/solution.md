# GitPeek — Write-up

**Category:** Command Injection  
**Flag:** `offsec{REDACTED}`

---

## Description

GitPeek is a web-based Git log viewer that accepts a branch/tag name via GET parameter (`?ref=`) and passes it to `git log`. The challenge description hints that the way references are looked up is "a little too trusting".

---

## Analysis

The backend executes the git command roughly as:

```python
subprocess.run(f"git log --oneline --graph --decorate {ref}", shell=True)
```

Using `shell=True` delegates execution to `/bin/sh`, which processes the input **before** invoking git. The application implements a character blacklist (`;`, backticks, etc.), but fails to filter **command substitution** syntax `$()`.

---

## Exploit

By submitting the following payload in the `ref` field:

```
$(printenv FLAG)
```

The shell expands `$(printenv FLAG)` → the value of the `FLAG` environment variable gets passed as an argument to `git log`. Git does not recognize it as a valid revision and returns an error that leaks the value in plaintext:

```
fatal: ambiguous argument 'offsec{REDACTED}':
unknown revision or path not in the working tree.
```

---

## Lesson Learned

A character blacklist is a weak defense against injection attacks. The correct fix is to use `shell=False` and pass arguments as a list, or to validate input against a strict **whitelist** of allowed characters (e.g. `[a-zA-Z0-9/_.-]`).