# SpreadSheet Zero — Write-up

**Category:** Code Injection (Server-Side Formula Evaluation)  
**Flag:** offsec{REDACTED}

---

## Description

SpreadSheet Zero is a collaborative online spreadsheet that supports server-side formula evaluation. Cells accept formulas prefixed with `=`, which are sent via POST to `/api/cell` and evaluated on the server.

---

## Analysis

The page footer hints at the vulnerability: *"Formulas powered by server-side evaluation engine"*. When a cell value is submitted, the frontend sends:

```json
POST /api/cell
{"ref": "A1", "value": "=<formula>"}
```

The backend evaluates the formula server-side. Given that arbitrary Python expressions work, the engine is almost certainly using Python's `eval()` with no sandboxing.

---

## Exploit

Entering the following formula in any cell:

```
=__import__('os').environ['FLAG']
```

The server evaluates the expression, imports the `os` module, reads the `FLAG` environment variable, and returns its value as the cell result, thus displaying the flag directly in the spreadsheet.

---

## Lesson Learned

Passing user-supplied formulas to `eval()` without a sandbox is equivalent to granting arbitrary code execution. Safe alternatives include using a dedicated expression parser that only supports mathematical operations (e.g. `ast.literal_eval`, or a library like `simpleeval`), with an explicit whitelist of allowed functions and no access to builtins.