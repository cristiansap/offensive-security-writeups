# Offensive Security

Write-ups from the CTF challenges tackled during the *Offensive Security* course (MSc Cybersecurity Engineering, Politecnico di Torino), covering binary exploitation (stack/heap, ROP, ret2libc) and web security (logic flaws, auth, SQLi, command injection, XSS), together with an in-depth academic report examining authentication vulnerabilities and bypass techniques.

> ⚠️ **Disclaimer:**
> This repository contains only my own write-ups, exploit scripts, and academic report. Original challenge
> material (source code, compiled binaries, Docker environments, course PDF handouts) has
> been intentionally excluded, and captured flags have been redacted from both text and
> screenshots, out of respect for the course's academic integrity. **Shared for educational
> purposes only**.

## Structure

```
offensive-security-writeups/
├── report/                       Authentication bypass (MFA, OAuth 2.0, SAML)
│   └── authentication-bypass-report.pdf
├── challenges/
│   ├── pwn/                      Binary exploitation & reverse engineering
│   │   ├── lab1_2_recap/         Recap — stack smashing, buffer overflows
│   │   ├── lab3_4_recap/         Recap — ret2libc
│   │   ├── lab_01_pwn-rev/       Binary exploitation & reverse engineering
│   │   ├── lab_02_printf_canaries/  Format string bugs, canary bypass
│   │   ├── lab_03_ret2libc/      ret2libc attacks
│   │   ├── lab_04_rop/           Return-oriented programming (PIE/ROP)
│   │   └── lab_05_heap/          Heap exploitation
│   └── web/                      Web security
│       ├── web_lab_01_logic/     Business logic flaws
│       ├── web_lab_02_auth/      Authentication flaws (incl. JWK confusion)
│       ├── web_lab_03_sqli/      SQL injection
│       ├── web_lab_04_cmdi/      Command injection
│       └── web_lab_05_xss/       Cross-site scripting
├── LICENSE
└── LICENSE-MIT
```

Each challenge folder includes my `solve.py`/`exploit.py` and/or a `README.md` write-up explaining the vulnerability and the exploitation steps.

## Report

`report/` contains an in-depth academic report, *"Authentication Bypass in Web Applications: Vulnerabilities, Attack Techniques, and Case Studies"*, covering MFA, OAuth 2.0, and SAML — technical background, common weaknesses, reconnaissance checklists, attack walkthroughs (PortSwigger Academy labs + real-world CVEs), and mitigations.

## Notes

- Real flag values are redacted (`offsec{REDACTED}`) in both write-ups and screenshots.
- Challenge binaries, source files, Docker setups, and course PDFs are not included.

## License

Write-ups and documentation are licensed under [CC BY-NC-SA 4.0](LICENSE). Scripts are licensed under [MIT](LICENSE-MIT).

## Author

Cristian Sapia
