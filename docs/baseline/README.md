# Baseline evidence

Artifacts describing the original, unhardened application (`app_student.py`).

| File | Contents |
|---|---|
| `flake8_report.txt` | `flake8` (with security plugin) output: hardcoded passwords (`S105`), SQL built from strings (`S608`), Flask debug mode (`S201`). |
| `bandit_report.txt` | `bandit -r app_student.py` output: `B105` hardcoded passwords, `B608` SQL injection vector, `B201` Flask `debug=True`. |
| `network_security_log.txt` | Sample API/network log showing unauthenticated admin access, injection and XSS attempts, and unhandled errors. |

**Line numbers** in the two scan reports refer to `app_student.py` as committed in
`a04090d` (the first commit). Comments in that file were later reworded, which shifted
some lines; the code itself is unchanged. To view the exact scanned version:

```bash
git show a04090d:app_student.py
```

How these findings were addressed is described in
[`../security-hardening.md`](../security-hardening.md).
