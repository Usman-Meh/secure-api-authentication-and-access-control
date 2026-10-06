# Security Hardening Notes

This document describes the weaknesses found in the baseline API (`app_student.py`), how
each was fixed in `app_solution.py`, and how the fixes were verified. Function names are
used instead of line numbers so the references stay valid as the code evolves.

## 1. Findings

| # | Weakness | CWE | Source |
|---|---|---|---|
| 1 | Hardcoded secrets and credentials | CWE-798 / CWE-259 | flake8 `S105`, bandit `B105` |
| 2 | Plaintext password storage | CWE-256 | flake8 `S105`, bandit `B105` |
| 3 | Missing API authentication | CWE-306 | Code review of `require_api_key()` |
| 4 | Broken authorization / missing least privilege | CWE-862 | Code review of `require_role()` |
| 5 | Error messages containing internal details | CWE-209 | Code review of `get_user_data()` |
| 6 | Unhandled exceptions from malformed form input | — | Code review of `rent_equipment()` |

Findings 3 and 4 are not flagged by a specific static-analysis rule; they were identified by
reading the authentication helpers and the routes that depend on them. The baseline scan
output and a sample traffic log are in [`baseline/`](baseline/).

## 2. Mitigation strategies

### 2.1 Secure credential and secret management (findings 1 and 2)

**Before:** the Flask session key, an API key and database credentials were string
literals in the source code, and the API key was printed at startup. User passwords were
stored in plaintext and compared with `==`.

**After:**

- Secrets are read from `FLASK_SECRET_KEY`, `RENTAL_API_KEY`, `DB_USER` and `DB_PASSWORD`.
  If no session key is configured, a random 256-bit key is generated per process with
  `secrets.token_hex(32)`. There is no hardcoded fallback value.
- The startup message reports only whether an API key is configured.
- `USERS_DB` holds only `password_hash` values created with
  `generate_password_hash(pw, method="pbkdf2:sha256:600000")`: salted PBKDF2-HMAC-SHA256
  at the 600,000-iteration work factor recommended by OWASP.
- `verify_password()` checks credentials with `check_password_hash` for both login paths.
  For an unknown username it still hashes against a random dummy value, so response time
  does not reveal which usernames exist.

**Effect:** reading the source or history no longer yields working secrets, secrets can be
rotated without code changes, and a leaked user store exposes only slow, salted hashes.
Existing users log in with the same passwords as before.

### 2.2 API authentication and role-based authorization (findings 3 and 4)

**Before:** no endpoint identified its caller, and every role check passed. Any network
client could read all rentals, list users, and delete accounts.

**After:**

- **Authentication (who is calling?).** `require_api_key()` parses only the
  `Authorization: Bearer <key>` header (query-string keys are ignored, CWE-598) and compares
  the token with each stored key using `hmac.compare_digest`, which avoids timing leaks.
  Protected routes return **401** with `WWW-Authenticate: Bearer` when it returns `None`.
- **Authorization (what may they do?).** `require_role()` uses the hierarchy
  `ROLE_LEVELS = {"guest": 1, "user": 2, "admin": 3}`. Unknown users, unknown roles and
  missing roles are denied. Insufficient privilege returns **403**.
- **Least privilege per route.**

  | Route | Rule |
  |---|---|
  | `GET /api/v1/admin/users`, `DELETE /api/v1/admin/delete_user` | `admin` only |
  | `GET /api/v1/rentals` | non-admins see only their own rentals |
  | `POST /api/v1/rentals` | `user` or higher; ownership comes from the authenticated caller, not the request body |
  | `GET /api/v1/user` | callers may read only their own record unless `admin` |

## 3. Input validation

Both techniques below are implemented in `app_solution.py`.

**Type checking.** `verify_password()` and `require_role()` confirm that usernames and
passwords are strings before using them. A JSON body such as
`{"username": ["admin"], "password": 123}` fails closed: it is treated as invalid instead of
raising a `TypeError` (lists cannot be dictionary keys) and producing a 500 response.

**Allowlist and format validation.** Only the `Bearer` scheme is accepted in the
`Authorization` header; rental equipment must be a key of `EQUIPMENT_PRICES` (otherwise
400); roles must exist in `ROLE_LEVELS`. Defining what is allowed — rather than trying to
recognize every bad value — keeps unexpected input out of the business logic.

## 4. Exception handling

**Database errors (`get_user_data()`).** The baseline used `except Exception as e` and
returned `str(e)`, which exposed messages such as `no such table: users`. The handler now
catches `sqlite3.Error` only, logs the full error server-side with `app.logger.exception`,
and returns `{"status": "error", "message": "Internal server error"}` with HTTP 500.
*Security:* no database or query details reach the client. *Reliability:* failures produce
a consistent, predictable response while the log keeps the detail needed for debugging.

**Rental form input (`rent_equipment()`).** The baseline indexed `EQUIPMENT_PRICES` and
called `int()` on form fields directly, so unknown equipment, missing fields, or
non-numeric days raised unhandled exceptions (HTTP 500). These specific errors
(`KeyError`, `ValueError`, `TypeError`) are now caught; the app logs a warning without
echoing the input and re-renders the form with HTTP 400 and a corrective message.
*Security:* malformed input cannot trigger stack traces or be used to generate server
errors. *Reliability:* the request path no longer crashes; valid input is unaffected.

| Input to `POST /rent` | Baseline | Hardened |
|---|---|---|
| Unknown equipment | 500 | 400 + message |
| Non-numeric days | 500 | 400 + message |
| Missing fields | 500 | 400 + message |
| Valid (Crane, 2 days) | 200 | 200, total $1,600 |

## 5. Transport security

TLS (HTTPS) is the appropriate way to protect this API's traffic in transit — credentials
sent to `/api/v1/authenticate`, the API key it returns, and the `Authorization` header on
every request. TLS provides confidentiality against eavesdropping, integrity against
tampering, and server authentication through certificates.

**TLS is not enabled in this repository.** `app_solution.py` starts Flask's development
server over plain HTTP. A deployment would terminate TLS in a reverse proxy or web server
in front of the application.

Note that password hashing and TLS solve different problems: hashing protects stored
passwords at rest and is one-way; TLS protects data while it travels and is decrypted by
the receiver. The application needs both.

## 6. Verification

`test_run.py` contains one pytest regression test per fix (findings 1–4):

| Test | Assertions |
|---|---|
| `test_general_vuln_1_hardcoded_secrets_remediated` | With env vars set, the app uses exactly those values; with none set, the session key is 64 hex characters, differs between two loads, and is not the old literal; `API_KEY` and `DB_PASSWORD` are `None` |
| `test_general_vuln_2_plaintext_passwords_remediated` | No `password` field; `password_hash` starts with `pbkdf2:sha256:600000$` and does not contain the plaintext; `check_password_hash` accepts the original password; login returns 200 / 401 for right / wrong passwords |
| `test_api_vuln_1_authentication_required` | No key, invalid key, key in URL → 401; valid Bearer key → 200 |
| `test_api_vuln_2_authorization_enforced` | `user` list/delete → 403 and the target user still exists; `guest` → 403; `admin` → 200 |

All four pass against `app_solution.py`. Run against `app_student.py`, all four fail —
for example `assert 200 == 401` and `assert 200 == 403` — which shows the tests detect the
original weaknesses rather than passing trivially.

The two exception-handling changes (section 4) were verified manually with Flask's test
client, comparing baseline and hardened responses; they are not yet covered by automated
tests.

## 7. Known issues

Not addressed in this pass and marked `KNOWN ISSUE` in the code:

- SQL built by string concatenation in `get_user_data()` (bandit `B608`, CWE-89). Exposure
  is reduced because non-admins can query only their own username, but admins can still
  inject. Fix: parameterized query.
- No rate limiting or account lockout on authentication (CWE-307).
- SSN fields remain in rental records (CWE-359); the user lookup fallback returns API keys
  and password hashes.
- Rental `days` is not type- or range-checked in the API, and negative values are accepted
  in the form.
- The search endpoint echoes its query unescaped.
- `debug=True` in the entry point (bandit `B201`, CWE-94) and no TLS.

## References

- MITRE. *CWE-209: Generation of Error Message Containing Sensitive Information.* https://cwe.mitre.org/data/definitions/209.html
- OWASP. *OWASP Top 10 API Security Risks – 2023.* https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Cheat Sheet Series — *Authorization*, *Error Handling*, *Input Validation*, *Password Storage*, *Secrets Management*, *Transport Layer Security.* https://cheatsheetseries.owasp.org/
- Pallets. *Werkzeug — Utilities (password hashing).* https://werkzeug.palletsprojects.com/en/stable/utils/
- Python Software Foundation. *hmac* and *secrets* modules. https://docs.python.org/3/library/hmac.html, https://docs.python.org/3/library/secrets.html
- pytest. *Good Integration Practices (test discovery).* https://docs.pytest.org/en/stable/explanation/goodpractices.html
