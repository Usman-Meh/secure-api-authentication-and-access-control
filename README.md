# Secure API Authentication and Access Control

Security hardening of a small Flask REST API: removing hardcoded secrets, hashing stored
passwords, adding API-key authentication and role-based authorization, and replacing
error handling that leaked internal details. Every fix is covered by a pytest regression
test that fails against the original code and passes against the hardened version.

The repository keeps both versions side by side so each change can be reviewed:

| File | Purpose |
|---|---|
| `app_student.py` | Original baseline. **Intentionally vulnerable — do not deploy.** |
| `app_solution.py` | Hardened version. Each fix sits next to the disabled original line it replaces. |
| `test_run.py` | Security regression tests (pytest). |

## Problem

The baseline is an equipment-rental API (`/api/v1/rentals`, `/api/v1/user`, admin
endpoints, and a small web UI). A review of the code, together with flake8/bandit output
and a sample traffic log ([`docs/baseline/`](docs/baseline/)), found:

| # | Weakness | Evidence |
|---|---|---|
| 1 | Hardcoded secrets — Flask session key, API key and database credentials in source; API key printed at startup | flake8 `S105`, bandit `B105` (CWE-798 / CWE-259) |
| 2 | Plaintext password storage and `==` password comparison | flake8 `S105`, bandit `B105` (CWE-256) |
| 3 | Missing API authentication — `require_api_key()` always returned `None` | Code review (CWE-306); log shows admin endpoints called without credentials |
| 4 | Broken authorization — `require_role()` always returned `True` | Code review (CWE-862) |
| 5 | Database errors returned to the client verbatim (`str(e)`) | Code review (CWE-209) |
| 6 | Malformed rental-form input raised unhandled `KeyError` / `ValueError` | Code review; log shows a related unhandled `TypeError` |

### Risks

- Anyone with read access to the code or its history obtains working secrets; a known
  session key allows forged session cookies.
- Any leak of the user store exposes every password directly.
- Any network client can read all rental records (including SSN fields), list users, and
  delete accounts.
- Error responses reveal database structure, and bad input produces HTTP 500 failures.

## Solution

### Secret management
- `FLASK_SECRET_KEY`, `RENTAL_API_KEY`, `DB_USER` and `DB_PASSWORD` are read from
  environment variables.
- If `FLASK_SECRET_KEY` is unset, a random key is generated with `secrets.token_hex(32)` —
  there is no hardcoded fallback.
- Startup output reports only whether an API key is configured, never its value.

### Password storage
- `USERS_DB` stores only `password_hash` values: salted PBKDF2-HMAC-SHA256 with 600,000
  iterations, generated with Werkzeug's `generate_password_hash`.
- `verify_password()` checks credentials with `check_password_hash` for both the API
  (`POST /api/v1/authenticate`) and the web login. Unknown usernames are checked against a
  dummy hash so they take about as long as a wrong password.

### API authentication
- `require_api_key()` accepts a key only from the `Authorization: Bearer <key>` header;
  keys in the query string are ignored (CWE-598).
- Keys are compared with `hmac.compare_digest` against every user, without an early exit.
- Unauthenticated requests receive **HTTP 401** with `WWW-Authenticate: Bearer`.

### Role-based authorization
- `require_role()` enforces `guest < user < admin` and denies unknown users or roles by
  default. Insufficient privilege returns **HTTP 403**.

| Endpoint | Rule |
|---|---|
| `GET /api/v1/admin/users`, `DELETE /api/v1/admin/delete_user` | `admin` only |
| `GET /api/v1/rentals` | non-admins see only their own rentals |
| `POST /api/v1/rentals` | `user` or higher; the rental is owned by the authenticated caller |
| `GET /api/v1/user` | callers may read only their own record unless `admin` |

### Error handling and input handling
- `get_user_data()` catches `sqlite3.Error` specifically, logs details server-side with
  `app.logger.exception`, and returns a generic `Internal server error` (HTTP 500).
- `rent_equipment()` catches `KeyError`, `ValueError` and `TypeError` from bad form input,
  logs a warning without echoing the input, and returns the form with HTTP 400 and a
  user-facing message.
- Type checks (`isinstance`) on credential and role inputs, and allowlists (known equipment
  types, known roles, the `Bearer` scheme) reject malformed values before use.

More detail: [`docs/security-hardening.md`](docs/security-hardening.md).

## Testing

```bash
pip install -r requirements.txt
python -m pytest test_run.py -v        # Windows: py -m pytest test_run.py -v
python -m pytest test_run.py -v -s     # also prints a PASS message per test
```

| Test | Verifies |
|---|---|
| `test_general_vuln_1_hardcoded_secrets_remediated` | Secrets come from the environment; when unset, the session key is random (not the old literal) and other secrets are `None` |
| `test_general_vuln_2_plaintext_passwords_remediated` | No plaintext `password` field; hashes are PBKDF2-SHA256; correct password → 200, wrong password → 401 |
| `test_api_vuln_1_authentication_required` | Missing key, invalid key, and key-in-URL → 401; valid Bearer key → 200 |
| `test_api_vuln_2_authorization_enforced` | `user` and `guest` → 403 on admin endpoints (no deletion occurs); `admin` → 200 |

As a negative control, the same tests were run against `app_student.py`; all four fail
(e.g. `assert 200 == 401`), confirming they detect the original weaknesses.
Tests run automatically on every push and pull request
([`.github/workflows/tests.yml`](.github/workflows/tests.yml)).

## Running locally

```bash
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"   # optional
python app_solution.py          # http://localhost:5000
```

`start.sh` / `start.bat` install dependencies and start the hardened app; `stop.sh` /
`stop.bat` stop it. The sample accounts (`admin`, `alice`, `bob`, `charlie`) and their API
keys are **demonstration values** — see [`SECURITY.md`](SECURITY.md).

Example request:

```bash
curl -H "Authorization: Bearer <api-key>" http://localhost:5000/api/v1/rentals
```

## Known limitations

This project addresses the issues above; it is a demonstration, not a production-ready
service. Remaining weaknesses are marked `KNOWN ISSUE` in `app_solution.py`:

- `get_user_data()` still builds its SQL query by string concatenation (bandit `B608`);
  it should use a parameterized query.
- No rate limiting or account lockout on authentication (`check_rate_limit()` is a stub).
- Rental records still contain SSN fields; the user lookup can return API keys and hashes.
- Rental `days` is not range-checked, and the search endpoint echoes its input unescaped.
- The development entry point runs with `debug=True` (bandit `B201`) over plain HTTP.
  A deployment would need debug disabled and TLS terminated in front of the app.
- Users, keys and rentals are in-memory sample data.

## Project structure

```
.
├── .github/workflows/tests.yml   # CI: pytest on push / pull request
├── app_solution.py               # hardened application
├── app_student.py                # original vulnerable baseline (reference only)
├── test_run.py                   # security regression tests
├── templates/                    # Jinja templates for the web UI
├── docs/
│   ├── security-hardening.md     # findings, fixes, verification, references
│   └── baseline/                 # flake8 / bandit output and sample traffic log
├── requirements.txt
├── start.sh / start.bat / stop.sh / stop.bat
└── SECURITY.md
```
