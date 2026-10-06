# Security Policy

## Scope

This repository demonstrates security hardening of a small Flask API. It is intended for
learning and code review, **not** for production deployment.

- `app_student.py` is the original baseline and is **intentionally vulnerable**. It is kept
  only so the fixes can be compared with the code they replace. Do not deploy or expose it.
- `app_solution.py` is the hardened version. It still has the known limitations listed in
  the [README](README.md#known-limitations), and it starts Flask's development server with
  `debug=True` over plain HTTP.

## Demonstration credentials

All credentials in this repository are fake sample data:

- The sample users (`admin`, `alice`, `bob`, `charlie`), their passwords and their API keys
  (`sk_<user>_key…`) exist only for local testing and the test suite.
- The hardcoded secret key, `sk_live_…` API key and database password in `app_student.py`
  are placeholder values that illustrate the hardcoded-secret weakness. They do not grant
  access to any real system.

Real secrets must be supplied through environment variables (`FLASK_SECRET_KEY`,
`RENTAL_API_KEY`, `DB_USER`, `DB_PASSWORD`) and must never be committed.

## Reporting a problem

If you find a security issue in the hardened code that is not already listed as a known
limitation, please open a GitHub issue describing the problem and how to reproduce it.
Do not include real credentials or personal data in the report.
