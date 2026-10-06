"""
Security regression tests for the hardened Construction Equipment Rental API.

Each test verifies one remediation in app_solution.py:
  1. Hardcoded secrets        -> configuration from environment variables
  2. Plaintext passwords      -> salted PBKDF2-HMAC-SHA256 hashes
  3. Missing authentication   -> Bearer API key required (HTTP 401 otherwise)
  4. Broken authorization     -> role hierarchy enforced (HTTP 403 otherwise)

Each test prints a PASS message only after all of its assertions succeed.

Run:  py -m pytest test_run.py -v       (add -s to show the PASS messages)
"""

import pytest
import json
import importlib.util
import sys
from pathlib import Path

from werkzeug.security import check_password_hash

from app_solution import app, EQUIPMENT_PRICES, USERS_DB

APP_PATH = Path(__file__).with_name("app_solution.py")

# Values that were hardcoded / stored in plaintext in the original app_student.py
ORIGINAL_SECRET_KEY = "supersecretkeyforflasksessions"
ORIGINAL_PLAINTEXT_PASSWORDS = {
    "admin": "admin123", "alice": "alice456", "bob": "bob789", "charlie": "charlie000",
}


# ------------------------------------------------------------
# Test fixture and helpers
# ------------------------------------------------------------

@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def load_fresh_app(module_name, monkeypatch):
    """Import a separate copy of app_solution.py so it reads the current environment."""
    spec = importlib.util.spec_from_file_location(module_name, APP_PATH)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def bearer(username):
    """Authorization header carrying the given user's API key."""
    return {"Authorization": f"Bearer {USERS_DB[username]['api_key']}"}


# ============================================================
# GENERAL SECURITY TESTS (secrets and password storage)
# ============================================================

# ------------------------------------------------------------
# Test 1 of 4 (General Security): Hardcoded Secrets Remediation
# Verifies that secrets are no longer hardcoded.
# ------------------------------------------------------------

def test_general_vuln_1_hardcoded_secrets_remediated(monkeypatch):
    """Secrets are read from environment variables, with no hardcoded fallback."""
    # Secrets supplied through the environment are the ones the app uses.
    monkeypatch.setenv("FLASK_SECRET_KEY", "env-flask-key-for-test")
    monkeypatch.setenv("RENTAL_API_KEY", "env-api-key-for-test")
    monkeypatch.setenv("DB_PASSWORD", "env-db-password-for-test")
    configured = load_fresh_app("app_solution_env_set", monkeypatch)
    assert configured.app.secret_key == "env-flask-key-for-test"
    assert configured.API_KEY == "env-api-key-for-test"
    assert configured.DB_PASSWORD == "env-db-password-for-test"

    # With nothing configured, no embedded secret is used as a fallback.
    for name in ("FLASK_SECRET_KEY", "RENTAL_API_KEY", "DB_USER", "DB_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    first = load_fresh_app("app_solution_env_unset_1", monkeypatch)
    second = load_fresh_app("app_solution_env_unset_2", monkeypatch)
    assert first.app.secret_key != ORIGINAL_SECRET_KEY
    assert len(first.app.secret_key) == 64            # secrets.token_hex(32)
    assert first.app.secret_key != second.app.secret_key   # random, not fixed
    assert first.API_KEY is None and first.DB_PASSWORD is None
    print("\nPASS [General 1 - Hardcoded secrets]: secret key, API key and DB password "
          "are read from environment variables; when unset, a random per-process "
          "secret key is generated and the original hardcoded values are never used.")


# ------------------------------------------------------------
# Test 2 of 4 (General Security): Plaintext Password Remediation
# Verifies that passwords are hashed, not stored in plaintext.
# ------------------------------------------------------------

def test_general_vuln_2_plaintext_passwords_remediated(client):
    """Passwords are stored only as salted hashes and login checks the hash."""
    for username, plaintext in ORIGINAL_PLAINTEXT_PASSWORDS.items():
        record = USERS_DB[username]
        assert "password" not in record, f"{username} still has a plaintext password"
        assert record["password_hash"].startswith("pbkdf2:sha256:600000$")
        assert plaintext not in record["password_hash"]
        assert check_password_hash(record["password_hash"], plaintext)

    valid = client.post("/api/v1/authenticate",
                        json={"username": "alice", "password": "alice456"})
    invalid = client.post("/api/v1/authenticate",
                          json={"username": "alice", "password": "wrong-password"})
    assert valid.status_code == 200
    assert valid.get_json()["api_key"] == USERS_DB["alice"]["api_key"]
    assert invalid.status_code == 401
    print("\nPASS [General 2 - Plaintext passwords]: all 4 users store only PBKDF2-SHA256 "
          "hashes (no plaintext field); correct password authenticates (200), "
          "wrong password is rejected (401).")


# ============================================================
# API SECURITY TESTS (authentication and authorization)
# ============================================================

# ------------------------------------------------------------
# Test 3 of 4 (API Security): API Authentication Remediation
# Verifies that protected endpoints require authentication.
# ------------------------------------------------------------

def test_api_vuln_1_authentication_required(client):
    """Protected endpoint requires a valid API key in the Authorization header."""
    alice_key = USERS_DB["alice"]["api_key"]
    no_key = client.get("/api/v1/rentals")
    wrong_key = client.get("/api/v1/rentals",
                           headers={"Authorization": "Bearer not-a-real-key"})
    key_in_url = client.get(f"/api/v1/rentals?api_key={alice_key}")
    valid_key = client.get("/api/v1/rentals", headers=bearer("alice"))

    assert no_key.status_code == 401, f"Expected 401, got {no_key.status_code}"
    assert wrong_key.status_code == 401, f"Expected 401, got {wrong_key.status_code}"
    assert key_in_url.status_code == 401, "API key in the URL must not be accepted"
    assert valid_key.status_code == 200, f"Expected 200, got {valid_key.status_code}"
    print("\nPASS [API 1 - Authentication]: /api/v1/rentals rejects missing, invalid and "
          "URL query-string API keys with 401 Unauthorized, and accepts a valid "
          "Bearer key (200).")


# ------------------------------------------------------------
# Test 4 of 4 (API Security): Authorization / Least Privilege Remediation
# Verifies that role-based access control is enforced.
# ------------------------------------------------------------

def test_api_vuln_2_authorization_enforced(client):
    """Admin-only endpoints deny non-admin users (403) and allow admins."""
    user_list = client.get("/api/v1/admin/users", headers=bearer("alice"))
    user_delete = client.delete("/api/v1/admin/delete_user?username=bob",
                                headers=bearer("alice"))
    guest_list = client.get("/api/v1/admin/users", headers=bearer("charlie"))
    admin_list = client.get("/api/v1/admin/users", headers=bearer("admin"))

    assert user_list.status_code == 403, f"Expected 403, got {user_list.status_code}"
    assert user_delete.status_code == 403, f"Expected 403, got {user_delete.status_code}"
    assert "bob" in USERS_DB, "Non-admin delete must not remove the user"
    assert guest_list.status_code == 403, f"Expected 403, got {guest_list.status_code}"
    assert admin_list.status_code == 200, f"Expected 200, got {admin_list.status_code}"
    print("\nPASS [API 2 - Authorization]: regular user and guest are denied the admin "
          "endpoints with 403 Forbidden (bob was NOT deleted); the admin role is "
          "allowed (200).")
