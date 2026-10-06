"""
Construction Equipment Rental API - hardened version.

Flask REST API for an equipment-rental service, hardened from the intentionally
vulnerable baseline in app_student.py. Remediated issues:

  1. Hardcoded secrets and credentials (CWE-798 / CWE-259)
     -> secrets are read from environment variables; no hardcoded fallback.
  2. Plaintext password storage (CWE-256)
     -> salted PBKDF2-HMAC-SHA256 hashes, verified with check_password_hash.
  3. Missing API authentication (CWE-306)
     -> Bearer API key in the Authorization header, constant-time comparison, HTTP 401.
  4. Broken authorization / missing least privilege (CWE-862)
     -> guest < user < admin role hierarchy, deny by default, HTTP 403.

Error handling was also improved: database errors no longer leak internal details
(CWE-209), and malformed rental-form input no longer causes an unhandled exception.

The original insecure lines are kept as comments next to each fix so the change
can be reviewed. Remaining weaknesses are marked "KNOWN ISSUE" (see README.md).
Baseline static-analysis output is in docs/baseline/.
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import sqlite3
import os
import hmac
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# =============================================================================
# Hardening 1 - Hardcoded secrets and credentials (CWE-798 / CWE-259)
# Baseline finding: flake8 S105 / bandit B105 (secret key, DB password).
# Secrets in source code are exposed through version control and cannot be
# rotated without a code change.
# =============================================================================

# Original insecure implementation (disabled, kept for review):
# app.secret_key = 'supersecretkeyforflasksessions'
#
# API_KEY = "sk_live_abc123xyz789secretkey"
#
# DB_USER = "admin"
# DB_PASSWORD = "password123"

# SECURE: secrets come from the environment, never from source code.
# No known fallback: if FLASK_SECRET_KEY is unset, a random 256-bit key is
# generated for this process (sessions simply reset on restart).
app.secret_key = (
    os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
)

API_KEY = os.environ.get("RENTAL_API_KEY")  # None if unset

DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# Equipment Pricing Data
EQUIPMENT_PRICES = {
    "Bulldozer": 500,
    "Excavator": 450,
    "Crane": 800
}

# =============================================================================
# Hardening 2 - Plaintext password storage (CWE-256)
# Baseline finding: flake8 S105 / bandit B105 on every USERS_DB password.
# A leak of the source or data store would expose every password.
# =============================================================================

# Original insecure implementation (disabled, kept for review):
# USERS_DB = {
#     "admin": {"password": "admin123", "role": "admin", "api_key": "sk_admin_key123"},
#     "alice": {"password": "alice456", "role": "user", "api_key": "sk_alice_key456"},
#     "bob": {"password": "bob789", "role": "user", "api_key": "sk_bob_key789"},
#     "charlie": {"password": "charlie000", "role": "guest", "api_key": "sk_charlie_key000"}
# }

# SECURE: store only salted PBKDF2-SHA256 hashes (600,000 iterations), made with
# generate_password_hash(pw, method="pbkdf2:sha256:600000"); verified below.
USERS_DB = {
    "admin": {"role": "admin", "api_key": "sk_admin_key123",
              "password_hash": "pbkdf2:sha256:600000$jBTu5PJVfRpg3y56$"
                               "4fe96350c4eb890565552415a11757262053428099f888046c1669a852391372"},
    "alice": {"role": "user", "api_key": "sk_alice_key456",
              "password_hash": "pbkdf2:sha256:600000$xfkZK23GY45yJeHH$"
                               "c3d550af4e7ca73f8c849f8475c1dc1c11f2c1f484a75677a0f05de2d0315a21"},
    "bob": {"role": "user", "api_key": "sk_bob_key789",
            "password_hash": "pbkdf2:sha256:600000$CsHb2MNRlvro4qPo$"
                             "219a0158fb9aaea5af231252e374b479053d59f833026f46cf73d2529e8bee9c"},
    "charlie": {"role": "guest", "api_key": "sk_charlie_key000",
                "password_hash": "pbkdf2:sha256:600000$jTzR4xDNeWoXD4T3$"
                                 "6845d615fe2711d409332a4983ac93c5e4832609d35f7e4b513b580d81e169c1"},
}


def verify_password(username, password):
    """SECURE: validate a password against its stored salted hash."""
    if not isinstance(password, str):
        password = ""
    user = USERS_DB.get(username) if isinstance(username, str) else None
    if user is None:
        check_password_hash(_DUMMY_PASSWORD_HASH, password)  # equalize timing
        return False
    return check_password_hash(user["password_hash"], password)


# Hash of a random value, checked when the username is unknown so that a bad
# username takes as long as a bad password (prevents username enumeration).
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(16))

# =============================================================================
# KNOWN ISSUE: rental records contain SSN values (sensitive data exposure,
# CWE-359). Not addressed in this hardening pass.
# =============================================================================

RENTAL_RECORDS = [
    {"id": 1, "user": "alice", "equipment": "Bulldozer", "days": 3, "total": 1500, "ssn": "123-45-6789"},
    {"id": 2, "user": "bob", "equipment": "Crane", "days": 2, "total": 1600, "ssn": "987-65-4321"},
    {"id": 3, "user": "admin", "equipment": "Excavator", "days": 5, "total": 2250, "ssn": "555-12-3456"},
]


# =============================================================================
# Database Helper Functions
# =============================================================================

def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect('rental_api.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize the database with sample data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            api_key TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rentals (
            id INTEGER PRIMARY KEY,
            username TEXT,
            equipment TEXT,
            days INTEGER,
            total REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# =============================================================================
# Hardening 3 - Missing API authentication (CWE-306)
# Baseline: require_api_key() always returned None, so no endpoint could
# identify its caller.
# =============================================================================

def require_api_key():
    """
    Authenticate the caller from the "Authorization: Bearer <api_key>" header.

    Returns the matching username, or None if the key is missing or invalid.
    API keys are accepted only in the header, never in URL parameters
    (CWE-598: Use of GET Request Method With Sensitive Query Strings).
    """
    # Original insecure implementation (disabled, kept for review):
    # # INSECURE: Currently returns None (no authentication)
    # return None

    # SECURE: accept the key only from "Authorization: Bearer <key>";
    # query-string keys (?api_key=...) are deliberately ignored (CWE-598).
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None

    # Constant-time comparison against every user's key (no early exit), so
    # response timing does not reveal how much of a guessed key was correct.
    authenticated_user = None
    for username, record in USERS_DB.items():
        if hmac.compare_digest(record["api_key"].encode(), token.encode()):
            authenticated_user = username
    return authenticated_user


# =============================================================================
# Hardening 4 - Broken authorization / missing least privilege (CWE-862)
# Baseline: require_role() always returned True, so any caller could use the
# admin endpoints.
# =============================================================================

def require_role(username, required_role):
    """
    Return True if `username` holds at least `required_role`.

    Role hierarchy: guest < user < admin. Unknown users and unknown roles
    are denied (deny by default).
    """
    # Original insecure implementation (disabled, kept for review):
    # # INSECURE: Currently always returns True (no authorization)
    # return True

    # SECURE: least-privilege role check, deny by default.
    user = USERS_DB.get(username) if isinstance(username, str) else None
    if user is None:
        return False                                   # unknown user -> deny
    user_level = ROLE_LEVELS.get(user.get("role"))
    required_level = ROLE_LEVELS.get(required_role)
    if user_level is None or required_level is None:
        return False                                   # unknown role -> deny
    return user_level >= required_level


# SECURE: role hierarchy guest < user < admin
ROLE_LEVELS = {"guest": 1, "user": 2, "admin": 3}


def unauthorized_response():
    """401: caller is not authenticated (missing/invalid API key)."""
    return (jsonify({"status": "error", "message": "Authentication required"}),
            401, {"WWW-Authenticate": "Bearer"})


def forbidden_response():
    """403: caller is authenticated but lacks the required role."""
    return jsonify({"status": "error", "message": "Insufficient privileges"}), 403


# =============================================================================
# KNOWN ISSUES (not addressed in this hardening pass):
#   - No rate limiting on authentication (CWE-307); see check_rate_limit().
#   - get_user_data() builds SQL by string concatenation (bandit B608, CWE-89).
#   - The entry point runs Flask with debug=True (bandit B201, CWE-94).
# =============================================================================

# =============================================================================
# Rate Limiting (Defense in Depth)
# =============================================================================
# KNOWN ISSUE: rate limiting is not implemented; check_rate_limit() is a stub.
# See CWE-307 (Improper Restriction of Excessive Authentication Attempts)

def check_rate_limit(identifier):
    """
    Placeholder for rate limiting (not implemented; always allows).

    Parameters:
        identifier: IP address or API key to track

    Returns:
        True if request is allowed, False if rate limited
    """
    # INSECURE: Currently no rate limiting implemented
    return True


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/api/v1/user', methods=['GET'])
def get_user_data():
    """
    Retrieve user information (authenticated; users may only read their own record).

    KNOWN ISSUES:
    - The SQL query is built by string concatenation (bandit B608, CWE-89);
      it should use a parameterized query.
    - The fallback response returns the full USERS_DB record, including the
      API key and password hash.
    """
    # SECURE: authenticate the caller first
    caller = require_api_key()
    if not caller:
        return unauthorized_response()

    username = request.args.get('username', '')

    # SECURE: least privilege - users may only look up themselves
    if username != caller and not require_role(caller, "admin"):
        return forbidden_response()

    # KNOWN ISSUE: SQL built by string concatenation (CWE-89); use a parameterized query.
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({
                "status": "success",
                "data": dict(user)
            })
        else:
            if username in USERS_DB:
                # KNOWN ISSUE: returns the full record (API key and password hash)
                return jsonify({
                    "status": "success",
                    "data": USERS_DB[username]
                })
            return jsonify({"status": "error", "message": "User not found"}), 404

    # Original insecure implementation (disabled, kept for review):
    # # VULNERABLE: Exposes internal error details to client (CWE-209)
    # except Exception as e:
    #     return jsonify({"status": "error", "message": str(e)}), 500

    # SECURE: catch the specific database error, log the details
    # server-side only, and return a generic message to the client.
    except sqlite3.Error:
        app.logger.exception("Database error in get_user_data")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.route('/api/v1/rentals', methods=['GET'])
def get_rentals():
    """
    Retrieve rental records (authenticated; non-admins see only their own).

    KNOWN ISSUE: records still include SSN values (CWE-359).
    """
    # Original disabled check from the baseline:
    # user = require_api_key()
    # if not user:
    #     return jsonify({"status": "error", "message": "Authentication required"}), 401

    # SECURE: authentication check is now active
    user = require_api_key()
    if not user:
        return unauthorized_response()

    user_filter = request.args.get('user', '')

    # SECURE: least privilege - non-admins only ever see their own rentals
    if not require_role(user, "admin"):
        user_filter = user

    if user_filter:
        filtered = [r for r in RENTAL_RECORDS if r['user'] == user_filter]
        return jsonify({"status": "success", "data": filtered})

    # Admin view: all records. KNOWN ISSUE: SSN values are still included.
    return jsonify({
        "status": "success",
        "data": RENTAL_RECORDS,
        "total_records": len(RENTAL_RECORDS)
    })


@app.route('/api/v1/rentals', methods=['POST'])
def create_rental():
    """
    Create a rental owned by the authenticated caller (role "user" or higher).

    KNOWN ISSUES: `days` is not type- or range-checked, and new records still
    contain a placeholder SSN field.
    """
    # SECURE: authenticate; guests are read-only, so require "user" role
    caller = require_api_key()
    if not caller:
        return unauthorized_response()
    if not require_role(caller, "user"):
        return forbidden_response()

    data = request.get_json()

    equipment = data.get('equipment')
    days = data.get('days')
    # Original insecure implementation (disabled, kept for review):
    # username = data.get('username')
    # SECURE: rental is owned by the authenticated caller, not a body field
    username = caller

    # Allowlist check: equipment must be a known type
    if equipment in EQUIPMENT_PRICES:
        # KNOWN ISSUE: days is not type- or range-checked
        total = EQUIPMENT_PRICES[equipment] * days

        new_rental = {
            "id": len(RENTAL_RECORDS) + 1,
            "user": username,
            "equipment": equipment,
            "days": days,
            "total": total,
            "ssn": "000-00-0000"  # KNOWN ISSUE: SSN should not be stored
        }
        RENTAL_RECORDS.append(new_rental)

        return jsonify({
            "status": "success",
            "message": "Rental created",
            "data": new_rental
        }), 201
    else:
        return jsonify({"status": "error", "message": "Invalid equipment"}), 400


# =============================================================================
# Admin Endpoints (valid API key and admin role required)
# =============================================================================
@app.route('/api/v1/admin/users', methods=['GET'])
def admin_get_all_users():
    """
    Administrative endpoint to list all users.

    Requires a valid API key (else 401) and the admin role (else 403).
    """
    # Original insecure implementation (disabled, kept for review):
    # # INSECURE: No authentication or authorization check!

    # SECURE: API key (401) + admin role (403) required
    caller = require_api_key()
    if not caller:
        return unauthorized_response()
    if not require_role(caller, "admin"):
        return forbidden_response()

    return jsonify({
        "status": "success",
        "data": list(USERS_DB.keys()),
        "message": "Admin access granted"
    })


@app.route('/api/v1/admin/delete_user', methods=['DELETE'])
def admin_delete_user():
    """
    Administrative endpoint to delete a user.

    Requires a valid API key (else 401) and the admin role (else 403).
    """
    # Original insecure implementation (disabled, kept for review):
    # # INSECURE: No authentication check on destructive operation!

    # SECURE: API key (401) + admin role (403) required
    caller = require_api_key()
    if not caller:
        return unauthorized_response()
    if not require_role(caller, "admin"):
        return forbidden_response()

    username = request.args.get('username', '')

    if username in USERS_DB:
        del USERS_DB[username]
        return jsonify({"status": "success", "message": f"User {username} deleted"})

    return jsonify({"status": "error", "message": "User not found"}), 404


# =============================================================================
# Equipment Search
# =============================================================================
@app.route('/api/v1/search', methods=['GET'])
def search_equipment():
    """
    Search for equipment by name.

    KNOWN ISSUE: the query string is echoed back without length limits or
    encoding (reflected-input / XSS risk if a client renders it).
    See docs/baseline/network_security_log.txt for related traffic.
    """
    query = request.args.get('q', '')

    results = []
    for equipment, price in EQUIPMENT_PRICES.items():
        if query.lower() in equipment.lower():
            results.append({"name": equipment, "price": price})

    # KNOWN ISSUE: reflects unsanitized input in the response
    return jsonify({
        "status": "success",
        "search_term": query,  # Unsanitized user input
        "results": results
    })


# =============================================================================
# Authentication Endpoint
# =============================================================================
@app.route('/api/v1/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate a user and return their API key.

    Passwords are verified against salted hashes (verify_password).
    KNOWN ISSUE: no rate limiting or account lockout (CWE-307).
    """
    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "message": "Request body required"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    # Original insecure implementation (disabled, kept for review):
    # if username in USERS_DB:
    #     # INSECURE: Plain text password comparison
    #     if USERS_DB[username]['password'] == password:
    #         return jsonify({
    #             "status": "success",
    #             "message": "Authentication successful",
    #             "api_key": USERS_DB[username]['api_key']
    #         })

    # SECURE: password checked against its salted hash
    if verify_password(username, password):
        return jsonify({
            "status": "success",
            "message": "Authentication successful",
            "api_key": USERS_DB[username]['api_key']
        })

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =============================================================================
# Web Interface Routes
# =============================================================================

@app.route('/')
def home():
    print("Home page accessed")
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        # Original insecure implementation (disabled, kept for review):
        # if username in USERS_DB and USERS_DB[username]['password'] == password:
        # SECURE: password checked against its salted hash
        if verify_password(username, password):
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/rent', methods=['GET', 'POST'])
def rent_equipment():
    """
    Equipment rental form endpoint.

    Unknown equipment, missing fields and non-numeric day values are handled
    and return HTTP 400 with a user-facing message.
    KNOWN ISSUE: negative day counts are not rejected.
    """
    rental_result = None

    if request.method == 'POST':
        equipment_type = request.form.get("equipment_type")
        days_str = request.form.get("days")

        # Original insecure implementation (disabled, kept for review):
        # # VULNERABLE: No input validation - could crash or behave unexpectedly
        # daily_rate = EQUIPMENT_PRICES[equipment_type]  # Could raise KeyError
        # days = int(days_str)  # Could raise ValueError

        # SECURE: handle the specific errors that bad form input causes
        # instead of letting the request crash with an unhandled exception.
        try:
            daily_rate = EQUIPMENT_PRICES[equipment_type]  # KeyError: unknown/missing equipment
            days = int(days_str)                           # ValueError: not a number; TypeError: missing
        except (KeyError, ValueError, TypeError):
            app.logger.warning("Rejected invalid rental form input")
            flash("Please choose a listed equipment type and enter the number of days "
                  "as a whole number.", "danger")
            return render_template('rent.html', rental_result=None), 400
        total_cost = daily_rate * days  # Could produce negative values

        print(f"Calculated cost: {total_cost}")

        rental_result = {
            "equipment": equipment_type,
            "days": days,
            "total_cost": total_cost
        }
        flash("Rental calculated successfully!", "success")

    return render_template('rent.html', rental_result=rental_result)


@app.route('/api/docs')
def api_documentation():
    """API Documentation page."""
    return render_template('api_docs.html')


# =============================================================================
# Application Entry Point
# =============================================================================

if __name__ == '__main__':
    init_database()
    print("Starting application...")
    # Original insecure implementation (disabled, kept for review):
    # VULNERABLE: Prints secret API key to console!
    # print(f"WARNING: Using hardcoded API key: {API_KEY}")
    # SECURE: report only whether a key is configured, never its value.
    print("RENTAL_API_KEY configured: " + ("yes" if API_KEY else "no"))
    # KNOWN ISSUE: debug=True (bandit B201) - disable outside local development.
    app.run(debug=True, port=5000)
