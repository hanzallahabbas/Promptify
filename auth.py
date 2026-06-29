# =============================================================
#  PROMPTIFY — Authentication Routes
#  File: auth.py
# =============================================================
#
#  HOW THE AUTH SYSTEM WORKS:
#  ──────────────────────────
#  1. User registers  → password is HASHED with bcrypt
#                     → stored in MongoDB (we never store plain passwords)
#
#  2. User logs in    → bcrypt checks the password against the hash
#                     → we create a JWT token (a signed string)
#                     → frontend stores the token in localStorage
#
#  3. Protected routes → frontend sends token in every request header
#                      → Flask verifies the token before processing
#
#  WHAT IS BCRYPT?
#  ───────────────
#  bcrypt is a hashing algorithm designed specifically for passwords.
#  It's one-way — you can't reverse a hash to get the password back.
#  Even if someone steals the database, they can't read passwords.
#
#  Example:
#    "john123"  →  bcrypt  →  "$2b$12$EixZaYVK1fsbw1ZfbX3OXe.PmYul..."
#    The hash is different every time, but bcrypt.check() still works.
#
#  WHAT IS JWT?
#  ─────────────
#  JWT = JSON Web Token. It's a signed string that proves who you are.
#  Structure: header.payload.signature
#    header   = {"alg": "HS256"}
#    payload  = {"email": "john@example.com", "exp": 1234567890}
#    signature= HMAC(header+payload, SECRET_KEY)
#
#  The server signs it with a secret key.
#  The frontend stores it and sends it back with every request.
#  The server verifies the signature — if valid, you're authenticated.
#
# =============================================================

from flask import Blueprint, request, jsonify
import bcrypt
import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from pymongo.errors import DuplicateKeyError

from database import users_col, history_col
from models import User, PromptHistory

auth_bp = Blueprint('auth', __name__)

# Secret key for signing JWT tokens
# In production this must be a long random string stored in .env
JWT_SECRET  = os.getenv('JWT_SECRET', 'promptify-secret-change-this-in-production')
JWT_EXPIRES = 24  # hours before token expires


# =============================================================
#  HELPER: Create JWT token
# =============================================================

def create_token(email, name):
    """
    Creates a signed JWT token for a logged-in user.
    Token expires after JWT_EXPIRES hours.
    """
    payload = {
        'email': email,
        'name':  name,
        'exp':   datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRES),
        'iat':   datetime.now(timezone.utc),   # issued at
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


# =============================================================
#  HELPER: Verify token (decorator for protected routes)
# =============================================================

def token_required(f):
    """
    Decorator that protects routes.
    Add @token_required above any route that needs login.

    How it works:
      1. Reads "Authorization: Bearer <token>" from request header
      2. Decodes and verifies the JWT token
      3. If valid — calls the route with the user's email
      4. If invalid / expired — returns 401 Unauthorized
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from header: "Authorization: Bearer <token>"
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'No token provided. Please log in.'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user_email = data['email']
            current_user_name  = data['name']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please log in again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token. Please log in.'}), 401

        # Pass user info into the route function
        return f(current_user_email, current_user_name, *args, **kwargs)

    return decorated


# =============================================================
#  ROUTE: POST /register
# =============================================================
#
#  Request body:
#    { "name": "Sara Ahmed", "email": "sara@gmail.com", "password": "pass123" }
#
#  What it does:
#    1. Validates input
#    2. Hashes the password with bcrypt
#    3. Saves user to MongoDB
#    4. Returns success + JWT token (so user is auto-logged in)

@auth_bp.route('/register', methods=['POST'])
def register():
    if users_col is None:
        return jsonify({'error': 'Database is currently unavailable. Please try again later.'}), 503

    data = request.get_json()

    # ── Validate input ────────────────────────────────────────
    name     = (data.get('name', '') or '').strip()
    email    = (data.get('email', '') or '').strip().lower()
    password = (data.get('password', '') or '').strip()

    is_valid, err_msg = User.validate_registration_input(name, email, password)
    if not is_valid:
        return jsonify({'error': err_msg}), 400

    # ── Hash password ─────────────────────────────────────────
    hashed_password = User.hash_password(password)

    # ── Save to MongoDB ───────────────────────────────────────
    user = User(name, email, hashed_password)

    try:
        users_col.insert_one(user.to_dict())
    except DuplicateKeyError:
        return jsonify({'error': 'An account with this email already exists.'}), 409

    # ── Return token (auto-login after register) ──────────────
    token = create_token(email, name)
    return jsonify({
        'message': 'Account created successfully.',
        'token':   token,
        'name':    name,
        'email':   email,
    }), 201


# =============================================================
#  ROUTE: POST /login
# =============================================================
#
#  Request body:
#    { "email": "sara@gmail.com", "password": "pass123" }
#
#  What it does:
#    1. Finds user by email in MongoDB
#    2. Uses bcrypt.checkpw() to verify the password against the hash
#    3. Returns JWT token if correct

@auth_bp.route('/login', methods=['POST'])
def login():
    if users_col is None:
        return jsonify({'error': 'Database is currently unavailable. Please try again later.'}), 503

    data = request.get_json()

    email    = (data.get('email', '') or '').strip().lower()
    password = (data.get('password', '') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    # ── Find user ─────────────────────────────────────────────
    user_doc = users_col.find_one({'email': email})
    if not user_doc:
        return jsonify({'error': 'No account found with this email.'}), 404

    user = User.from_dict(user_doc)

    # ── Check password ────────────────────────────────────────
    password_correct = User.verify_password(password, user.password)

    if not password_correct:
        return jsonify({'error': 'Incorrect password.'}), 401

    # ── Return token ──────────────────────────────────────────
    token = create_token(email, user.name)
    return jsonify({
        'message': 'Login successful.',
        'token':   token,
        'name':    user.name,
        'email':   email,
    }), 200


# =============================================================
#  ROUTE: GET /me
#  Returns the logged-in user's info (protected route)
# =============================================================

@auth_bp.route('/me', methods=['GET'])
@token_required
def get_me(current_user_email, current_user_name):
    return jsonify({
        'email': current_user_email,
        'name':  current_user_name,
    })


# =============================================================
#  ROUTE: GET /history
#  Returns this user's past scans (protected)
# =============================================================

@auth_bp.route('/history', methods=['GET'])
@token_required
def get_history(current_user_email, current_user_name):
    if history_col is None:
        return jsonify({'error': 'Database is currently unavailable. Please try again later.'}), 503

    records = list(
        history_col
        .find({'user_email': current_user_email}, {'_id': 0})
        .sort('timestamp', -1)   # newest first
        .limit(50)               # max 50 records
    )
    return jsonify({'history': records})


# =============================================================
#  ROUTE: DELETE /history
#  Clears this user's history (protected)
# =============================================================

@auth_bp.route('/history', methods=['DELETE'])
@token_required
def clear_history(current_user_email, current_user_name):
    if history_col is None:
        return jsonify({'error': 'Database is currently unavailable. Please try again later.'}), 503

    result = history_col.delete_many({'user_email': current_user_email})
    return jsonify({'message': f'Deleted {result.deleted_count} records.'})
