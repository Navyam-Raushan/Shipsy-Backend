# app/middlewares/jwt.py
from flask import request, jsonify, current_app, g
import jwt
from functools import wraps
import logging
import datetime
from datetime import timezone

# check post request with these credentials
# {
#     "name": "main_admin",
#     "password": "a-strong-password-123"
# }


def jwt_auth_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get("Authorization", None)
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authorization header is missing or malformed."}), 401

            token = auth_header.split(" ")[1]
            secret = current_app.config['JWT_SECRET']
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            g.user = decoded  # Use Flask's g object to store request-specific data

            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            logging.error("JWT verification error")
            return jsonify({"error": "Invalid or expired token."}), 401
    return decorated_function

def generate_access_token(user_data):
    """Generates a short-lived access token."""
    payload = {
        **user_data,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=180),
        "iat": datetime.datetime.now(timezone.utc)
    }
    secret = current_app.config['JWT_SECRET']
    return jwt.encode(payload, secret, algorithm="HS256")

def generate_refresh_token(user_data):
    """Generates a long-lived refresh token."""
    payload = {
        **user_data,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(days=7),
        "iat": datetime.datetime.now(timezone.utc)
    }
    secret = current_app.config['REFRESH_TOKEN_SECRET']
    return jwt.encode(payload, secret, algorithm="HS256")

def refresh_token_handler():
    data = request.get_json(silent=True)
    if not data or "token" not in data:
        return jsonify({"error": "Refresh token is missing."}), 401

    try:
        token = data["token"]
        secret = current_app.config['REFRESH_TOKEN_SECRET']
        decoded = jwt.decode(token, secret, algorithms=["HS256"])

        # Prepare payload for the new access token, excluding old expiry info
        # Note: 'roll' might be a typo for 'role'.
        new_payload = {
            key: value for key, value in decoded.items() if key not in ('exp', 'iat')
        }
        new_access_token = generate_access_token(new_payload)
        return jsonify({"accessToken": new_access_token}), 200
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid or expired refresh token."}), 403

def verify_access_token(token):
    try:
        secret = current_app.config['JWT_SECRET']
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None
