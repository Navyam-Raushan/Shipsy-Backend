# app/routes/auth_routes.py
from flask import Blueprint, jsonify, g
from app.middlewares.jwt import jwt_auth_middleware, refresh_token_handler

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token_route():
    """
    Refreshes an access token using a valid refresh token provided in the request body.
    The logic is handled by the imported refresh_token_handler.
    """
    return refresh_token_handler()

@auth_bp.route('/verify-token', methods=['POST'])
@jwt_auth_middleware
def verify_token_route():
    """
    Verifies the validity of an access token from the 'Authorization: Bearer <token>' header.
    If this function is reached, the middleware has successfully validated the token.
    """
    # g.user is populated by the jwt_auth_middleware upon successful verification.
    return jsonify({"message": "Token is valid.", "user": g.user}), 200