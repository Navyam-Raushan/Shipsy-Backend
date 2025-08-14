# app/__init__.py
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from app.config import Config
from app.extensions import mongo, bcrypt, init_db
import logging

def register_extensions(app):
    """Initialize and register Flask extensions."""
    CORS(app, origins=app.config["CORS_ORIGINS"], supports_credentials=True)
    bcrypt.init_app(app)
    init_db(app)

def register_blueprints(app):
    """Import and register blueprints."""
    from app.routes.customer_routes import customer_bp
    from app.routes.admin_routes import admin_bp
    from app.routes.auth_routes import auth_bp

    app.register_blueprint(customer_bp, url_prefix="/api/v1/customer")
    app.register_blueprint(admin_bp, url_prefix="/api/v1/admin")
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")

def create_app():
    """Application factory function."""
    load_dotenv()

    # Configure basic logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    app = Flask(__name__)
    app.config.from_object(Config)

    register_extensions(app)
    register_blueprints(app)

    # Add a simple root route for health check
    @app.route('/')
    def index():
        return jsonify({"status": "online", "message": "Welcome to the Beauty Product Management API!"})

    return app
