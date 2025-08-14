# app/__init__.py
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from app.config import Config
from app.extensions import mongo, bcrypt, init_db

def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, origins=["http://localhost:5173"])

    bcrypt.init_app(app)
    init_db(app)

    # Import & register blueprints later
    from app.routes.customer_routes import customer_bp
    from app.routes.admin_routes import admin_bp
    from app.routes.auth_routes import auth_bp

    app.register_blueprint(customer_bp, url_prefix="/api/v1/customer")
    app.register_blueprint(admin_bp, url_prefix="/api/v1/admin")
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")

    return app
