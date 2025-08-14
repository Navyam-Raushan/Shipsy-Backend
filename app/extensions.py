# app/extensions.py
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import logging

mongo = PyMongo()
bcrypt = Bcrypt()

def init_db(app):
    """Connect to MongoDB and set up event handlers."""
    try:
        mongo.init_app(app, uri=app.config["MONGO_URI"])
        logging.info("✅ Connected to MongoDB successfully")
    except Exception as e:
        logging.error(f"❌ MongoDB connection error: {e}")
        raise e
