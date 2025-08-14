# app/extensions.py
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import logging
from pymongo.errors import OperationFailure

mongo = PyMongo()
bcrypt = Bcrypt()

def init_db(app):
    """Connect to MongoDB and set up event handlers."""
    mongo_uri = app.config.get("MONGO_URI")
    
    # Add a check to ensure the MONGO_URI is present and not empty.
    # This prevents the 'NoneType' error if the .env variable is missing or empty.
    if not mongo_uri:
        logging.error("FATAL: MONGO_URI is not set in the configuration. Application cannot start.")
        raise ValueError("MONGO_URI is not set. Please check your .env file and configuration.")

    try:
        mongo.init_app(app, uri=mongo_uri)
        # After successful connection, ensure database indexes are created.
        # Using app_context to make sure the 'mongo' object is ready.
        with app.app_context():
            try:
                # Ensure a unique index on the 'name' field of the 'products' collection
                mongo.db.products.create_index("name", unique=True)
                logging.info("✅ Ensured unique index on 'products.name'")
            except OperationFailure as e:
                # This is not fatal if the index already exists, but good to log.
                logging.warning(f"Could not create unique index on products.name (it may already exist): {e}")
        logging.info("✅ Connected to MongoDB successfully")
    except Exception as e:
        logging.error(f"❌ MongoDB connection error during init: {e}")
        raise e
