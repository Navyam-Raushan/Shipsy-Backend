# app/config.py
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt_secret_here")
    REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET", "refresh_secret_here")
    MONGO_URI = os.getenv("MONGODB_URL", "mongodb://localhost:27017/yourdb")
