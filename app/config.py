# app/config.py
# app/config.py
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt_secret_here")
    REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET", "refresh_secret_here")
    MONGO_URI = "mongodb+srv://raushan:raushan123@shipsy-cluster.1keccqa.mongodb.net/shipsy-db?retryWrites=true&w=majority&appName=shipsy-cluster"

    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(',')

