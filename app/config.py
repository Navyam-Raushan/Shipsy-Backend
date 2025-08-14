# app/config.py
# app/config.py
import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
load_dotenv(os.path.join(BASE_DIR, ".env"))
# load_dotenv()
print("DEBUG MONGO_URI from env:", os.getenv("MONGO_URI"))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt_secret_here")
    REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET", "refresh_secret_here")

    MONGO_URI = os.getenv("MONGODB_URL", "")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(',')

