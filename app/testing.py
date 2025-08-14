import os
from dotenv import load_dotenv
from app.config import Config

# Load environment variables from .env file
load_dotenv()


# Now you can safely read
MONGO_URI = os.getenv("MONGODB_URL")
if not MONGO_URI:
    raise ValueError("MONGO_URI is not set. Please check your .env file.")
else:
    print(MONGO_URI)