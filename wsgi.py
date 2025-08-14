from app import create_app
from dotenv import load_dotenv

# Load environment variables from .env file for the production server
load_dotenv()

# The WSGI server will look for this 'application' variable
application = create_app()