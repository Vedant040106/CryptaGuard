import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Session security
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_HTTPONLY = True   # Prevent JS access to session cookie (XSS defense)
    SESSION_COOKIE_SAMESITE = 'Lax' # CSRF protection
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in prod

    # AI configuration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

    # Database configuration (Railway / Cloud MySQL)
    MYSQL_HOST = os.environ.get('MYSQL_HOST')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD')
    MYSQL_DB = os.environ.get('MYSQL_DATABASE')