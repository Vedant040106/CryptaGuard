import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Secret Key used for session security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super_secret_cryptaguard_key_99'
    
    # AI Configuration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') or 'YOUR_GEMINI_API_KEY'

    # Database Configuration
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'cryptaguard')
