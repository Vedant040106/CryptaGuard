import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Session security
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # AI configuration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

    # Database configuration (Railway / Cloud MySQL)
    MYSQL_HOST = os.environ.get('MYSQL_HOST')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD')
    MYSQL_DB = os.environ.get('MYSQL_DATABASE')