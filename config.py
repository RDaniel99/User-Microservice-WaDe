import os
from datetime import timedelta


class Config(object):
    # Set a secret key for the session
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'

    # Set up Flask-JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'your-jwt-secret-key'
    
    # Set up expiration time for JWT Tokens
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)

    # Set up the database
    DATABASE_URI = os.environ.get('DATABASE_URI') or 'users.db'
