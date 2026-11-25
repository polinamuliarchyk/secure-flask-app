import os

basedir = os.path.abspath(os.path.dirname(__file__))

def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

class Config:
    SECRET_KEY = _require('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

    GRAYLOG_API_URL = os.getenv('GRAYLOG_API_URL')
    GRAYLOG_API_TOKEN = os.getenv('GRAYLOG_API_TOKEN')
    
    ADMIN_USERNAME = _require('ADMIN_USERNAME')
    ADMIN_PASSWORD = _require('ADMIN_PASSWORD')
    ADMIN_EMAIL = _require('ADMIN_EMAIL')
    FERNET_KEY = _require('FERNET_KEY')
