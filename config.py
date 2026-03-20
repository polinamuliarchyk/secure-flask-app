import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'secret')
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

    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpassword')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')

    FERNET_KEY = os.getenv('FERNET_KEY')
