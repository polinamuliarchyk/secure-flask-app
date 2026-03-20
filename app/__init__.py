import base64

from flask import Flask, current_app, g, request, redirect
from cryptography.fernet import Fernet
from .extensions import db, mail
from .auth import bp as auth_bp
from config import Config
from .models import User
import os
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from flask_wtf import CSRFProtect
from flask_login import LoginManager

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
login_manager = LoginManager()


def create_default_admin():
    admin_username = current_app.config.get('ADMIN_USERNAME')
    admin_password = current_app.config.get('ADMIN_PASSWORD')
    admin_email = current_app.config.get('ADMIN_EMAIL')

    admin = User.query.filter_by(username=admin_username).first()
    if not admin:
        admin = User(username=admin_username, role='admin')
        admin.set_password(admin_password)
        admin.email = admin_email
        db.session.add(admin)
        db.session.commit()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.fernet = Fernet(app.config['FERNET_KEY'])

    db.init_app(app)
    mail.init_app(app)
    setup_logging(app)
    setup_logger(app)

    login_manager.init_app(app)
    login_manager.login_view = 'routes.login'
    login_manager.login_message = "Please log in to access"

    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)
    app.register_blueprint(auth_bp)
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE='Lax'
    )

    csrf.init_app(app)
    limiter.init_app(app)

    @app.before_request
    def generate_nonce():
        g.nonce = base64.b64encode(os.urandom(16)).decode()

    @app.after_request
    def add_csp_header(response):
        nonce = getattr(g, "nonce", "")
        response.headers["Content-Security-Policy"] = (
            f"script-src 'nonce-{nonce}' 'strict-dynamic' https: 'unsafe-inline'; "
            "object-src 'none'; "
            "base-uri 'none';"
        )

        response.headers["X-Frame-Options"] = "DENY"

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Type"] = "text/html; charset=UTF-8"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    @app.context_processor
    def inject_nonce():
        return {"nonce": getattr(g, "nonce", "")}

    @app.before_request
    def check_cookie_consent():
        if request.endpoint is None:
            return

        if request.endpoint.startswith("static"):
            return

        if request.endpoint in [
            'routes.accept_cookie',
            'routes.dashboard',
            'routes.login',
            'routes.register'
        ]:
            return

        if request.cookies.get('cookie_consent') != 'true':
            return

    @app.before_request
    def redirect_to_https():
        if not request.is_secure:
            return redirect(request.url.replace("http://", "https://"))

    with app.app_context():
        db.create_all()
        create_default_admin()

    return app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def setup_logging(app):
    if not os.path.exists('logs'):
        os.mkdir('logs')

    if not app.logger.handlers:
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    app.logger.info('Flask app startup')


def setup_logger(app):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_folder = os.path.join(base_dir, 'logs')
    os.makedirs(log_folder, exist_ok=True)

    log_file = os.path.join(log_folder, 'app.log')

    if not app.logger.handlers:
        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding='utf-8'
        )

        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        )
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)

        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
        app.logger.propagate = False
