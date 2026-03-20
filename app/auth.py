import pyotp
import qrcode
import io
from flask import send_file, Blueprint, current_app as app
from flask_login import login_required

from .models import User, Alert
from .extensions import db
from .safe_logging import safe_graylog_warning, fallback_log, safe_add_alert

bp = Blueprint('auth', __name__)
failed_logins = {}
admin_attempts = {}


def generate_otp_secret():
    return pyotp.random_base32()


def get_totp_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureApp")


def verify_totp(token, secret):
    return pyotp.TOTP(secret).verify(token)


def get_user_from_db(username):
    return User.query.filter_by(username=username).first()


def save_user(user):
    db.session.add(user)
    db.session.commit()


@bp.route('/generate-2fa/<username>')
@login_required
def generate_2fa(username):
    user = get_user_from_db(username)

    if not user:
        return "User not found", 404

    if not user.mfa_secret:
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        user.twofa_enabled = True
        save_user(user)

    otp_uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.email,
        issuer_name="MySecureApp"
    )

    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')


def log_failed_login(ip_address):
    app.logger.info(f"Call log_failed_login for IP: {ip_address}")

    from datetime import datetime, timedelta
    now = datetime.now()

    failed_logins.setdefault(ip_address, []).append(now)
    failed_logins[ip_address] = [t for t in failed_logins[ip_address] if now - t < timedelta(minutes=10)]

    if len(failed_logins[ip_address]) >= 5:
        message = f"More than 5 failed login attempts from IP: {ip_address}"

        if not safe_graylog_warning(message, {"event_type": "login_failures", "ip": ip_address}):
            fallback_log(message)

        alert = Alert(alert_type='login_failures', message=message, ip_address=ip_address)
        if not safe_add_alert(alert):
            fallback_log(message)

        app.logger.warning(message)


def is_admin_user(username):
    admin_users = {"admin"}
    return username in admin_users


def log_admin_access(ip_address, username, success):
    app.logger.info(f"Call log_admin_access for IP={ip_address}, user={username}, success={success}")

    from datetime import datetime, timedelta
    now = datetime.now()

    if not is_admin_user(username):
        return

    if success:
        return

    admin_attempts.setdefault(ip_address, []).append(now)
    admin_attempts[ip_address] = [t for t in admin_attempts[ip_address] if now - t < timedelta(minutes=10)]

    if len(admin_attempts[ip_address]) >= 3:
        message = f"More than 3 suspicious failed admin login attempts from IP {ip_address}, user {username}"

        if not safe_graylog_warning(message, {"event_type": "admin_attempts", "ip": ip_address, "user": username}):
            fallback_log(message)

        alert = Alert(alert_type='admin_attempts', message=message, ip_address=ip_address)
        if not safe_add_alert(alert):
            fallback_log(message)

        app.logger.warning(message)


def check_night_login(ip_address, username):
    app.logger.info(f"Call check_night_login for IP: {ip_address}")

    from datetime import datetime
    now = datetime.now()

    if 2 <= now.hour < 5:
        message = f"Night login: user={username}, ip={ip_address}"

        if not safe_graylog_warning(message, {"event_type": "night_login", "ip": ip_address}):
            fallback_log(message)

        alert = Alert(alert_type='night_login', message=message, ip_address=ip_address)
        if not safe_add_alert(alert):
            fallback_log(message)

        app.logger.warning(message)

