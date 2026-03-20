from flask_mail import Message
from flask import current_app
import re
import hashlib
import requests
from app import mail
from typing import Optional


def is_password_strong(password: str) -> bool:
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password) and
            re.search(r'[!@#$%^&*(),.?":{}|<>]', password))


def check_pwned_password(password: str) -> Optional[int]:

    sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()  # nosec B324
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]

    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            return None
    except requests.RequestException:
        return None

    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)

    return 0


def send_email(subject, recipients, body):
    msg = Message(subject=subject,
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=recipients)
    msg.body = body
    mail.send(msg)