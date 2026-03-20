import random
from faker import Faker
import pyotp
import string
from dotenv import load_dotenv



load_dotenv()
from cryptography.fernet import Fernet
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

from app import create_app, User, db

app = create_app()

fake = Faker()


def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choice(chars) for _ in range(length))


def create_teachers(count=17):
    credentials = []

    for _ in range(count):
        first_name = fake.first_name()
        last_name = fake.last_name()
        username = (first_name + "_" + last_name).lower()
        email = fake.email()

        password = generate_random_password()
        password_hash = generate_password_hash(password)

        role = 'teacher'

        mfa_secret = pyotp.random_base32()
        preferred_mfa_method = random.choice(['qr', 'email'])

        teacher = User(
            name=first_name,
            lastname=last_name,
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            mfa_secret=mfa_secret,
            preferred_mfa_method=preferred_mfa_method
        )
        db.session.add(teacher)
        credentials.append((username, password))

    db.session.commit()

    print("Teachers successfully created! Credentials:")
    for username, password in credentials:
        print(f"Username: {username}, Password: {password}")


if __name__ == '__main__':
    app.run(ssl_context=(
        "localhost+1.pem",
        "localhost+1-key.pem"
    ))

    # with app.app_context():
    #     create_teachers()
