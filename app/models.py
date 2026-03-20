from datetime import datetime

import pytz
from flask import current_app
from .extensions import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    lastname = db.Column(db.String(30))
    username = db.Column(db.String(80), unique=True, nullable=False)
    _email = db.Column("email", db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='student')
    mfa_secret = db.Column(db.String(32))
    preferred_mfa_method = db.Column(db.String(10), default='email')

    enrollments = db.relationship('Enrollment', back_populates='user')

    @staticmethod
    def can_remove_admin():
        return User.query.filter_by(role="admin").count() > 1

    def has_permission(self, permission_name):
        role_permissions = {
            "admin": ["view_users", "add_users", "edit_users", "delete_users", "view_alerts"],
            "teacher": [],
            "student": [],
        }
        return permission_name in role_permissions.get(self.role, [])

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    @property
    def email(self):
        f = getattr(current_app, 'fernet', None)
        if not f:
            raise RuntimeError("Fernet not initialised in the application")
        return f.decrypt(self._email).decode()

    @email.setter
    def email(self, plain):
        f = getattr(current_app, 'fernet', None)
        if not f:
            raise RuntimeError("Fernet not initialised in the application")
        self._email = f.encrypt(plain.encode())


class Courses(db.Model):
    __tablename__ = 'Courses'

    id = db.Column(db.Integer, primary_key=True)
    id_student = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    id_teacher = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    duration_months = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    employment = db.Column(db.Boolean, default=False)
    level = db.Column(db.String(20), nullable=False)
    image_filename = db.Column(db.String(100), nullable=False)

    enrollments = db.relationship('Enrollment', back_populates='course')
    teacher = db.relationship('User', foreign_keys=[id_teacher], backref='courses_teaching')
    student = db.relationship('User', foreign_keys=[id_student], backref='courses_taken')


ALLOWED_TYPES = {"design", "english", "game_dev", "management", "marketing", "programming", "other"}
ALLOWED_LEVELS = {"beginner", "expert"}

ALLOWED_SORT_FIELDS = {
    "name": Courses.name,
    "duration": Courses.duration_months,
    "level": Courses.level,
    "price": Courses.price,
}


class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('Courses.id'), nullable=False)

    user = db.relationship('User', back_populates='enrollments')
    course = db.relationship('Courses', back_populates='enrollments')

    @staticmethod
    def create_enrollment(user, course):
        existing = Enrollment.query.filter_by(
            user_id=user.id,
            course_id=course.id
        ).first()

        if existing:
            raise ValueError("Already enrolled")

        enrollment = Enrollment(user_id=user.id, course_id=course.id)
        db.session.add(enrollment)
        db.session.commit()
        return enrollment


def now_local():
    tz = pytz.timezone("Europe/Warsaw")
    return datetime.now(tz)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(64))
    message = db.Column(db.Text)
    ip_address = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=now_local)



