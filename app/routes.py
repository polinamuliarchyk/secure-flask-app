import re
import secrets
import pyotp
import qrcode
import io
import base64

from flask import make_response, current_app
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort

from app.models import db, User, Alert, Courses, Enrollment, ALLOWED_TYPES, ALLOWED_LEVELS, ALLOWED_SORT_FIELDS
from app.utils import is_password_strong, check_pwned_password, send_email
from app.auth import generate_otp_secret, log_failed_login, log_admin_access, admin_attempts
from app.access_control import role_required, permission_required
from .extensions import logger
from app import limiter
from .forms import LoginForm, QRVerifyForm, RegisterForm, EditUserForm, AddUserForm, DeleteUserForm
from .forms import EmailCodeForm
from app.forms import MFAChoiceForm
from flask_login import current_user, login_required, login_user, logout_user

bp = Blueprint('routes', __name__)


@bp.route('/')
def dashboard():
    if current_user.is_authenticated:
        return render_template('dashboard.html', user=current_user, role=current_user.role)
    return render_template('dashboard.html', user=None, role=None)


@bp.route('/accept_cookie')
def accept_cookie():
    resp = make_response("OK")
    resp.set_cookie(
        'cookie_consent',
        'true',
        max_age=60*60*24*365,
        httponly=False,
        secure=True,
        samesite='Lax'
    )
    return resp


@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.first_name.data
        lastname = form.last_name.data
        username = form.username.data
        password = form.password.data
        email = form.email.data

        if User.query.filter_by(username=username).first():
            flash("The user already exists.")
        elif not is_password_strong(password):
            flash("Weak password.")
        elif check_pwned_password(password) > 0:
            flash("The password was found in the leaks.")
        elif form.password.data != form.confirm_password.data:
            flash("Passwords do not match.")
        else:
            user = User(username=username)
            user.set_password(password)
            user.name = name
            user.lastname = lastname
            user.email = email
            user.mfa_secret = generate_otp_secret()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Registration successful.")
            return redirect(url_for('routes.user_account'))
    return render_template('register.html', form=form)


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        ip = request.remote_addr

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()

            if user.role == 'admin':
                admin_attempts.pop(ip, None)

            session['pre_2fa'] = user.username
            return redirect(url_for('routes.choice_verify'))

        if user and user.role == 'admin':
            log_admin_access(ip, username, success=False)
        else:
            log_failed_login(ip)

        logger.warning(f"Failed login attempt: {username}")
        flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)


@bp.route('/user_account', methods=['GET', 'POST'])
@role_required('student')
@login_required
def user_account():
    user = current_user

    purchased_courses = [enrollment.course for enrollment in user.enrollments]
    purchased_ids = [course.id for course in purchased_courses]

    query = Courses.query.filter(Courses.price == 0)
    if purchased_ids:
        query = query.filter(~Courses.id.in_(purchased_ids))

    courses_all = query.all()
    return render_template("user_account.html", user=user, purchased_courses=purchased_courses, courses_all=courses_all)


@bp.route('/teacher_account', methods=['GET', 'POST'])
@role_required('teacher')
@login_required
def teacher_account():
    user = current_user
    teacher_courses = Courses.query.filter_by(id_teacher=user.id).all()
    return render_template("teacher_account.html", user=user, teacher_courses=teacher_courses)


@bp.route("/teacher_account/students")
@role_required('teacher')
@login_required
def teacher_students():
    user = current_user
    delete_form = DeleteUserForm()

    teacher_courses = Courses.query.filter_by(id_teacher=user.id).all()
    course_ids = [c.id for c in teacher_courses]

    students = (
        User.query
            .join(Enrollment, Enrollment.user_id == User.id)
            .filter(Enrollment.course_id.in_(course_ids))
            .filter(User.role == "student")
            .distinct()
            .all()
    )

    return render_template(
        "students_teacher.html",
        students=students,
        teacher_courses=teacher_courses,
        delete_form=delete_form
    )


@bp.route("/course/<int:course_id>/student/<int:student_id>/remove", methods=["POST"])
@role_required('teacher')
@login_required
def remove_student_from_course(course_id, student_id):
    delete_form = DeleteUserForm()

    enrollment = Enrollment.query.filter_by(
        course_id=course_id,
        user_id=student_id
    ).first_or_404()

    db.session.delete(enrollment)
    db.session.commit()

    course = Courses.query.get(course_id)

    return redirect(url_for("routes.teacher_students", id_teacher=course.id_teacher, delete_form=delete_form))


@bp.route("/all_courses")
def all_courses():
    course_type = request.args.get("type")
    level = request.args.get("level")
    employment = request.args.get("employment")
    duration = request.args.get("duration", type=int, default=24)
    sort = request.args.get("sort")
    page = request.args.get("page", type=int, default=1)

    query = Courses.query.filter(Courses.duration_months <= duration)

    if course_type in ALLOWED_TYPES:
        query = query.filter(Courses.type == course_type)

    if level in ALLOWED_LEVELS:
        query = query.filter(Courses.level == level)

    if employment == "true":
        query = query.filter(Courses.employment.is_(True))
    elif employment == "false":
        query = query.filter(Courses.employment.is_(False))

    sort_order = request.args.get("order", "asc")
    if sort in ALLOWED_SORT_FIELDS:
        field = ALLOWED_SORT_FIELDS[sort]

        allowed_orders = ['asc', 'desc']
        safe_order = sort_order if sort_order in allowed_orders else 'asc'

        if safe_order == 'desc':
            query = query.order_by(field.desc())
        else:
            query = query.order_by(field.asc())

    courses = query.paginate(page=page, per_page=40, error_out=False)

    user_obj = current_user if current_user.is_authenticated else None
    role = current_user.role if current_user.is_authenticated else None

    return render_template(
        "all_courses.html",
        courses=courses,
        user=user_obj,
        role=role,
        allowed_sort=list(ALLOWED_SORT_FIELDS.keys())
    )


@bp.route('/enroll_course', methods=['POST'])
@login_required
def enroll_course():
    course_id = request.form.get('course_id')

    if not course_id:
        flash('Error: no course selected', 'error')
        return redirect(url_for('routes.user_account'))

    course = Courses.query.get(course_id)
    if not course:
        flash('There is no such course', 'error')
        return redirect(url_for('routes.user_account'))

    try:
        Enrollment.create_enrollment(current_user, course)
    except ValueError as e:
        flash(str(e), 'info')
        return redirect(url_for('routes.user_account'))
    except Exception as e:
        abort(400, str(e))

    flash(f'You have successfully enrolled in the course "{course.name}"', 'success')
    return redirect(url_for('routes.user_account'))


@bp.route('/delete_course', methods=['POST'])
@login_required
def delete_course():
    course_id = request.form.get('course_id')
    purchased = Enrollment.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if purchased:
        db.session.delete(purchased)
        db.session.commit()
        flash('Course deleted successfully', 'success')
    else:
        flash('Course not found', 'error')
    return redirect(url_for('routes.user_account'))


@bp.route('/choice-verify', methods=['GET', 'POST'])
def choice_verify():
    username = session.get('pre_2fa')
    if not username:
        flash("Please log in.")
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(username=username).first()
    if not user:
        session.clear()
        flash("User not found.")
        return redirect(url_for('routes.login'))

    form = MFAChoiceForm()
    if form.validate_on_submit():
        method = form.mfa_method.data

        if method == 'totp' and user.mfa_secret:
            logger.info(f"User {username} chose TOTP for MFA")
            return redirect(url_for('routes.qr_verify'))

        elif method == 'email':
            code = str(secrets.randbelow(900000) + 100000)
            session['2fa_code'] = code
            logger.info(f"Sent 2FA code via email to {user.email} for user {username}")

            send_email(
                subject="Login confirmation code",
                recipients=[user.email],
                body=f"Your confirmation code: {code}"
            )
            return redirect(url_for('routes.mfa_verify'))

        else:
            flash("Select the correct confirmation method.")

    return render_template('choice_verify.html', form=form, user=user)


@bp.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    form = EmailCodeForm()

    username = session.get('pre_2fa')
    if not username:
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(username=username).first()
    if not user:
        session.clear()
        flash("User not found.")
        return redirect(url_for('routes.login'))

    if form.validate_on_submit():
        input_code = form.token.data
        if session.get('2fa_code') == input_code:
            session.pop('2fa_code', None)
            session.pop('pre_2fa', None)

            login_user(user)

            if user.role == 'admin':
                return redirect(url_for('routes.admin_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('routes.teacher_account'))
            else:
                return redirect(url_for('routes.user_account'))
        else:
            flash("Incorrect code from the email.")

    return render_template('mfa_verify.html', form=form)


@bp.route('/qr-verify', methods=['GET', 'POST'])
def qr_verify():
    form = QRVerifyForm()
    username = session.get('pre_2fa')
    if not username:
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(username=username).first()

    if not user or not user.mfa_secret:
        flash("The user is not found or TOTP is not configured.")
        return redirect(url_for('routes.login'))

    if form.validate_on_submit():
        input_code = form.token.data
        totp = pyotp.TOTP(user.mfa_secret)

        if totp.verify(input_code):
            session.pop('pre_2fa', None)

            login_user(user)

            if user.role == 'admin':
                return redirect(url_for('routes.admin_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('routes.teacher_account'))
            else:
                return redirect(url_for('routes.user_account'))
        else:
            flash("Invalid code from the Google Authenticator app.")

    return render_template('qr_verify.html', form=form)


@bp.route('/user_account/qr')
@login_required
def qr():
    user = current_user

    if not getattr(user, "mfa_secret", None):
        try:
            secret = pyotp.random_base32()
            user.mfa_secret = secret

            from app import db
            db.session.add(user)
            db.session.commit()

            flash("A new 2FA secret has been generated for you.", "success")
        except Exception as e:
            current_app.logger.exception("Failed to generate MFA secret")
            flash("Error generating 2FA secret.", "error")
            return redirect(url_for('routes.dashboard'))

    try:
        otp_uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(
            name=user.email,
            issuer_name=current_app.config.get("APP_NAME", "MySecureApp")
        )
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_b64 = base64.b64encode(buf.read()).decode('utf-8')
    except Exception:
        current_app.logger.exception("Failed to generate QR image")
        abort(500)

    return render_template('qr.html', qr_b64=qr_b64, secret=user.mfa_secret)


@bp.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash("You're out of the system.")
    return redirect(url_for('routes.login'))


@bp.route('/admin')
@role_required('admin')
@login_required
def admin_dashboard():
    return redirect(url_for("routes.admin_panel_activity"))


@bp.route('/admin/panel1', methods=['GET', 'POST'])
@role_required('admin')
@login_required
def admin_panel_users():
    users = User.query.all()
    add_form = AddUserForm()
    delete_form = DeleteUserForm()

    edit_forms = {u.username: EditUserForm(obj=u) for u in users}

    return render_template(
        'user_administration.html',
        users=users,
        add_form=add_form,
        delete_form=delete_form,
        edit_forms=edit_forms
    )


@bp.route('/admin/panel2')
@login_required
@role_required('admin')
def admin_panel_activity():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
    return render_template("activity_administration.html", alerts=alerts)


@bp.route('/admin/panel1/add', methods=['GET', 'POST'])
@role_required('admin')
@permission_required("add_users")
@login_required
def add_user():
    form = AddUserForm()
    users = User.query.all()
    if form.validate_on_submit():
        username = form.new_username.data
        if User.query.filter_by(username=username).first():
            flash("The user already exists.")
        else:
            password = form.new_password.data
            if check_pwned_password(password) > 0:
                flash("The password was found in the leaks.")
            else:
                new_user = User(username=username, role=form.new_role.data)
                new_user.set_password(password)
                new_user.name = form.new_name.data
                new_user.lastname = form.new_lastname.data
                new_user.email = form.new_email.data
                new_user.mfa_secret = generate_otp_secret()
                db.session.add(new_user)
                db.session.commit()
                flash(f"User {username} added.")
                return redirect(url_for('routes.admin_panel_users'))
    else:
        print("Form errors:", form.errors)
    return render_template(
        'user_administration.html',
        users=users,
        add_form=form,
        delete_form=DeleteUserForm(),
        edit_forms={u.username: EditUserForm(obj=u) for u in users}
    )


@bp.route('/admin/panel1/edit/<string:username>', methods=['GET', 'POST'])
@role_required('admin')
@permission_required("edit_users")
@login_required
def edit_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        new_username = form.username.data
        if new_username != user.username and User.query.filter_by(username=new_username).first():
            flash("The username is already taken")
            return redirect(url_for('routes.admin_panel_users'))

        new_password = form.password.data
        if new_password:
            if check_pwned_password(new_password) > 0:
                flash("The password was found in the leaks.")
                return redirect(url_for('routes.admin_panel_users'))
            user.set_password(new_password)

        user.username = new_username
        user.name = form.name.data or user.name
        user.lastname = form.lastname.data or user.lastname
        user.email = form.email.data or user.email
        user.role = form.role.data

        if session.get('user') == username and new_username != username:
            session['user'] = new_username

        db.session.commit()
        flash(f"User {username} updated.")
        return redirect(url_for('routes.admin_panel_users'))

    form.username.data = user.username
    form.name.data = user.name
    form.lastname.data = user.lastname
    form.email.data = user.email
    form.role.data = user.role
    return render_template('user_administration.html', edit_form=form, user=user)


@bp.route('/admin/panel1/delete/<string:username>', methods=['POST'])
@role_required('admin')
@permission_required("delete_users")
@login_required
def delete_user(username):
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        abort(400, "Invalid username format")

    if username == session.get('user'):
        flash("You can't delete yourself.")
        return redirect(url_for('routes.admin_panel_users'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.")
        return redirect(url_for('routes.admin_panel_users'))

    if user.role == "admin" and not User.can_remove_admin():
        flash("You cannot delete the last administrator.")
        return redirect(url_for('routes.admin_panel_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User {username} deleted.")

    return redirect(url_for('routes.admin_panel_users'))