from functools import wraps
from flask import abort
from flask import current_app as app
from flask_login import current_user


def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            if not current_user.is_authenticated:
                app.logger.warning("Unauthorized access attempt")
                abort(403)

            if current_user.role != role_name:
                app.logger.warning(
                    f"Forbidden access: user={current_user.username}, "
                    f"role={current_user.role}, required={role_name}"
                )
                abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator


ROLE_PERMISSIONS = {
    "admin": {"view_users", "edit_users", "delete_users", "add_users", "view_alerts"},
    "teacher": {"view_teacher"},
    "student": {"view_student"}
}


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            if not current_user.is_authenticated:
                app.logger.warning(
                    f"Unauthorized access attempt to permission '{permission}'"
                )
                abort(403)

            if not current_user.has_permission(permission):
                app.logger.warning(
                    f"Forbidden permission access: user={current_user.username}, "
                    f"role={current_user.role}, missing_permission={permission}"
                )
                abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator


