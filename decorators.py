from functools import wraps
from flask import session, flash, redirect, url_for

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Access restricted to admins.", "danger")
            return redirect(url_for('inventory'))  # Redirect to a safe page
        return f(*args, **kwargs)
    return decorated_function
