import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db


bp = Blueprint('student', __name__, url_prefix='/student')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        if error is None:
            try:
                db.execute(
                    "INSERT INTO student (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"Student {username} is already registered."
            else:
                return redirect(url_for("student.login"))
        flash(error)
    return render_template('student/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        student = db.execute(
            'SELECT * FROM student WHERE username = ?', (username,)
        ).fetchone()
        if student is None:
            error = 'Incorrect username.'
        elif not check_password_hash(student['password'], password):
            error = 'Incorrect password.'
        if error is None:
            session['student_id'] = student['id']
            return redirect(url_for('index'))

        flash(error)
    return render_template('student/login.html')


@bp.before_app_request
def load_logged_in_user():
    student_id = session.get('student_id')
    if student_id is None:
        g.student = None
    else:
        g.student = get_db().execute(
            'SELECT * FROM student WHERE id = ?', (student_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session['student_id'] = None
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('student.login'))
        return view(**kwargs)
    return wrapped_view