import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, make_response, current_app
)

from werkzeug.security import check_password_hash
from rayweb.db import get_db
from rayweb.auth import create_token, login_required, admin_required

bp = Blueprint('admin',__name__, url_prefix='/admin')


@bp.route('/', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        table = request.form['table']
        db = get_db()
        error = None
        admin = db.execute(
            'SELECT * FROM {} WHERE username = ?'.format(table), (username,)
        ).fetchone()
    
        if admin is None:
            error = 'You are not an administrator!'
        elif not check_password_hash(admin['password'], password):
            error = 'Incorrect password.'
    
        if error is None:
            token = create_token(admin['username'],'admins',current_app.config.get('SECRET_KEY'))
            response = make_response(redirect(url_for('admin.control')))
            response.headers['Set-Cookie'] = 'token=' + token + '; path=/'
            return response
    
        flash(error)

    return render_template('admin/login.html')


@bp.route('/control', methods=('GET',))
@admin_required
def control():
    return render_template('admin/control.html')


@bp.route('/drop', methods=('POST',))
@login_required
def drop():
    pin = request.form['pin']
    if pin == '1234':
        db = get_db()
        db.executescript('''
            DROP TABLE IF EXISTS user;
            DROP TABLE IF EXISTS admins;
            DROP TABLE IF EXISTS post;
            '''
            
        )
        db.commit()
    return render_template('admin/control.html')