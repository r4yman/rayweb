import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, make_response, current_app
)

from werkzeug.security import check_password_hash
from rayweb.auth import create_token, login_required, admin_required, create_id
from rayweb.db import get_db

bp = Blueprint('admin',__name__, url_prefix='/admin')


@bp.route('/', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mongo = get_db()
        error = None
        admin = mongo.db.admins.find_one({'username':username})
        '''
        db.execute(
            'SELECT * FROM admins WHERE username = ?', (username,)
        ).fetchone()
        '''
    
        if admin is None:
            error = 'You are not an administrator!'
        elif not check_password_hash(admin['password'], password):
            error = 'Incorrect password.'
    
        if error is None:
            eth = create_id(mongo)
            token = create_token(admin['username'],'admins',eth,current_app.config.get('SECRET_KEY'))
            mongo.db.admins.update_one({'username':username},{'$set':{'tokenid':eth}})
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
        mongo = get_db()
        mongo.db.drop_collection('user')
        mongo.db.drop_collection('admins')
        mongo.db.drop_collection('post')
        mongo.db.drop_collection('systemvariables')
        '''
        db.executescript(
            DROP TABLE IF EXISTS user;
            DROP TABLE IF EXISTS admins;
            DROP TABLE IF EXISTS post;
            DROP TABLE IF EXISTS server_variables;
        )
        db.commit()
        '''
    return render_template('admin/control.html')