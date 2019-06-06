import functools
import datetime
import jwt

from flask import (
	Blueprint, flash, g, redirect, render_template, request, url_for, make_response, current_app
)
from werkzeug.security import check_password_hash, generate_password_hash

from rayweb.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def create_token(sub,role,key):
	payload = {
		'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
		'iat': datetime.datetime.utcnow(),
		'sub': sub,
		'role': role
	}

	token = jwt.encode(
		payload,
		key,
		algorithm = 'HS256'
	).decode()

	return token

@bp.route('/register', methods=('GET', 'POST'))
def register():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		if 'persistent' in request.form.keys():
			persistent = True
		else:
			persistent = False
		db = get_db()
		error = None

		if not username:
			error = 'Username is required.'
		elif not password:
			error = 'Password is required.'
		elif db.execute(
			'SELECT id FROM user WHERE username = ?', (username,)
		).fetchone() is not None:
			error = 'User {} is already registered.'.format(username)

		if error is None:
			if persistent:
				payload = {
					'iat': datetime.datetime.utcnow(),
					'sub': username,
					'role': 'user'
				}

				token  = jwt.encode(payload,current_app.config.get('SECRET_KEY'),algorithm='HS256')
				db.execute(
					'INSERT INTO user (username, password, token) VALUES (?, ?, ?)',
					(username, generate_password_hash(password), token)
				)
			else:
				db.execute(
					'INSERT INTO user (username, password) VALUES (?, ?)',
					(username, generate_password_hash(password))
				)
			db.commit()
			return redirect(url_for('auth.login'))

		flash(error)

	return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db = get_db()
		error = None
		user = db.execute(
			'SELECT * FROM user WHERE username = ?', (username,)
		).fetchone()

		if user is None:
			error = 'Incorrect username.'
		elif not check_password_hash(user['password'], password):
			error = 'Incorrect password.'
		elif user['token'] is not None:
			token = user['token'].decode()
			response = make_response(redirect(url_for('index')))
			response.headers['Set-Cookie'] = 'token=' + token + '; path=/'
			return response

		if error is None:
			token = create_token(user['username'],'user',current_app.config.get('SECRET_KEY'))
			response = make_response(redirect(url_for('index')))
			response.headers['Set-Cookie'] = 'token=' + token + '; path=/'
			return response

		flash(error)

	return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
	if 'token' in request.cookies:
		authToken = request.cookies['token']
		
		try:
			payload = jwt.decode(authToken, current_app.config.get('SECRET_KEY'))
		except (jwt.exceptions.ExpiredSignatureError,jwt.exceptions.InvalidTokenError):
			g.user = None
			g.role = None
		else:
			g.user = get_db().execute(
				'SELECT * FROM {} WHERE username = ?'.format(payload['role']), (payload['sub'],)
			).fetchone()
			g.role = payload['role']
	else:
		g.user = None
		g.role = None


@bp.route('/logout')
def logout():
	exp = datetime.datetime.utcnow()
	conv = exp.strftime('%a, %d %b %Y %H:%M:%S GMT')
	response = make_response(redirect(url_for('index')))
	response.headers['Set-Cookie'] = 'token=expired; path=/; expires=' + conv
	return response


def login_required(view):
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
			return redirect(url_for('auth.login'))

		return view(**kwargs)

	return wrapped_view


def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.role != 'admins':
            return redirect(url_for('admin.login'))

        return view(**kwargs)

    return wrapped_view