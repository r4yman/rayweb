import functools
import datetime
import jwt

from flask import (
	Blueprint, flash, g, redirect, render_template, request, url_for, make_response, current_app
)
from werkzeug.security import check_password_hash, generate_password_hash

from rayweb.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


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
		elif db.execute(
			'SELECT id FROM user WHERE username = ?', (username,)
		).fetchone() is not None:
			error = 'User {} is already registered.'.format(username)

		if error is None:
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

		if error is None:
			try:
				payload = {
					'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
					'iat': datetime.datetime.utcnow(),
					'sub': user['id']
				}

				token = jwt.encode(
					payload,
					current_app.config.get('SECRET_KEY'),
					algorithm = 'HS256'
				)
			except Exception as e:
				error = e
			else:
				response = make_response(redirect(url_for('index')))
				response.headers['Set-Cookie'] = 'token=' + token + '; path=/'
				return response

		flash(error)

	return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
	try:
		authToken = request.cookies['token']
		
		try:
			payload = jwt.decode(authToken, current_app.config.get('SECRET_KEY'))
		except jwt.ExpiredSignatureError:
			g.user = None
			pass
		except jwt.InvalidTokenError:
			g.user = None
			pass
		else:
			g.user = get_db().execute(
				'SELECT * FROM user WHERE id = ?', (payload['sub'],)
			).fetchone()

	except KeyError:
		g.user = None


@bp.route('/logout')
def logout():
	exp = datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5)
	conv = exp.strftime('%a, %d %b %Y %H:%M:%S GMT')
	response = make_response(redirect(url_for('index')))
	response.headers['Set-Cookie'] = 'token=; path=/; expires=' + conv
	return response


def login_required(view):
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
			return redirect(url_for('auth.login'))

		return view(**kwargs)

	return wrapped_view