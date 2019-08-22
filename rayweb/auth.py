import functools
import hashlib
import datetime
import jwt
import uuid

from flask import (
	Blueprint, flash, g, redirect, render_template, request, url_for, make_response, current_app
)
from rayweb.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint('auth', __name__, url_prefix='/auth')

def create_id(mongo):
	seed = mongo.db.systemvariables.find_one({'variable':'urandom'},{'value':1})
	counter = mongo.db.systemvariables.find_one({'variable':'counter'},{'value':1})
	counter = counter['value']

	gen = hashlib.sha256(bytes(counter)+seed['value']).hexdigest()
	counter += 1
	mongo.db.systemvariables.update_one({'variable':'counter'},{'$set':{'value':counter}})

	return gen

def create_token(sub,role,id,key):
	payload = {
		'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
		'iat': datetime.datetime.utcnow(),
		'sub': sub,
		'role': role,
		'jti' : id
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
		
		mongo = get_db()
		error = None

		if not username:
			error = 'Username is required.'
		elif not password:
			error = 'Password is required.'
		elif mongo.db.user.find_one({'username':username},{'id':1}) is not None:
			error = 'User {} is already registered.'.format(username)

		if error is None:
			#TODO: think about how to generate a guessable id for user (Access Controls)
			mongo.db.user.insert({'id':uuid.uuid4().hex,'username':username,'password':generate_password_hash(password)})
			return redirect(url_for('auth.login'))

		flash(error)

	return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		mongo = get_db()
		error = None
		user = mongo.db.user.find_one({'username':username})

		if user is None:
			error = 'Incorrect username.'
		elif not check_password_hash(user['password'], password):
			error = 'Incorrect password.'

		if error is None:
			eth = create_id(mongo)
			token = create_token(user['username'],'user',eth,current_app.config.get('SECRET_KEY'))
			mongo.db.user.update_one({'username':username},{'$set':{'tokenid':eth}})
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
			mongo = get_db()
			user = mongo.db.user.find_one({'username':payload['sub']})
			if user is not None:
				if 'tokenid' in user.keys():
					if user['tokenid'] == payload['jti']:
						g.user = user
						g.role = payload['role']
					else:
						g.user = None
						g.role = None
				else:
					g.user = None
					g.role = None
			else:
				admin = mongo.db.admins.find_one({'username':payload['sub']})
				if admin is not None:
					g.user = admin
					g.role = payload['role']
				else:
					g.user = None
					g.role = None
	else:
		g.user = None
		g.role = None

@bp.after_app_request
def issue_token(response):
	mongo = get_db()
	if g.user is not None:
		eth = create_id(mongo)
		token = create_token(g.user['username'],g.role,eth,current_app.config.get('SECRET_KEY'))
		if g.role == 'admins':
			mongo.db.admins.update_one({'username':g.user['username']},{'$set':{'tokenid':eth}})
		else:
			mongo.db.user.update_one({'username':g.user['username']},{'$set':{'tokenid':eth}})
		response.headers['Set-Cookie'] = 'token=' + token + '; path=/'
		return response
	else:
		return response


@bp.route('/logout')
def logout():
	mongo = get_db()
	eth = create_id(mongo)
	if g.role == 'admins':
		mongo.db.admins.update_one({'username':g.user['username']},{'$set':{'tokenid':eth}})
	else:
		mongo.db.user.update_one({'username':g.user['username']},{'$set':{'tokenid':eth}})

	exp = datetime.datetime.utcnow()
	conv = exp.strftime('%a, %d %b %Y %H:%M:%S GMT')
	response = make_response(redirect(url_for('index')))
	response.headers['Set-Cookie'] = 'token=expired; path=/; expires=' + conv

	g.user = None
	g.role = None
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