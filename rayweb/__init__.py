import os

from flask import Flask, send_from_directory, url_for, current_app
from flask_cors import CORS


def create_app(test_config=None):
	app = Flask('rayweb', instance_path="/instance", instance_relative_config=True)
	app.config.from_mapping(
		SECRET_KEY='dev',
		ORIGINS=['http://192.168.99.101:8000',],
		DATABASE=os.path.join(app.instance_path,'rayweb.sqlite'),
	)
	# the resource path is not dynamic
	CORS(app,resources='/create',origins=app.config.get("ORIGINS"),supports_credentials=True)

	if test_config is None:
		# load the instance config, if it exists, when not testing
		app.config.from_pyfile('/configs/config.py', silent=True)
	else:
		# load the test config if passed in
		app.config.from_mapping(test_config)

	# ensure the instance folder exists
	try:
		os.makedirs(app.instance_path)
	except OSError:
		pass

	# just a test display
	if app.config.get('TESTING'):
		@app.route('/test')
		def hello():
			return 'Hello, World!'

	# a secret :)
	if app.config.get('TESTING'):
		@app.route('/topsecret')
		def secret():
			return send_from_directory('static','frog.gif', mimetype='image/gif')

	from . import db
	db.init_app(app)
	with app.app_context():
		db.init_db()

	from . import auth
	app.register_blueprint(auth.bp)

	from . import blog
	app.register_blueprint(blog.bp)
	app.add_url_rule('/', endpoint='index')

	from . import admin
	app.register_blueprint(admin.bp)

	return app
