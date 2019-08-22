import os
import click

from flask import current_app, g
from flask.cli import with_appcontext
from flask_pymongo import PyMongo

def get_db():
	if 'mongo' not in g:
		g.mongo = PyMongo(current_app)
	return g.mongo

def close_db(e=None):
	mongo = g.pop('mongo',None)
	if mongo is not None:
		mongo.db.client.close()

def init_db():
	mongo = get_db()

	if mongo.db.systemvariables.find_one() is None:
		mongo.db.systemvariables.insert_many([{"variable":"urandom","value":os.urandom(160)},{"variable":"counter","value":1}])
	if mongo.db.admins.find_one() is None:
		mongo.db.admins.insert_one({"username":"admin","password":"pbkdf2:sha256:150000$GKr6WUfi$2db1a7e3fa645138a106039a22f363c5525e37aa85022bc3753d02051fe8d8a6"})

@click.command('reset-db')
@with_appcontext
def reset_db_command():
	mongo = get_db()

	mongo.db.client.drop_database(mongo.db.client.get_default_database())
	init_db()

def init_app(app):
	app.teardown_appcontext(close_db)
	app.cli.add_command(reset_db_command)