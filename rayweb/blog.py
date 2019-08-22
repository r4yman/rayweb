import datetime
import uuid

from flask import (
	Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from rayweb.auth import login_required
from rayweb.db import get_db

bp = Blueprint('blog',__name__)


@bp.route('/')
def index():
	mongo = get_db()
	posts = mongo.db.post.find({},{'id':1,'title':1,'body':1,'created':1,'username':1,'_id':0}).sort('created',-1)
	return render_template('blog/index.html', posts=posts)

#TODO: think about how to generate a guessable id for user (Access Controls)
@bp.route('/profile/<id>', methods=('GET',))
@login_required
def profile(id):
	mongo = get_db()
	user = mongo.db.user.find_one({'id':id})
	return render_template('blog/profile.html', entity=user)


@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
	if request.method == 'POST':
		title = request.form['title']
		body = request.form['body']
		error = None

		if not title:
			error = 'Title is required.'

		if error is not None:
			flash(error)
		else:
			mongo = get_db()
			mongo.db.post.insert({'id':uuid.uuid4().hex,'title':title,'body':body,'created':datetime.datetime.utcnow(),'username':g.user['username']})
			return redirect(url_for('blog.index'))

	return render_template('blog/create.html')


def get_post(id, check_author=True):
	mongo = get_db()
	post = mongo.db.post.find_one({'id':id},{'id':1,'title':1,'body':1,'created':1,'username':1,'_id':0})

	if post is None:
		abort(404, "Post id {0} doesn't exist.".format(id))

	if check_author and post['username'] != g.user['username']:
		abort(403)

	return post

@bp.route('/update/<id>', methods=('GET', 'POST'))
@login_required
def update(id):
	post = get_post(id)

	if request.method == 'POST':
		title = request.form['title']
		body = request.form['body']
		error = None

		if not title:
			error = 'Title is required.'

		if error is not None:
			flash(error)
		else:
			mongo = get_db()
			mongo.db.post.update_one({'id':id},{'$set':{'title':title,'body':body}})
			return redirect(url_for('blog.index'))

	return render_template('blog/update.html', post=post)


@bp.route('/delete/<id>', methods=('GET','POST'))
@login_required
def delete(id):
	get_post(id)
	mongo = get_db()
	mongo.db.post.remove({'id':id})
	return redirect(url_for('blog.index'))