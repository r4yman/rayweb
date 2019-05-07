#!/usr/local/bin/python
from flup.server.fcgi import WSGIServer
from rayweb import create_app

if __name__ == '__main__':
	WSGIServer(create_app(), bindAddress=('0.0.0.0',9000)).run()
