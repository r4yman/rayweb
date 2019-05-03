#!/usr/bin/python3
from flup.server.fcgi import WSGIServer
from rayweb import create_app

if __name__ == '__main__':
	WSGIServer(create_app(), bindAddress=('eth0',9000), umask=700).run()
