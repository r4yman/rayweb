# Rayweb

This simple WebApplication originated from the offical Flask Tutorial and was transformed into a demonstration for security vulnerabilities.

## Installation

To install, clone this repository and go into the `prod/` folder. Then simply run:

```text
docker-compose up --build
```

the first time you install it. After installing it once

```text
docker-compose up
```
does the trick.

This will create 3 docker container each time you run it, one running nginx as reverse-proxy, one hosting the MongoDB and the last running this app as a FCGI Server.

## Configuration

If you want to configure the WebApp, change the values in the `prod/config.py` file before starting the containers. This is useful if you want to change the database or the `SECRET_KEY` value used for encryption.

The `prod/config.py` file could look like this:

```python
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
ORIGINS = ['https://github.com','http://localhost:8080']
MONGO_URI = 'mongodb://localhost:27017/rayweb'
```
## SSL/TLS Encryption

Automatically generates a Certificate every time a docker container is created and serves the content over HTTPS and HTTP.

## Cross Origin Resource Sharing

You can put your machines IP address into the `ORIGINS` variable in the `prod/config.py` file together with port 8000 to be able to use the there hosted SOP and CORS demos.

```python
ORIGINS = ['http://machinesIP:8000']
```

