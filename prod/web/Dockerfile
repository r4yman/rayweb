FROM nginx:latest
RUN mkdir -p /ssl
RUN openssl req -x509 -newkey rsa:4096 -nodes -out /ssl/cert.pem -keyout /ssl/key.pem -days 365 -batch