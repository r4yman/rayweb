FROM alpine:latest
RUN mkdir -p /ssl
RUN apk add nginx openssl
RUN openssl req -x509 -newkey rsa:4096 -nodes -out /ssl/cert.pem -keyout /ssl/key.pem -days 365 -batch -subj "/C=DE/ST=Baden-Wuertemberg/L=Heidelberg/O=ERNW/CN=webserver"
RUN curl https://ssl-config.mozilla.org/ffdhe2048.txt > /ssl/dhparam.pem
COPY ./sop.html /var/www/html/sop.html
CMD nginx && tail -f /var/log/nginx/*
