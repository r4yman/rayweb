FROM python:latest
WORKDIR /rayweb
COPY . /rayweb
RUN pip3 install wheel
RUN pip3 install rayweb-1.0.0-py3-none-any.whl
EXPOSE 9000
CMD ["bash", "rayweb.fcgi"]
