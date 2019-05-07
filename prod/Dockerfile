FROM python:latest
WORKDIR /rayweb
COPY . /rayweb
RUN pip install flup
RUN pip install rayweb-1.0.0-py3-none-any.whl
ENV FlASK_APP rayweb
RUN flask init-db
EXPOSE 9000
CMD ["python", "rayweb.fcgi"]
