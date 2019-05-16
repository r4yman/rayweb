FROM python:latest
WORKDIR /rayweb
COPY . /rayweb
COPY ./config.py /configs/.
RUN pip install flup
RUN pip install pyjwt
RUN pip install rayweb-1.0.0-py3-none-any.whl
ENV FlASK_APP rayweb
CMD ["python", "rayweb.fcgi"]
