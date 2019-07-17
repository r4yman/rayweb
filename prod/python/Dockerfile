FROM python:latest
RUN mkdir -p /instance
WORKDIR /rayweb
COPY . /rayweb
RUN mkdir -p /configs
COPY ./config.py /configs/config.py
RUN pip install flup
RUN pip install pyjwt
RUN pip install rayweb-1.0.0-py3-none-any.whl
ENV FlASK_APP rayweb
CMD ["python", "rayweb.fcgi"]
