FROM python:latest
WORKDIR /rayweb
COPY . /rayweb
RUN mkdir -p /configs
COPY ./config.py /configs/config.py
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
ENV FlASK_APP rayweb
CMD ["python", "rayweb.fcgi"]
