WORKDIR /rayweb
COPY . /rayweb
RUN pip3 install flup-py3
RUN pip3 install wheel
RUN pip3 install rayweb-1.0.0-py3-none-any.whl
EXPOSE 9000
CMD ["python3", "rayweb.fcgi"]
