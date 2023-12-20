FROM python:3.11-slim-buster

COPY . /opt/ws_gl_int

RUN python3 -m pip install --upgrade pip
WORKDIR /opt/ws_gl_int
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "/opt/ws_gl_int/ws_gitlab_integration/ws2gl_format_convertor.py"]
CMD ["-h"]
