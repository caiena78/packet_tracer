FROM docker.io/python:3.12-alpine3.20
LABEL maintainer="Chad Aiena"

RUN apk add --no-cache --upgrade git

RUN mkdir -p /var/python

WORKDIR /var/python

RUN git clone https://github.com/caiena78/packet_tracer.git

WORKDIR /var/python/packet_tracer

RUN pip3 install -r requirements.txt

EXPOSE 5000/tcp

CMD ["python3", "web.py"]