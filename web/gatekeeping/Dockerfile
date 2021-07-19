FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y python3 python3-pip supervisor nginx

RUN groupadd -g 1000 app && useradd -g app -m -u 1000 app -s /bin/bash

RUN pip3 install gunicorn flask pycrypto

ADD server/ /server
RUN "/server/setup.sh"


CMD ["/usr/bin/supervisord"]
