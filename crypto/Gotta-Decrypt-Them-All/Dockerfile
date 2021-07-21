FROM debian:stretch
MAINTAINER Dhyey

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install pycryptodome
RUN pip3 install sympy
RUN pip3 install inputimeout
RUN apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -M chal

WORKDIR /opt/chal

COPY flag.txt .
COPY server.py .

EXPOSE 5000

CMD ["socat", "-T300", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/usr/bin/python3 /opt/chal/server.py,pty,echo=0"]
