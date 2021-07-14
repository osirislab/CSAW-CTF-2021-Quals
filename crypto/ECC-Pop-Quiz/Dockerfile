FROM debian:stretch
MAINTAINER Dhyey

RUN apt-get update && apt-get install -y python3 python3-pip sagemath
RUN pip3 install pycryptodome
RUN pip3 install sympy
RUN apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -M chal

WORKDIR /opt/chal

COPY flag.txt .
COPY server.sage .
COPY mov_attack_curves.json .
COPY smarts_attack_curves.json .
COPY singular_curves.json .

EXPOSE 5000

CMD ["socat", "-T300", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/usr/bin/sage /opt/chal/server.sage,pty,echo=0"]
