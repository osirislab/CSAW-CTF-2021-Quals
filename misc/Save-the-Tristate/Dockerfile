FROM debian:stretch
MAINTAINER Jasmine

RUN apt-get update && apt-get install -y python3 python3-pip 
RUN apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -M chal

WORKDIR /opt/chal

COPY flag.txt .
COPY save_tristate.py .
COPY key.txt .

EXPOSE 5000

CMD ["socat", "-T300", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/usr/bin/python3 /opt/chal/generator.py,pty,echo=0"]
