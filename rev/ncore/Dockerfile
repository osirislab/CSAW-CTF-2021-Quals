FROM ubuntu:18.04

RUN apt-get update && apt-get -y install python3 python3-pip socat iverilog

WORKDIR /home/
COPY flag.hex .
COPY server.py .
COPY nco .

EXPOSE 8001
CMD ["socat", "-T200", "TCP-LISTEN:8000,reuseaddr,pktinfo,fork,ignoreeof", "EXEC:python3 /home/server.py"]