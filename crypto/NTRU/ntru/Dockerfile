FROM debian:stretch

RUN apt update && apt install -y socat python3 python3-pip && rm -rf /var/lib/apt/lists/*

RUN pip3 install sympy numpy

RUN useradd -M chal

WORKDIR /opt/chal

COPY server.py .
COPY flag.txt .
COPY ntru ./ntru
COPY private_key .
COPY public_key .
COPY random_poly .

RUN chmod 444 flag.txt && chmod 555 server.py

EXPOSE 5000

USER chal
CMD ["socat", "-T60", "TCP-LISTEN:5000,reuseaddr,fork","EXEC:python3 ./server.py"]
