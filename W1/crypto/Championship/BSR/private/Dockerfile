FROM ubuntu:latest

RUN apt update -y && apt install socat python-is-python3 python3-pip -y
RUN pip install pycryptodome --break-system-packages
WORKDIR /
COPY chall.py / 
COPY utils.py /
COPY flag.txt / 
COPY secret.txt /

CMD ["socat", "TCP-LISTEN:12345,reuseaddr,fork", "EXEC:\"python3 chall.py\",stderr"]
