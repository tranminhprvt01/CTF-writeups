FROM sagemath/sagemath:latest

RUN sudo apt-get -y update && sudo apt-get install -y socat
COPY . .
RUN sage -pip install timeout-decorator

CMD ["socat", "TCP-LISTEN:7574,reuseaddr,fork", "exec:'python3 task.py'"]
