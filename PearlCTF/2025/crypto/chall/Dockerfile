FROM python:slim AS app
RUN pip install --no-cache-dir progress
RUN pip install numpy

FROM pwn.red/jail
COPY --from=app / /srv
COPY ./docker-files /srv/app
RUN chmod +x /srv/app/run
ENV JAIL_MEM=150M JAIL_PIDS=50 JAIL_CPU=500 JAIL_TIME=4000
