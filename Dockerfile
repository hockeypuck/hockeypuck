FROM golang:1.24.12-trixie AS builder
LABEL io.hockeypuck.temp=true

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get -y upgrade && \
    adduser builder --system --disabled-login && \
    apt-get -y install build-essential postgresql-17 postgresql-server-dev-17 --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --chown=builder:root Makefile /hockeypuck/
COPY --chown=builder:root src /hockeypuck/src
ENV GOPATH=/hockeypuck
USER builder
WORKDIR /hockeypuck
RUN make test test-postgresql
COPY --chown=builder:root .git /hockeypuck/.git
RUN make build


FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /hockeypuck/bin /hockeypuck/lib /hockeypuck/etc /hockeypuck/data && \
    apt-get update -qq && \
    apt-get -y upgrade && \
    apt-get -y install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY contrib/templates /hockeypuck/lib/templates
COPY contrib/webroot /hockeypuck/lib/www
COPY contrib/bin/startup.sh /hockeypuck/bin/
VOLUME /hockeypuck/etc /hockeypuck/data
CMD ["/hockeypuck/bin/startup.sh"]
