FROM golang:1.24-trixie AS builder
LABEL io.hockeypuck.temp=true

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -qq && \
    apt -y upgrade && \
    adduser builder --system --disabled-login && \
    apt -y install build-essential postgresql-17 postgresql-server-dev-17 --no-install-recommends && \
    apt clean && \
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
RUN mkdir -p /hockeypuck/bin /hockeypuck/lib /hockeypuck/etc /hockeypuck/data && \
    apt update -qq && \
    apt -y upgrade && \
    apt -y install ca-certificates && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY contrib/templates /hockeypuck/lib/templates
COPY contrib/webroot /hockeypuck/lib/www
COPY contrib/bin/startup.sh /hockeypuck/bin/
VOLUME /hockeypuck/etc /hockeypuck/data
CMD ["/hockeypuck/bin/startup.sh"]
