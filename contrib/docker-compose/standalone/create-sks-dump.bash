#!/bin/bash

set -eu

PGP_EXPORT=$(awk -F= '/^PGP_EXPORT=/ { print $2 }' .env | tail -1)

./docker-compose.bash run --rm \
    --volume "${PGP_EXPORT:-/var/cache/hockeypuck}:/hockeypuck/export" \
    --entrypoint /bin/bash \
    hockeypuck -xe -c \
		'mkdir -p /hockeypuck/export/dump; find /hockeypuck/export/dump -type f -exec rm {} +; /hockeypuck/bin/hockeypuck-dump -config /hockeypuck/etc/hockeypuck.conf -path /hockeypuck/export/dump'
