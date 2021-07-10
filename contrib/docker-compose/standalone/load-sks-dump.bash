#!/bin/bash

set -eu

docker-compose run --rm --entrypoint \
	/bin/bash hockeypuck -x -c \
		'/hockeypuck/bin/hockeypuck-load -config /hockeypuck/etc/hockeypuck.conf /hockeypuck/import/dump/*.pgp'
