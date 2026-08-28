#!/bin/bash

set -eu

docker-compose \
	run --rm --entrypoint /bin/bash hockeypuck \
		-x -c '/hockeypuck/bin/hockeypuck-reload -config /hockeypuck/etc/hockeypuck.conf'
