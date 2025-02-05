#!/bin/bash

set -eu

docker-compose -f docker-compose.yml -f docker-compose-tools.yml \
    run --rm --entrypoint /bin/sh import-keys \
        -x -c 'rsync -avr --delete "rsync://rsync.cyberbits.eu/hockeypuck/dump/*.pgp" /import/dump'
