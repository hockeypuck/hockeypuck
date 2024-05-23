#!/bin/bash

set -eu

docker-compose -f docker-compose.yml -f docker-compose-tools.yml \
    run --rm --entrypoint /bin/sh import-keys \
        -x -c 'rsync -avr rsync://rsync.cyberbits.eu/sks/dump/*.pgp /import'
