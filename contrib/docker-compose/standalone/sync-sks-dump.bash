#!/bin/bash

set -eu

if [[ -z ${KEYDUMP:-} ]]; then
    cat <<EOF

Note that to prevent abuse, public keyserver dumps are no longer maintained.
Please set the KEYDUMP environment variable to point to an alternative source, e.g.:

    export KEYDUMP=rsync://username:password@rsync.example.com/hockeypuck/dump
    $0

Contact hockeypuck-devel@groups.google.com for assistance.

EOF
    exit 1
fi

./docker-compose.bash -f docker-compose.yml -f docker-compose-tools.yml \
    run --rm --entrypoint /bin/sh import-keys \
        -x -c 'rsync -avr --delete "${KEYDUMP}/*.pgp" /import/dump'
