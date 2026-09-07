#!/bin/bash

set -eu

./docker-compose.bash -f docker-compose.yml -f docker-compose-tools.yml \
    run --rm --entrypoint /bin/sh import-keys \
        -x -c 'rm /import/dump/*'
