#!/bin/bash

set -eu

docker-compose up -d import-keys
docker-compose exec import-keys /bin/sh -c 'rm /import/dump/*'
