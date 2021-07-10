#!/bin/bash

set -eu

docker-compose up -d import-keys
docker-compose exec import-keys rsync -avr rsync://rsync.cyberbits.eu/sks/dump /import
