#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eu

[ -e "$HERE/.env" ]

env - $(< "$HERE/.env") envsubst '$FQDN:$FINGERPRINT:$RELEASE:$POSTGRES_USER:$POSTGRES_PASSWORD' \
	< "$HERE/hockeypuck/etc/hockeypuck.conf.tmpl" > "$HERE/hockeypuck/etc/hockeypuck.conf"
env - $(< "$HERE/.env") envsubst '$FQDN' \
	< "$HERE/nginx/conf.d/hockeypuck.conf.tmpl" > "$HERE/nginx/conf.d/hockeypuck.conf"
