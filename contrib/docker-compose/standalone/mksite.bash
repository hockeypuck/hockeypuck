#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eu

[ ! -e "$HERE/.env" ]

POSTGRES_PASSWORD=$(head -c 30 /dev/urandom | base32 -w0)
cat >$HERE/.env <<EOF
FQDN=hockeypuck.io
EMAIL=hockeypuck@hockeypuck.io
FINGERPRINT=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
POSTGRES_USER=hkp
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
RELEASE=2.1.0
EOF
chmod 600 $HERE/.env
