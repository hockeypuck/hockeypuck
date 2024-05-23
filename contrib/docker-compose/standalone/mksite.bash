#!/bin/bash

HERE=$(cd "$(dirname "$0")"; pwd)
set -eu

# Script to create or migrate a hockeypuck standalone deployment.

# This script should not overwrite existing modifications.
# To regenerate the .env file from scratch you must remove it first.

if [ ! -e "$HERE/.env" ]; then

POSTGRES_PASSWORD=$(LC_ALL=C tr -dc 'A-Z3-7' </dev/urandom | fold -w 48 | head -n 1)
cat >"$HERE/.env" <<EOF
###########################################################
## HOCKEYPUCK STANDALONE SITE CONFIGURATION TEMPLATE
## Edit this, then run ./mkconfig.bash
###########################################################

#######################################################################
## docker-compose<1.29 does not parse quoted values like a POSIX shell.
## This means that normally you should not quote values in this file,
## as docker-compose's old behaviour is highly unintuitive.
## 
## The scripts in this directory try to compensate, and can parse
## *double* quotes around ALIAS_FQDNS, CLUSTER_FQDNS and HKP_LOG_FORMAT
## values *only*, as these values will normally contain whitespace and
## so most users will instinctively quote them anyway.
##
## In all other cases, enclosing quotes MUST NOT be used.
#######################################################################

# This is the primary FQDN of your site
FQDN=keyserver.example.com
# Any extra FQDN aliases, space-separated
ALIAS_FQDNS=""
# A contact email address for the site operator (that's you!)
EMAIL=admin@example.com
# PGP encryption key for the above email address
FINGERPRINT=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
# ACME Directory Resource URI (use Let's Encrypt if empty)
ACME_SERVER=

# Version of PostgreSQL to initialise
# BEWARE if you change this, you MUST do one of the following:
#
# a) remove the "standalone_pg_data" docker volume and restore from dump:
#       docker volume rm standalone_pg_data
#
# b) migrate the postgres data files by hand, see e.g.:
#       https://github.com/tianon/docker-postgres-upgrade
#
POSTGRES_VERSION=15

###########################################################
# You normally won't need to change anything below here
###########################################################

POSTGRES_USER=hkp
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
RELEASE=standalone
EOF
fi

if ! grep -q MIGRATION_HAPROXY_DONE "$HERE/.env"; then
# Migration 1: new haproxy configuration.

cat >>"$HERE/.env" <<EOF

# Parameterised default values for haproxy config

# The following is only required in shim mode
#KEYSERVER_HOST_PORT=hockeypuck:11371

# Remote URL for fetching tor exit relays list
TOR_EXIT_RELAYS_URL=https://www.dan.me.uk/torlist/?exit

# Advanced HAProxy configuration options

# Set this to the host:port that your HAProxy peers will see
#HAP_PEER_HOST_PORT=127.0.0.1:1395
# Every name and alias of your other cluster members, space-separated
# Note that their IPs should also be added to ./haproxy/etc/lists/whitelist.list
CLUSTER_FQDNS=""

# Set these to "port" or "host:port" to override the listening hostip/port(s)
#HAP_HTTP_HOST_PORT=80
#HAP_HTTPS_HOST_PORT=443
#HAP_HKP_HOST_PORT=11371

# Uncomment *at most one* of the BEHIND settings to trust an upstream proxy's request headers.
# This is vital so that rate limiting applies to the client's real IP and not the proxy's.
#
# Trust CF-Connecting-IP: headers
#HAP_BEHIND_CLOUDFLARE=true
# Trust X-Forwarded-For: headers
#HAP_BEHIND_PROXY=true
# As above for HTTP[S], but HKP listens directly (so that HSTS dual-mode still works)
#HAP_BEHIND_PROXY_EXCEPT_HKP=true

# Set this to e.g. /etc/letsencrypt in order to share certificates with the host.
# Note that the certbot container is responsible for renewing these.
#CERTBOT_CONF=certbot_conf

# MIGRATION_HAPROXY_DONE (DO NOT REMOVE THIS LINE!)
EOF

fi

if ! grep -q MIGRATION_HAPROXY_LOGFORMAT_DONE "$HERE/.env"; then
# Migration 2: new haproxy configuration (additional)

cat >>"$HERE/.env" <<EOF

# Set the HAProxy log format
HAP_LOG_FORMAT="%ci:%cp [%t] %ft %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %ST %U/%B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"

# MIGRATION_HAPROXY_LOGFORMAT_DONE (DO NOT REMOVE THIS LINE!)
EOF

fi

if ! grep -q MIGRATION_3_DONE "$HERE/.env"; then
# Migration 3: revert haproxy configuration (redundant envars)

sed -E -i -e '/^(PROMETHEUS_HOST_PORT|CERTBOT_HOST_PORT|HAP_DHPARAM_FILE|HAP_CONF_DIR|HAP_CACHE_DIR|HAP_CERT_DIR|# Hosts and ports|# Paths and files|# You should only change these)/ d' "$HERE/.env"

echo "# MIGRATION_3_DONE (DO NOT REMOVE THIS LINE!)" >> "$HERE/.env"
fi

chmod 600 "$HERE/.env"
