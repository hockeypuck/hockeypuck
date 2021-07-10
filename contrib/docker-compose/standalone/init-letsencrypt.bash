#!/bin/bash

# Adapted from https://github.com/wmnnd/nginx-certbot.

# MIT License
# 
# Copyright (c) 2018 Philipp Schmieder
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

HERE=$(cd $(dirname $0); pwd)
set -eu
[ -e $HERE/.env ]
. $HERE/.env

if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  exit 1
fi

domains=($FQDN)
rsa_key_size=4096
email="$EMAIL" # Adding a valid address is strongly recommended

echo "### Downloading recommended TLS parameters ..."
docker-compose run --rm --entrypoint "/bin/sh -c \"\
  cd /etc/letsencrypt && \
  wget -q https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf -O options-ssl-nginx.conf && \
  wget -q https://ssl-config.mozilla.org/ffdhe2048.txt -O ssl-dhparams.pem\"" certbot
echo

echo "### Creating dummy certificates for $domains ..."
for domain in "${domains[@]}"; do
  path="/etc/letsencrypt/live/$domain"
  docker-compose run --rm --entrypoint "/bin/sh -c \"\
    mkdir -p $path && \
    openssl req -x509 -nodes -newkey rsa:1024 -days 1\
      -keyout '$path/privkey.pem' \
      -out '$path/fullchain.pem' \
      -subj '/CN=localhost'\"" certbot
  echo
done

echo "### Starting nginx ..."
docker-compose up --force-recreate -d nginx
echo

echo "### Deleting dummy certificates for $domains ..."
docker-compose run --rm --entrypoint "/bin/sh -c \"\
  rm -Rf /etc/letsencrypt/live/* /etc/letsencrypt/archive/* /etc/letsencrypt/renewal/*\"" certbot
echo

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ ${CERTBOT_STAGING:-0} != "0" ]; then staging_arg="--staging"; else staging_arg=""; fi

docker-compose run --rm --entrypoint "\
  certbot certonly --webroot -w /etc/nginx/html \
    $staging_arg \
    $email_arg \
    $domain_args \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --force-renewal" certbot
echo

echo "### Shutting down ..."
docker-compose down
