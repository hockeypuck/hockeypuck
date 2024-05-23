#!/bin/bash

# A QAD script to emulate PKS functionality until we fix it properly in the codebase
#
# It takes two arguments, the target server and the timestamp from which to start processing
# The target server is the base URL, e.g. "https://pgpkeys.eu"
# The timestamp is in SQL ISO format, e.g. "2024-04-19 23:17:28.231113+00"

set -euo pipefail

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
CURL_FLAGS=-SsfL

[[ ${2:-} ]] || {
    echo "Usage: $0 <target-host> <start-timestamp>"
    exit 1
}

remotehost="$1"
start_timestamp="$2"

new_timestamp=
while true; do
    while read fp _ timestamp; do
        [[ $timestamp ]] || break
        : "${new_timestamp:=$timestamp}"
        echo "'$fp' at '$timestamp'"
        curl $CURL_FLAGS 'http://'"$(hostname --fqdn)"':11371/pks/lookup?op=get&options=mr&search=0x'"$fp" | \
            curl $CURL_FLAGS -H "Content-Type: application/x-www-form-urlencoded" \
                -XPOST "$remotehost"/pks/add --data-urlencode keytext@-
        # be gentle, don't scare the haproxy
        sleep 5
    done < <($SCRIPT_DIR/find-keys.bash -s "$start_timestamp" | tr -d '\r')
    start_timestamp="${new_timestamp:-$start_timestamp}"
    echo "up to date with '$start_timestamp'"
    new_timestamp=
    sleep 3600
done
