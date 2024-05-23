#!/bin/bash

# Find keys in the Hockeypuck postgres database by keyword search

set -euo pipefail

cd "$(dirname "$0")"
[ -f ".env" ] || { echo "Could not open environment file"; exit 1; }

POSTGRES_USER=$(awk -F= '/^POSTGRES_USER=/ {print $2}' < .env | tail -1)

# SQL command for docker-compose/standalone default configuration.
# If using this script elsewhere, you will need to customise the below.
SQLCMD="docker-compose exec postgres psql hkp -U ${POSTGRES_USER} -t -P pager=off"
# for non-docker postgres, e.g.
#SQLCMD="psql hkp -U hkp"

usage() {
    cat <<EOF
Usage: $0 [options] SEARCH

If SEARCH is "-", then search parameters of the appropriate type are read from STDIN, one per line.

Command line options are:

-r  each search parameter is a regex (searches against first userid only)
-s  each search parameter is a SQL timestamp (finds entries modified since)
-t  each search parameter is a SQL tsquery

Otherwise each search parameter is a search-engine style webquery.

EOF
    exit 1
}

s_userid_regex() {
    $SQLCMD -c "select reverse(rfingerprint), keywords from keys where doc->'userIDs'->0->>'keywords' ~ '$1';"
}

s_keywords_tsquery() {
    $SQLCMD -c "select reverse(rfingerprint), keywords from keys, to_tsquery($1) query where query @@ keywords;"
}

s_keywords_websearch() {
    $SQLCMD -c "select reverse(rfingerprint), keywords from keys, websearch_to_tsquery('$1') query where query @@ keywords;"
}

s_modified_since() {
    $SQLCMD -c "SELECT reverse(rfingerprint), mtime FROM keys WHERE mtime > TIMESTAMP '$1' ORDER BY mtime DESC LIMIT 100;"
}

[[ ${1:-} ]] || usage

if [[ $1 == -r ]]; then
    shift
    [[ ${1:-} ]] || usage
    COMMAND=s_userid_regex
elif [[ $1 == -s ]]; then
    shift
    [[ ${1:-} ]] || usage
    COMMAND=s_modified_since
elif [[ $1 == -t ]]; then
    shift
    [[ ${1:-} ]] || usage
    COMMAND=s_keywords_tsquery
else
    COMMAND=s_keywords_websearch
fi

if [[ $1 == "-" ]]; then
    while read -r pattern ; do
        [[ $pattern && "${pattern:0:1}" != "#" ]] || continue
        echo "# $pattern"
        $COMMAND "$pattern"
    done
else
    $COMMAND "$1"
fi
