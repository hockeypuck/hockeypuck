#!/bin/bash

# Find keys in the Hockeypuck postgres database by keyword search

set -euo pipefail

cd "$(dirname "$0")"
[ -f ".env" ] || { echo "Could not open environment file"; exit 1; }

POSTGRES_USER=$(awk -F= '/^POSTGRES_USER=/ {print $2}' < .env | tail -1)

# SQL command for docker-compose/standalone default configuration.
# If using this script elsewhere, you will need to customise the below.
SQLCMD="./docker-compose.bash exec postgres psql hkp -U ${POSTGRES_USER} -t -P pager=off"
# for non-docker postgres, e.g.
#SQLCMD="psql hkp -U hkp"

usage() {
    cat <<EOF
Usage: $0 [output-options] [search-options] SEARCH

If SEARCH is "-", then search parameters of the appropriate type are read from STDIN, one per line.

Output options are:

-v  all columns are returned in the output
-j  only the JSON is returned in the output

Search options are:

-f  each search parameter is a vfingerprint
-r  each search parameter is a regex (searches against first userid only)
-s  each search parameter is a SQL timestamp (finds entries modified since)
-t  each search parameter is a SQL tsquery

Otherwise each search parameter is a search-engine style webquery.

EOF
    exit 1
}

s_vfingerprint() {
    $SQLCMD -c "select $2 from keys where vfingerprint = '$1';"
}

s_userid_regex() {
    $SQLCMD -c "select $2 from keys where doc->'userIDs'->0->>'keywords' ~ '$1';"
}

s_keywords_tsquery() {
    $SQLCMD -c "select $2 from keys, to_tsquery($1) query where query @@ keywords;"
}

s_keywords_websearch() {
    $SQLCMD -c "select $2 from keys, websearch_to_tsquery('$1') query where query @@ keywords;"
}

s_modified_since() {
    $SQLCMD -c "SELECT $2 FROM keys WHERE mtime > TIMESTAMP '$1' ORDER BY mtime DESC LIMIT 100;"
}

[[ ${1:-} ]] || usage

COLUMNS='reverse(rfingerprint),mtime,keywords'
if [[ $1 == -v ]]; then
    shift
    [[ ${1:-} ]] || usage
    COLUMNS='reverse(rfingerprint),*'
elif [[ $1 == -j ]]; then
    shift
    [[ ${1:-} ]] || usage
    COLUMNS='doc'
fi

if [[ $1 == -f ]]; then
    shift
    [[ ${1:-} ]] || usage
    COMMAND=s_vfingerprint
elif [[ $1 == -r ]]; then
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
        $COMMAND "${pattern,,}" "$COLUMNS"
    done
else
    $COMMAND "${1,,}" "$COLUMNS"
fi
