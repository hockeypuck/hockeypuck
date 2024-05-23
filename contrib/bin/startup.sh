#!/bin/sh
# Ensure that some data has been imported before running the server

hkp=/hockeypuck
bin=$hkp/bin
config=$hkp/etc/hockeypuck.conf

data=$hkp/data
ptree=$data/ptree

keydump=$hkp/import/dump
timestamp=$keydump/.import-timestamp

if [ ! -f $config ]
then
  cat << EOF >&2
$config missing, please copy from
./contrib/docker-compose/devel/hockeypuck/etc and adapt.
ABORTING
EOF
  exit 1
fi

if ! grep -q '^path=' $config
then
  cat << EOF >&2
Path for prefix tree missing from $config,
please correct (see ./contrib/docker-compose/devel/hockeypuck/etc)
and restart.
ABORTING
EOF
  exit 1
fi

if ! grep -q "^path=\"$ptree\"" $config
then
  # Case 1. Update from a previous version: do not try to perform an
  # (unnecessary, slow) import
  echo "Non-standard or previous setup found: Skipping keydump import"
elif [ ! -d $ptree -o ! -f $timestamp ]
then
  # Case 2: First run: make sure we run an import
  if ! ls $keydump/*.pgp >/dev/null 2>&1
  then
    cat << EOF >&2
First run detected but no keydump available. Please obtain one from e.g.
one of the URLs in ./contrib/data-sources.md and put it in ./keydump
ABORTING
EOF
    exit 1
  else
    mkdir -p $ptree
    echo "Importing PGP files from keydump..."
    $bin/hockeypuck-load -config $config $keydump/\*.pgp || exit 1
    touch $timestamp
  fi
else
  # Case 3: Further runs: only perform an import, if things have been updated.
  # This is rare, but here as it is hard to stop the daemon from auto-starting.
  echo "Importing any PGP files newer than the timestamp..."
  find $keydump -name "*.pgp" -newer $timestamp -print0 | \
    xargs -0r $bin/hockeypuck-load -config $config || exit 1
fi

echo "Starting hockeypuck daemon..."
exec $bin/hockeypuck -config $config
