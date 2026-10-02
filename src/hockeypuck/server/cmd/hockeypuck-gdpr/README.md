# hockeypuck-gdpr

Services data subject erasure requests ("right to be forgotten", GDPR Art. 17)
against a Hockeypuck keyserver.

It reads the ordinary `hockeypuck.conf`, so it talks to the same database,
reconciliation prefix tree and blacklist as the server itself. There is nothing
to configure separately and no database credentials to keep in a second place.

## Why not just delete the rows

`contrib/docker-compose/standalone/delete-keys.bash` deletes straight from
Postgres. That leaves two things undone, and both of them undo the erasure:

* **The reconciliation prefix tree still contains the key's digest.** This node
  keeps advertising key material it no longer has, and partners keep trying to
  recover it.
* **Partners still hold the key.** Unless the fingerprint is blacklisted, the
  next reconciliation round puts it straight back, usually within hours.

`hockeypuck-gdpr` erases through the server's own storage layer, so the prefix
tree is updated with the database, and it reports and maintains the blacklist
entries that keep the erasure from being reversed.

## Working through a request

```console
# 1. Find what the request is actually about.
$ hockeypuck-gdpr search alice@example.com

# 2. Keep a copy, in case the request turns out to be mistaken or fraudulent.
$ hockeypuck-gdpr export -case GDPR-2026-001 -o ./evidence alice@example.com

# 3. Preview. This needs no locks, so it can be run while the server is up.
$ hockeypuck-gdpr erase -case GDPR-2026-001 -dry-run alice@example.com

# 4. Erase. Stop hockeypuck first, so the prefix tree can be updated.
$ sudo systemctl stop hockeypuck
$ sudo -u hockeypuck hockeypuck-gdpr erase \
    -case GDPR-2026-001 \
    -requester alice@example.com \
    -reason "Art.17(1)(a), identity verified 2026-08-20" \
    -blacklist-out /etc/hockeypuck/gdpr-blacklist.toml \
    alice@example.com

# 5. Merge the generated blacklist into hockeypuck.conf, then restart.
$ sudo systemctl start hockeypuck

# 6. Confirm, now and later.
$ hockeypuck-gdpr verify -case GDPR-2026-001
$ hockeypuck-gdpr blacklist -check
```

Steps 5 and 6 are the ones that are easy to skip and expensive to get wrong.
`verify` and `blacklist -check` both exit non-zero when something is amiss and
touch only the database, so they are worth running from cron.

## Search terms

Every command that takes a `TERM` classifies it automatically:

| Term | Treated as |
| --- | --- |
| `0x19CAA24EBD1BA88D`, `19caa24ebd1ba88d` | key ID |
| `5AD8 9A35 C128 4FF0 43F5  55B6 19CA A24E BD1B A88D` | fingerprint |
| `alice@example.com`, `Alice <alice@example.com>` | user ID identity |
| anything else | free text key word search |

Prefix a term with `fp:`, `keyid:`, `email:` or `keyword:` to override the
guess. Key IDs and subkey fingerprints resolve to the primary key that owns
them, since that is the unit that can be erased. `-f FILE` reads terms from a
file (or from stdin, as `-f -`), one per line, ignoring blanks and `#` comments.

## The audit trail

Every export, erasure and reappearance is appended to a JSON Lines audit trail,
by default beside the reconciliation database, overridable with `-audit` or
`$HOCKEYPUCK_GDPR_AUDIT`. `verify` and `blacklist` read the fingerprints they
work on from it, so a request stays actionable long after the shell history has
gone.

User IDs are recorded as a digest rather than verbatim, so that the trail does
not itself become a store of the personal data the request asked you to erase.
The digest is enough to confirm that the key erased was the key the request
described. Pass `-record-uids` if your own retention policy calls for the full
text. The same caution applies to `-evidence` and `export` output: those files
contain exactly what was asked to be erased, so store them accordingly and
delete them once your appeal window closes.

## Erasing without stopping the server

`-no-ptree` erases from the database only. It lets an urgent request be
actioned against a live server, at the cost of leaving the prefix tree
advertising key material that is no longer there. Repairing that means removing
the tree and rebuilding it, because `hockeypuck-pbuild` only inserts and cannot
retract a digest on its own:

```console
$ sudo systemctl stop hockeypuck
$ sudo -u hockeypuck rm -rf /var/lib/hockeypuck/recon.db
$ sudo -u hockeypuck hockeypuck-pbuild -config /etc/hockeypuck/hockeypuck.conf
$ sudo systemctl start hockeypuck
```

Prefer stopping the server for the erasure itself; it is the shorter outage.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | the command found what it was looking for and you need to act: keys reappeared, fingerprints are unblacklisted, an erasure failed |
| 2 | the request did not make sense, or a precondition is unmet (the server holds the prefix tree lock) |
