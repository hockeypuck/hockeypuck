# README

If you are running `docker compose` in this directory for the first time and have not previously downloaded the `postgres:latest` docker image, or if you have recently pulled `postgres:latest`, then postgres may fail to start up with the following error:

```
postgres-1  | Error: in 18+, these Docker images are configured to store database data in a
postgres-1  |        format which is compatible with "pg_ctlcluster" (specifically, using
postgres-1  |        major-version-specific directory names).  This better reflects how
postgres-1  |        PostgreSQL itself works, and how upgrades are to be performed.
postgres-1  |
postgres-1  |        See also https://github.com/docker-library/postgres/pull/1259
postgres-1  |
postgres-1  |        Counter to that, there appears to be PostgreSQL data in:
postgres-1  |          /var/lib/postgresql/data (unused mount/volume)
postgres-1  |
postgres-1  |        This is usually the result of upgrading the Docker image without
postgres-1  |        upgrading the underlying database using "pg_upgrade" (which requires both
postgres-1  |        versions).
postgres-1  |
postgres-1  |        The suggested container configuration for 18+ is to place a single mount
postgres-1  |        at /var/lib/postgresql which will then place PostgreSQL data in a
postgres-1  |        subdirectory, allowing usage of "pg_upgrade --link" without mount point
postgres-1  |        boundary issues.
postgres-1  |
postgres-1  |        See https://github.com/docker-library/postgres/issues/37 for a (long)
postgres-1  |        discussion around this process, and suggestions for how to do so.
```

To fix this error, create a `.env` file in this directory and put the following in it:

```
POSTGRES_IMAGE=pgautoupgrade/pgautoupgrade
POSTGRES_VERSION=18-debian
PG_DATA_MOUNT=/var/lib/postgresql
```
