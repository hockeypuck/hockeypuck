# Repository structure

This repository is structured as follows:

* `contrib`
    * `bin`
        The standard startup script that handles database population on first startup.
    * `config`
        Sample configuration files.
    * `docker-compose`
        Deployment configurations for docker-compose.
        * `devel`
            Development-grade deployment.
        * `standalone`
            Single-node production-grade deployment.
    * `pyinfra`
        Deployment configuration for pyinfra.
    * `templates`
        Go template files for serving the human-readable HKP index and stats pages.
    * `webroot`
        Human-readable search and error pages, forked from `github.com/mattrude/pgpkeyserver-lite`.
* `debian`
    Debian package configuration.
* `scripts`
    Tools for publishing releases.
* `snap`
    Snapcraft package configuration (placeholder).
* `src`
    * `hockeypuck`
        * `conflux`
            Large dataset recon protocol implementation (used by SKS).
            The data types are defined in the top level, and the recon protocol itself is in a subfolder.
        * `hkp`
            HKP service implementation.
            * `jsonhkp`
                Summary of PGP key info in JSON format suitable for go templating (see `contrib/templates`).
            * `pks`
                PKS protocol (not currently enabled).
            * `sks`
                SKS protocol (calls `conflux`).
            * `storage`
                Abstract back-end storage model.
                * `mock`
                    Partial in-memory storage implementation for unit testing only.
        * `logrus`
            Logging library, forked from `github.com/Sirupsen/logrus`.
        * `metrics`
            Metrics endpoint for prometheus to query.
        * `openpgp`
            OpenPGP grammar model; does not perform any crypto (delegates to `go-crypto/openpgp`).
        * `pghkp`
            Implementation of back-end storage model for PostgreSQL.
        * `pgtest`
            Test harness for `pghkp`.
        * `server`
            Top-level application code; also includes command-line utilities and (unmaintained) sample config files.
        * `testing`
            Test harness and data for unit tests.
        * `vendor`
            Vendored dependencies, managed by `go mod`.


# Consolidation of Hockeypuck project repositories

Sources have been aggregated from several Hockeypuck Github projects here as subtrees.
These were added with the following commands:

    git subtree add --prefix=src/hockeypuck/conflux https://github.com/hockeypuck/conflux master --squash
    git subtree add --prefix=src/hockeypuck/hkp https://github.com/hockeypuck/hkp master --squash
    git subtree add --prefix=src/hockeypuck/logrus https://github.com/hockeypuck/logrus master --squash
    git subtree add --prefix=src/hockeypuck/mgohkp https://github.com/hockeypuck/mgohkp master --squash
    git subtree add --prefix=src/hockeypuck/openpgp https://github.com/hockeypuck/openpgp master --squash
    git subtree add --prefix=src/hockeypuck/pghkp https://github.com/hockeypuck/pghkp master --squash
    git subtree add --prefix=src/hockeypuck/pgtest https://github.com/hockeypuck/pgtest master --squash
    git subtree add --prefix=src/hockeypuck/server https://github.com/hockeypuck/server master --squash
    git subtree add --prefix=src/hockeypuck/testing https://github.com/hockeypuck/testing master --squash

(Note that the mgohkp back end has since been removed)

The upstream Github projects have been archived.
Any new development on Hockeypuck should be proposed here.
