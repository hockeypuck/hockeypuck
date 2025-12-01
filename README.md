# Hockeypuck

Hockeypuck is an OpenPGP public keyserver.

## Releases

Hockeypuck uses semantic versioning and should always be installed from the current release tag (or release branch) for production use.
The `master` git branch and `latest` docker image should be considered alpha-quality, and may contain breaking changes.

The current release branch is [2.3](https://github.com/hockeypuck/hockeypuck/tree/branch-2.3)

If you wish to configure SKS peering, you should ensure that all peers are using the same minor version.
Hockeypuck is not guaranteed to sync successfully between different minor versions.

# Quick start with docker-compose (for testing)

A quick and easy way to run Hockeypuck locally is with `docker-compose`.
First, obtain a keydump from an existing server.
A partial list of dump sources can be found in `contrib/data-sources.md`.
Unpack the `*.pgp` files from the dump under `contrib/docker-compose/devel/keydump/`, then:

    cd contrib/docker-compose/devel
    docker-compose up -d

You can change the configuration by editing `contrib/docker-compose/devel/etc/hockeypuck.conf` and running `docker-compose restart`.
To stop, run `docker-compose down`.

## Building docker on Windows

BEWARE that if you are building a docker image on Windows, you MUST clone this repository with `autocrlf` disabled:

```
git clone --config core.autocrlf=false https://github.com/hockeypuck/hockeypuck
```

See https://stackoverflow.com/questions/53165471/building-docker-images-on-windows-entrypoint-script-no-such-file-or-directory

# Production deployment with docker-compose (RECOMMENDED for most users)

You can use `docker-compose` to build and deploy a standalone Hockeypuck instance in a production environment.
This includes automated database population and TLS certificate management.

See `contrib/docker-compose/standalone/README.md` for full instructions.

# Installing with Ansible

Add this to your ansible playbook to deploy hockeypuck using the [`sebix.hockeypuck`](https://galaxy.ansible.com/sebix/hockeypuck) ansible role:

```
    - hosts: servers
      roles:
        - sebix.hockeypuck
      vars:
        # optional variables, see documentation for a complete list and default values
        - hockeypuck_contact: "YOUR_KEY_FINGERPRINT"
```

# Building

## Any platform/arch

With Go 1.24 installed, simply run:

    make build

Hockeypuck binaries will be in `bin/`.

Optionally run `sudo make install` to install the executables to `/usr/bin/`.
It will also install configuration examples and static files.

## Vendored Dependencies

The dependencies for this project are managed via Go modules.
To update the dependencies run:

    cd src/hockeypuck
    go get -u -m
    go mod vendor

After which you can ensure that the code continues to build and
that the tests still pass.

## Ubuntu package maintainers

To locally build the hockeypuck binaries:

    make install-build-depends
    make

# Releases

## Building a Snap

If it's installed, remove the snapcraft Ubuntu package:

    sudo apt remove snapcraft

Install snapcraft from the Snap store:

    snap install snapcraft

Confirm that you're using a recent enough version of snapcraft:

    $ which snapcraft
    /snap/bin/snapcraft
    $ snapcraft version
    snapcraft, version 3.7.2
    $ _

Now you can build the snap:

    snapcraft snap

snapcraft defaults to building in a multipass VM.  If you're already
in a throwaway environment, you can build the snap as follows instead:

    SNAPCRAFT_BUILD_ENVIRONMENT=host snapcraft snap

Or use LXD for a lighter-weight isolated build:

    SNAPCRAFT_BUILD_ENVIRONMENT=lxd snapcraft snap

Enabling cpu or memory profiling:

    sudo snap set hockeypuck cpuprof=1
    sudo snap set hockeypuck memprof=1
    sudo systemctl restart snap.hockeypuck.hockeypuck.service

Disabling cpu or memory profiling:

    sudo snap unset hockeypuck cpuprof
    sudo snap unset hockeypuck memprof
    sudo systemctl restart snap.hockeypuck.hockeypuck.service

## Ubuntu package maintainers

In order to release a new version of hockeypuck:

    make dch
    git add debian/changelog
    git commit -m 'x.y.z release'
    git tag -s -u <keyid> -m 'x.y.z release' x.y.z
    git push --tags
    make deb-src
    dput <your ppa> ../hockeypuck\_x.y.z\_source.changes

Where `x.y.z` is the appropriate version number.
This will upload the debian source package to the Launchpad PPA for building.

# Configuration file templating and format

The configuration file supports templating using the Go text/template package with Sprig extensions.
The template is rendered before the configuration file is parsed, so the configuration file can contain
environment variables as well.

For example, setting the database configuration to use environment variables:

```toml
[hockeypuck.openpgp.db]
driver="postgres-jsonb"
dsn="database=hkp host=postgres user={{ .POSTGRES_USER }} password={{ .POSTGRES_PASSWORD }} port=5432 sslmode=disable"
```

You can also use the `osenv` custom function to read environment variables by prefix:

```toml
{{ range $key, $value := osenv "HKP_" }}
{{ $key }}={{ $value }}
{{ end }}
```

# About

Copyright 2012-2025 Casey Marshall and the Hockeypuck Contributors.
See CONTRIBUTORS and LICENSE for details.
