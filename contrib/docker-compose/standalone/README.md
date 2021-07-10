# Standalone docker-compose deployment

The docker-compose and supporting scripts in this directory are useful for
running a full Hockeypuck deployment on a single machine.

Obviously, this will not be a highly-available deployment, but it can be useful
for a low-cost, low-maintenance deployment.

# Supported platforms

Tested on Ubuntu 18.04 and 20.04, with dependencies installed using `./setup.bash`.

Other platforms may work but may require some customization.

# Building

* `cd` to the base directory of this repository
* Run `docker build .` - it should return e.g. "Successfully built DEADBEEF1234"
* Tag the build: `docker tag DEADBEEF1234 hockeypuck/hockeypuck:RELEASE`
  (replacing `DEADBEEF1234` with the hash emitted by `docker build .`,
  and `RELEASE` as appropriate, cf `../../../debian/changelog` and/or `./mksite.bash`)
* Now `cd` back to this directory before continuing below

# Installation

* (Optional) Register a DNS name for your server's public IP address.
* Configure your ingress firewall to allow ports: 80, 443, 11370, 11371
* Create a `.env` file by running `./mksite.bash`.
* Customize the settings in `.env` to your liking.
   DO NOT surround values with double quotes.
   Make sure that `RELEASE` matches the docker tag you created above.
   (Optional) If you're using DNS & TLS, make sure FQDN and EMAIL are correct;
   they're used for Let's Encrypt.
* Generate hockeypuck and nginx configuration from your site settings with
   `./mkconfig.bash`.
* (Optional) Set up TLS with `./init-letsencrypt.bash`. Answer the prompts as
   needed. If you want to test LE first with staging before getting a real
   cert, set the environment variable `CERTBOT_STAGING=1`.
* Download a keydump by running `./sync-sks-dump.bash`.
* Incant `docker-compose up -d` to start Hockeypuck and all dependencies.
   It will take several hours (or days) to load the keydump on first invocation.
   You can keep track of progress by running `docker logs standalone_hockeypuck_1`.
* Once you are sure Hockeypuck has loaded all keys, you can run
   `./clean-sks-dump.bash` to remove the dump files and recover disk space.

# Configuration

* Hockeypuck configuration: `hockeypuck/etc/hockeypuck.conf`
* NGINX configuration: `nginx/conf.d/hockeypuck.conf`
* Prometheus configuration: `prometheus/etc/prometheus.yml`

To reload services after changing the configuration, incant `docker-compose restart`.

# Operation

## Monitoring

Browse to `https://FQDN/monitoring/prometheus` to access prometheus. If you don't want this
to be public, edit `nginx/conf.d/hockeypuck.conf` to your liking.

## Obtaining a new keyserver dump

Use `sync-sks-dump.bash` to fetch a recent keyserver dump from a public location.
This script may need to be edited depending on the availability of dump servers.

## Loading a keyserver dump

Use `load-sks-dump.bash` to load the keyserver dump (make sure that Hockeypuck is not running).
This can be I/O intensive on PostgreSQL and may take several hours (or days) to complete.

## Removing stale dumpfiles

Use `./clean-sks-dump.bash` to remove stale dump files from the import volume and save space.
This will preserve the timestamp file that indicates a keydump has been loaded.
To start from scratch instead, destroy the import volume using `docker volume rm pgp_import`.
