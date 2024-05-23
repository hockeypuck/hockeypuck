# Standalone docker-compose deployment

The docker-compose and supporting scripts in this directory are useful for
running a full Hockeypuck deployment on a single machine.

Obviously, this will not be a highly-available deployment, but it can be useful
for a low-cost, low-maintenance deployment.

NB: all the below assume that you have `cd`-ed into this directory first.

# Supported platforms

Tested on Ubuntu 22.04 and Debian 11 (bullseye), with dependencies installed using `./setup.bash`.

Other platforms may work but will require some customization.
At minimum, docker (v18.06+) and docker-compose (v1.22+) must be installed in advance.

# Migration of legacy nginx deployments (!BREAKING CHANGES!)

If you created a standalone deployment before April 2023, you will need to migrate from nginx to haproxy.

* `cd` into this directory
* BACK UP ALL CONFIG FILES by incanting `cp -a . /path/to/somewhere/safe/`
* Incant `./mksite.bash` to apply the migrations to your configuration settings

If you have made local changes to the default nginx configuration, you will need to port these changes to haproxy.
Please open a ticket in the hockeypuck github project if you require assistance.

* Incant `docker-compose down --remove-orphans && docker-compose up -d` to bring up the new deployment
* You can now remove your nginx configuration by deleting the `nginx` subdirectory.

# Installation

* Register a DNS name for your server's public IP address.
* Configure your ingress firewall to allow ports: 80, 443, 11370, 11371
* Create a `.env` file by running `./mksite.bash`.
* Customize the settings in `.env` to your liking.
   * Set EMAIL and FINGERPRINT to the contact email and associated PGP fingerprint of the site admin.
   * Set FQDN and (optionally) ALIAS_FQDNS to the primary (and other) DNS name(s) of your server.
   * (Optional) Set ACME_SERVER to your internal CA if not using Let's Encrypt.
* Build hockeypuck by incanting `docker-compose build`.
* Set up TLS with `./init-letsencrypt.bash`. Answer the prompts as needed.
   If you want to test LE first with staging before getting a real cert,
   set the environment variable `CERTBOT_STAGING=1`.
* Download a keydump by running `./sync-sks-dump.bash`.
* Incant `docker-compose up -d` to start Hockeypuck and all dependencies.
   It will take several hours (or days) to load the keydump on first invocation.
   You can keep track of progress by running `docker-compose logs -f hockeypuck`.
* Once you are sure Hockeypuck has loaded all keys, you can run
   `./clean-sks-dump.bash` to remove the dump files and recover disk space.

## BEWARE

Docker-compose before v1.29 does not parse quoted values like a POSIX shell would.
This means that normally you should not quote values in `.env`,
as docker-compose's old behaviour is highly unintuitive.

The scripts in this directory try to compensate, and can parse *double* quotes around 
ALIAS_FQDNS, CLUSTER_FQDNS, and HKP_LOG_FORMAT values *only*,
as these values will normally contain whitespace and so most users will instinctively quote them anyway.

In all other cases, enclosing quotes MUST NOT be used.

# Configuration

* Hockeypuck configuration: `hockeypuck/etc/hockeypuck.conf`
* HAProxy configuration: `haproxy/etc/`
* Prometheus configuration: `prometheus/etc/prometheus.yml`

To reload all services after changing the configuration, incant `docker-compose restart`.

To gracefully reload HAProxy without downtime, incant `docker-compose kill -s HUP haproxy`.

# Upgrading

## Hockeypuck

To upgrade the Hockeypuck container to the latest commit, incant:

```
git pull
docker-compose build
docker-compose stop hockeypuck
docker-compose up -d
```

This will leave behind stale intermediate images, which may be quite large.
To clean them up, run `./clean-images.bash`.

## HAProxy

The HAProxy template configuration is volatile and may change significantly between releases.
To update your running configuration with changes from from upstream, incant the following:

```
git pull
docker-compose kill -s HUP haproxy
docker-compose restart haproxy_cache
docker-compose restart haproxy_internal
```

Note that this will not pick up any changes made to the `.env` or `docker-compose.yml` files.
For this, you will need to stop and recreate the HAProxy container:

```
docker-compose stop haproxy
docker-compose rm haproxy
docker-compose up -d
```

Beware however that this will cause a short interruption in service.

The HAProxy configuration is divided into several files under `./haproxy/etc/`.
Most are not intended to be user-editable, with the following exceptions:

* The files `./haproxy/etc/haproxy.d/*LOCAL*.cfg` should be edited iff you are running a high-availability cluster.
* The files `./haproxy/etc/lists/*` can be edited for white/blacklisting of client IPs.

The above files are not tracked in git and will not be overwritten on update.
If you modify any of the other files under `./haproxy/etc`, this may cause merge conflicts on update.
You should maintain a local branch if you want to configure these.

### HAProxy clustering

If you have more than one `docker-compose/standalone` stack, you can cluster them by configuring the following on each node:

* Bring the deployment up at least once in order to populate the local config files.
* Add _every_ FQDN of _all_ cluster members to `CLUSTER_FQDNS` in `./.env`
   * NOTE: This is not the same as `ALIAS_FQDNS`, because certbot will not provision SSL certificates for `CLUSTER_FQDNS`
* Add the IPs of all cluster members to `./haproxy/etc/lists/whitelist.list`, one per line in CIDR format
* Edit `./haproxy/etc/haproxy.d/90_LOCAL_be_hockeypuck.cfg`
   * Uncomment and edit the lines at the bottom to include each remote cluster member
* Edit `./haproxy/etc/haproxy.d/20_LOCAL_peers.cfg`
   * Uncomment and edit the lines at the bottom to include each remote cluster member
* Make sure that your firewall allows connectivity in from all cluster peers on ports 11371 and 1395

### HAProxy shim

It is also possible to use the HAProxy configuration as a WAF-only shim,
for insertion between an existing reverse proxy (e.g. Apache) and keyserver.
For guidelines, please see `README_SHIM.md` in this directory.

# Operation

## Monitoring

By default the prometheus monitoring console is not accessible from external IP addresses.
Add your permitted IPs to `haproxy/etc/lists/prometheus_whilelist.list` in CIDR format.
Once done, browse to `https://$FQDN/monitoring/prometheus` to access the monitoring console.

## Obtaining a new keyserver dump

Use `./sync-sks-dump.bash` to fetch a recent keyserver dump from a public location.
This script may need to be edited depending on the availability of dump servers.

## Loading a keyserver dump

Use `./load-sks-dump.bash` to load the keyserver dump (make sure that Hockeypuck is not running).
This can be I/O intensive on PostgreSQL and may take several hours (or days) to complete.

## Removing stale dumpfiles

Use `./clean-sks-dump.bash` to remove stale dump files from the import volume and save space.
This will preserve the timestamp file that indicates a keydump has been loaded.
To start from scratch instead, destroy the import volume using `docker volume rm pgp_import`.

## Blacklisting and deleting keys

To blacklist a key, add its full fingerprint (without any `0x`) to the `hockeypuck.openpgp.blacklist` array in `hockeypuck/etc/hockeypuck.conf`, e.g.:

```
[hockeypuck.openpgp]
blacklist=[
   "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
]
```

Note that blacklisting will only prevent updates to this key via e.g. gossip.
It WILL NOT delete any existing keys in the postgres database.
To delete a key or keys from the database, use the `delete-keys.bash` script in this directory:

```
./delete-keys.bash DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
```

You can delete multiple keys by providing multiple arguments.

In case of accidental deletion, you will need to remove the key from the blacklist and then rebuild your PTtree (see below).

# Debugging

## PTree corruption

Hockeypuck can sometimes suffer from PTree corruption.
Signs of corruption include:

* A key count that diverges significantly from its direct peers
* Key searches that produce stale output
* Missing keys

If any of the above persist for several days, rebuilding the PTree may help.
First, stop the running hockeypuck using `docker-compose down`.
Then run `./ptree-rebuild.bash`, and finally `docker-compose up -d`.
