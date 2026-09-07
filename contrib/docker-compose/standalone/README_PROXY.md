# Standalone docker-compose deployment without SSL/TLS termination

You can insert HAProxy as a shim between an existing reverse proxy and keyserver,
keeping your existing SSL termination etc. in place and using HAProxy just for its rate limiting features.

    Existing proxy (e.g. Apache) [ -> HAProxy ] -> Keyserver

To do this, you can invoke a custom `docker-compose` config with the keyserver and certbot services disabled.

BEWARE that the following is EXPERIMENTAL and provided as a guideline only. Your mileage WILL vary.

# Installation and configuration

A common use case is that of an Apache or Nginx reverse proxy installed on Linux.
In this case we can update the reverse proxy machine to install and reference the shim without touching the back end.

1. Install `docker` and `docker-compose`, or docker compose v2, on the same machine as your existing proxy.

2. Clone this repo and `cd` into this directory, e.g.:

```
cd /usr/local
git clone https://github.com/hockeypuck/hockeypuck
cd hockeypuck/contrib/docker-compose/standalone
```

3. Populate the default site settings:

```
./mksite.bash
```

4. Edit the newly-created `.env` file:

* `FQDN` and `ALIAS_FQDNS` should be self-explanatory
* `KEYSERVER_HOST_PORT` should be uncommented and point to your existing keyserver HKP port (e.g. `keyserver-backend.example.com:11371`)
* `HAP_HTTP_HOST_PORT` should be set to unused localhost port e.g. `10000`
* `HAP_HTTPS_HOST_PORT` should be set to unused localhost port e.g. `10001`
* `HAP_HKP_HOST_PORT` should be set to unused localhost port e.g. `10002`
* `HAP_BEHIND_PROXY` should be uncommented and set to `true`

You can safely ignore the other settings.

Note that `KEYSERVER_HOST_PORT` is resolved inside the docker container, so `localhost:11371` will not work.
If you are running the keyserver on the same machine as the reverse proxy, you should use the docker host IP here,
e.g. `172.17.0.1:11371`, and make sure that your host iptables allows for incoming connections on the `docker0` interface.

At this point, haproxy is configured to talk to your keyserver back end, but to listen only on some unused localhost ports.
In this configuration it should not clash with anything you already have running on that machine.

Finally, if the reverse proxy and Hockeypuck don't run on the same machine, you will need to tunnel TCP port 11370 used for reconciliation.
It uses a binary protocol and cannot be proxied with a regular web server since it doesn't speak HTTP.
You may use `socat` for that, here is a systemd service file for reference:

```systemd
# hockeypuck-tunnel.service

[Unit]
Description=Hockeypuck tunnel for TCP port 11370
After=network.target

[Service]
PrivateTmp=true
ProtectHome=true
ProtectProc=invisible
ProtectSystem=full
ExecStart=/usr/bin/socat tcp-listen:11370,reuseaddr,fork tcp:10.1.2.3:11370
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Replace 10.1.2.3 with the IP address of the Hockeypuck machine.


# Testing and operation

To bring up HAProxy, make sure you are cd-ed into the `standalone` directory and incant:

```
docker-compose -f docker-compose-proxy.yml up -d
```

or, if using docker compose v2:

```
docker compose -f docker-compose-proxy.yml up -d
```

It should start the following containers only:

* standalone-haproxy-1
* standalone-haproxy-cache-1
* standalone-haproxy-internal-1
* standalone-hockeypuck-1
* standalone-postgres-1

To verify, incant

```
docker-compose -f docker-compose-proxy.yml ps
```

or, if using docker compose v2:

```
docker compose -f docker-compose-proxy.yml ps
```

to check that they are all running, and

```
docker-compose -f docker-compose-proxy.yml logs -f <service>
```

or, if using docker compose v2:

```
docker compose -f docker-compose-proxy.yml logs -f <service>
```

to check the logs of each in turn for any obvious error messages.

(BTW yes, there are two `-f` options in the `logs` command; they mean different things depending on what order they come in the argument list)

To shut down, incant:

```
docker-compose -f docker-compose-proxy.yml down
```

or, if using docker compose v2:

```
docker compose -f docker-compose-proxy.yml down
```
