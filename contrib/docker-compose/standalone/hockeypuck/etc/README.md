# Sample hockeypuck configuration

The config file in this directory is optimised for hockeypuck's `docker-compose/standalone` deployment, and Should Just Work (TM) out of the box.
(see `contrib/docker-compose/standalone/README.md` for full instructions)

If you are NOT using `docker-compose/standalone` you MUST copy the `hockeypuck.conf.tmpl` files to `hockeypuck.conf` before use.
This allows you to edit the configuration without introducing git merge conflicts.

To facilitate portability, these files have been parameterised using hockeypuck template substitution, i.e. "{{ .ENVAR }}"
You can populate these values at runtime by setting the corresponding environment variables:

* FQDN                  the FQDN of this server
* FINGERPRINT           the fingerprint of the server operator's OpenPGP key
* POSTGRES_USER         the credentials used to connect to the PostgreSQL backend
* POSTGRES_PASSWORD     

These envars are normally supplied by `contrib/docker-compose/standalone/docker-compose.yml`.
