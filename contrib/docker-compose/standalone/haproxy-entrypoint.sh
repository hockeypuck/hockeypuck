#!/bin/sh
export HOSTNAME=$(hostname)
export HOST_IP=$(hostname -i)

RELOAD_INTERVAL=${RELOAD_INTERVAL:-1800}

# Populate the LOCAL portions of the HAProxy configuration
for template in "${HAP_CONF_DIR}"/haproxy.d/*LOCAL*.cfg.tmpl; do
  config="${HAP_CONF_DIR}/haproxy.d/$(basename "$template" .tmpl)"
  [ ! -f "$config" ] &&
    cp "$template" "$config"
done

[ ! -d "${HAP_CONF_DIR}/lists" ] &&
  mkdir "${HAP_CONF_DIR}/lists"

# Make sure that black/whitelists exist, even if empty
for file in blacklist whitelist prometheus_whitelist; do
  [ ! -f "${HAP_CONF_DIR}/lists/$file.list" ] &&
    touch "${HAP_CONF_DIR}/lists/$file.list"
done

# Strip enclosing quotes, as docker-compose<1.29 does not parse shell metachars in .env
# See https://github.com/docker/compose/issues/8388
ALIAS_FQDNS="${ALIAS_FQDNS%\"}"
ALIAS_FQDNS="${ALIAS_FQDNS#\"}"
CLUSTER_FQDNS="${CLUSTER_FQDNS%\"}"
CLUSTER_FQDNS="${CLUSTER_FQDNS#\"}"
HAP_LOG_FORMAT="${HAP_LOG_FORMAT%\"}"
HAP_LOG_FORMAT="${HAP_LOG_FORMAT#\"}"

# And populate the aliases map
for alias in ${ALIAS_FQDNS:-} ${CLUSTER_FQDNS:-}; do
  echo "$alias $FQDN"
done > "${HAP_CONF_DIR}"/lists/aliases.map

# After we invoke 'exec' below, haproxy's PID will be the same as this shell
/bin/sh -c "
  while true; do
    sleep \"$RELOAD_INTERVAL\" & wait \${!}
    kill -HUP $$
  done
" &

exec haproxy "$@"
