# Recon PROXY protocol support

## Problem

Hockeypuck authorizes inbound reconciliation (recon/gossip) connections by
matching the **source IP** of the connection against the configured recon
partners (`[conflux.recon.partner.*]`) and `allowCIDRs`. See
`(*Peer).Serve` → `matcher.Match(ip)` in `conflux/recon/peer.go`.

When recon is fronted by a load balancer such as HAProxy in **TCP mode**, the
source IP that Hockeypuck sees is the load balancer's, not the real peer's, so
partner matching fails. The usual workaround is to DNAT the real client IPs
through to the backend, which is operationally awkward and does not compose well
with HAProxy.

The [PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt)
solves this: the proxy prepends a small header to the TCP stream carrying the
real client address. Hockeypuck can parse that header and use the real address
for partner matching.

## Design

PROXY protocol is only meaningful for **inbound** recon. Outbound gossip
(`InitiateRecon`) dials partners directly; when those partners are fronted by a
load balancer, the load balancer generates the PROXY header itself (HAProxy
`send-proxy-v2`), so Hockeypuck never needs to emit one.

Rather than change the existing recon listener (which would break direct,
internal peers that do **not** speak PROXY protocol), Hockeypuck can run an
**additional, opt-in listener** on a separate port that expects a PROXY header
on every connection. This means:

- Internal peers keep connecting directly to the normal `reconAddr` — unchanged.
- External peers reach you via the load balancer's public TCP frontend, which
  forwards to the dedicated PROXY-protocol port with `send-proxy-v2`.

### Trust model

A forged PROXY header would let an attacker who can reach the port impersonate
any partner. To prevent this, the PROXY listener only honours headers from a
configured allow-list of **trusted proxies**:

- A connection from a trusted proxy address **must** carry a valid PROXY header
  (`REQUIRE`); the parsed client address is then used for partner matching.
- A connection from any other source is dropped immediately, before the recon
  handshake begins.
- If `trustedProxies` is left empty, a valid header is required from *every*
  connection but the source address is not restricted — only safe when the port
  is reachable solely by your proxy (network/firewall isolation).

This is implemented with `github.com/pires/go-proxyproto` and a custom
connection policy in `conflux/recon/peer.go` (`proxyProtocolPolicy`).

## Configuration

```toml
[hockeypuck.conflux.recon]
# The normal, plain-TCP recon listener. Internal peers that connect directly
# (no load balancer) keep using this, unchanged.
reconAddr=":11370"
# Direct internal peers are still authorized the usual way.
allowCIDRs=["10.0.0.0/8"]

# Optional additional listener that expects a PROXY protocol (v1 or v2) header.
[hockeypuck.conflux.recon.proxyProtocol]
# Turn the extra listener on.
enabled=true
# A DISTINCT address from reconAddr above. Your load balancer's TCP backend
# should send-proxy-v2 to this port.
reconAddr=":11372"
# Source IPs / CIDRs allowed to send PROXY headers (your load balancer nodes).
# Anything else connecting here is dropped. Leave empty only if the port is
# isolated to your proxy by other means.
trustedProxies=["10.0.0.5/32", "10.0.0.6/32"]
# How long to wait for the PROXY header before giving up. Optional; defaults
# to 10 seconds.
headerTimeoutSecs=10
```

Notes:

- `proxyProtocol.reconAddr` **must** differ from `reconAddr`; Hockeypuck refuses
  to start otherwise.
- `proxyProtocol.reconNet` may be set (defaults to `tcp`).
- The real client IPs delivered via the PROXY header must still match a
  configured partner or `allowCIDRs` entry — PROXY protocol restores the real
  address, it does not bypass authorization.

## Serve-only (no outbound gossip)

A peer behind a load balancer can optionally **serve inbound recon without ever
initiating outbound gossip**, relying on partners to connect to it:

```toml
[hockeypuck.conflux.recon]
gossip=false   # defaults to true
```

This works because SKS reconciliation is symmetric within a single session:
when a partner gossips in, both sides recover what they are missing, and keys
submitted locally still propagate outward as partners pull them. The trade-off
is that syncing then happens on the partners' gossip cadence rather than yours.

A useful side effect for the load-balanced topology: with outbound gossip
disabled, the only remaining outbound traffic is HTTP key *recovery* to a
partner's public HKP endpoint, which is not subject to source-IP partner
matching. That removes any need to make outbound recon egress from a particular
(e.g. load-balancer) address.

Note that `reconAddr="none"` is the opposite switch: it disables the inbound
listener and runs gossip-only. Combining `reconAddr="none"` with `gossip=false`
leaves the peer idle (neither serving nor gossiping).

## HAProxy example

Front the public recon port with a TCP-mode frontend and forward to Hockeypuck's
PROXY-protocol port with `send-proxy-v2`:

```haproxy
frontend recon_in
    mode tcp
    bind :11370
    default_backend hockeypuck_recon

backend hockeypuck_recon
    mode tcp
    # send-proxy-v2 prepends the PROXY header carrying the real client address.
    server hkp1 10.0.0.10:11372 send-proxy-v2
```

With this in place:

- External peers point their gossip at your HAProxy `:11370` (public).
- HAProxy forwards to Hockeypuck `:11372` with the real client address in the
  PROXY header.
- Hockeypuck parses it, confirms the connection came from a trusted proxy
  (`10.0.0.x`), and matches the real client IP against your partners.
- Internal peers continue to hit Hockeypuck `:11370` directly with no PROXY
  protocol involved.
