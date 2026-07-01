# OTun egress deploy package

One unified binary (`otun-egress`) + systemd template = repeatable, scalable
egress deployment. Replaces the old "scp a per-protocol binary to /tmp and
`nohup &`" workflow.

## What's here

| File | Purpose |
|---|---|
| `otun-egress@.service` | systemd **template** unit — one instance per realm slot, `Restart=always`, runs as unprivileged `otun` user |
| `install.sh` | idempotent installer (binary → `/usr/local/bin`, unit → systemd, dirs/user). Does **not** start any slot. |
| `example-single.json` | single-rendezvous config (the common case) |
| `example-dual-rendezvous.json` | **problem 1A**: one egress registered to two rendezvous VPSes for failover |

## Build the binary

Reality needs uTLS, so build with the `with_utls` tag:

```bash
# native
go build -tags with_utls -o otun-egress ./cmd/otun-egress
# for a Debian/amd64 node (cross-compile from macOS)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags with_utls -o otun-egress-linux-amd64 ./cmd/otun-egress
```

One binary runs **all six** protocols (`hysteria2|tuic|reality|trojan|shadowsocks|vmess`),
chosen by the config's `protocol` field.

## Deploy a node

```bash
sudo ./install.sh ./otun-egress-linux-amd64
sudo cp example-single.json /etc/otun/egress/m1-hy2.json   # edit token/realm_id/port
sudo systemctl enable --now otun-egress@m1-hy2
journalctl -u otun-egress@m1-hy2 -f
```

N slots on one host = N config files + N enabled instances. They all share one
binary and one template unit.

## Problem 1A — rendezvous-VPS failover

The realm wire protocol is single-rendezvous / single-session per UDP socket by
design (zero-change Hy2 compat: a slot can have only one live session per
rendezvous). So failover is achieved by registering the **same egress** to
**multiple rendezvous** at once — `example-dual-rendezvous.json`:

- The binary starts one independent node per `rendezvous[]` entry (each its own
  UDP socket + `realm.Server`), all sharing the protocol + credentials + egress.
- A rendezvous being unreachable is **non-fatal**: that node logs the error and
  keeps retrying in the background; the other rendezvous stay up. The process
  only aborts if *every* rendezvous fails to bind its local socket.
- Client outbounds can point at any listed rendezvous. If rendezvous-A's VPS
  dies, clients using rendezvous-B still punch to the same egress IP.

Each `rendezvous[]` entry needs its **own `listen` port** (one UDP socket each).

## Notes / gotchas

- High listen ports (51820+) need no privileged caps; the unit runs as `otun`.
- Self-signed PoC TLS (client dials `insecure: true`). For production, wire real
  cert/key into the node packages.
- Reality config needs `private_key` / `short_id` / `server_name` (borrowed SNI)
  / `handshake_server` (use an **IP**, not a domain — see realm config pitfalls).
