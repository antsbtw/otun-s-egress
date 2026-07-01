#!/usr/bin/env bash
# Install/upgrade the OTun unified egress on a node (Debian/amd64).
# Idempotent: safe to re-run for upgrades. Does NOT start any slot — you enable
# slots explicitly so this never touches services you didn't ask for.
#
#   sudo ./install.sh ./otun-egress-linux-amd64
#   sudo cp my-slot.json /etc/otun/egress/m1-hy2.json
#   sudo systemctl enable --now otun-egress@m1-hy2
#
set -euo pipefail

BIN_SRC="${1:?usage: install.sh <path-to-otun-egress-binary>}"
PREFIX=/usr/local/bin
CONF_DIR=/etc/otun/egress
LOG_DIR=/var/log/otun
UNIT_SRC="$(dirname "$0")/otun-egress@.service"

echo "==> creating otun user/group (if missing)"
getent group otun >/dev/null || groupadd --system otun
getent passwd otun >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin -g otun otun

echo "==> installing binary -> $PREFIX/otun-egress"
install -m 0755 "$BIN_SRC" "$PREFIX/otun-egress"

echo "==> creating dirs"
install -d -m 0750 -o root -g otun "$CONF_DIR"
install -d -m 0755 -o otun -g otun "$LOG_DIR"

echo "==> installing systemd template unit"
install -m 0644 "$UNIT_SRC" /etc/systemd/system/otun-egress@.service
systemctl daemon-reload

echo "==> done. Drop configs in $CONF_DIR/<slot>.json then:"
echo "    systemctl enable --now otun-egress@<slot>"
echo "    journalctl -u otun-egress@<slot> -f"
