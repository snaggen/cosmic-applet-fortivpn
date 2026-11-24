#!/usr/bin/env bash
# Manual gateway test: does the FortiGate accept openfortivpn with SAML login?
#
# Usage: scripts/gateway-test.sh <host:port> [openfortivpn options...]
#
# Starts `openfortivpn --saml-login` (needs sudo) and opens the SAML start page in the
# default browser once openfortivpn listens on localhost:8020. Success is the line
# "Tunnel is up and running." Stop with Ctrl-C.
#
# Extra options go to openfortivpn, e.g. `--trusted-cert <sha256>` for a gateway that
# does not send its full certificate chain.
set -euo pipefail

gw=${1:?usage: $0 <host:port> [openfortivpn options...]}
shift

if ! command -v openfortivpn >/dev/null; then
    echo "openfortivpn is not installed: sudo dnf install openfortivpn" >&2
    exit 1
fi
if ! openfortivpn --help 2>&1 | grep -q -- --saml-login; then
    echo "this openfortivpn has no --saml-login" >&2
    exit 1
fi
if ip -br link | grep -q '^fctvpn'; then
    echo "FortiClient is connected; disconnect it first" >&2
    exit 1
fi

url="https://${gw}/remote/saml/start?redirect=1"

# Open the login page as the current user (not root) once the SAML listener is up.
# Waits up to 60 s, which also covers typing the sudo password.
(
    for _ in $(seq 60); do
        if ss -ltn 'sport = :8020' | grep -q LISTEN; then
            xdg-open "$url"
            exit 0
        fi
        sleep 1
    done
    echo "openfortivpn never listened on localhost:8020" >&2
) &

sudo openfortivpn "$gw" --saml-login -v "$@"
