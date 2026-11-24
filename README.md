# cosmic-applet-fortivpn

A COSMIC panel applet for a Fortinet SSL VPN with SAML/SSO login, built on
[openfortivpn](https://github.com/adrienverge/openfortivpn).

**Status:** connects and disconnects, with SAML login in the system browser. The embedded
login, statistics and suspend handling are still to come.

Requires `openfortivpn` (at `/usr/bin/openfortivpn`) and polkit.

## How it works

The panel runs one applet per output, so the tunnel is owned by an agent instead: the same
binary started with `--agent` through D-Bus activation, once per session. The applets show
its state and send it Connect/Disconnect over the session bus. The agent opens a window in
front of the user when they must act: to trust a certificate or to log in in the browser.

openfortivpn needs root, so the agent starts `cosmic-applet-fortivpn-helper` through pkexec. The helper takes only the login from the
applet; the gateway and the trusted certificate come from `/etc/cosmic-applet-fortivpn/`,
which only `cosmic-applet-fortivpn-configure` writes, and polkit requires an admin password
for that. Closing the helper's stdin disconnects.

## Build and install

Tools are pinned with [mise](https://mise.jdx.dev/):

```sh
mise install
just check            # fmt, clippy, tests
just install-helper   # root helpers and polkit policy, through sudo
just install          # applet into ~/.local; override with: just prefix=/usr/local install
```

The installed desktop entry gets the absolute binary path, since the panel's PATH may not
contain the prefix. Then add the applet to the panel in COSMIC Settings → Desktop → Panel →
Applets.

## Translations

Strings live in `i18n/<lang>/cosmic_applet_fortivpn.ftl` (Fluent). English is the fallback.
A new language needs the same message ids as `i18n/en`; `cargo test` checks that.

## Tools

`scripts/gateway-test.sh <host:port> [openfortivpn options]` checks by hand whether a gateway
accepts openfortivpn with SAML login.
