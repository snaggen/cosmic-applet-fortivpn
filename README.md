# cosmic-applet-fortivpn

A COSMIC panel applet for a Fortinet SSL VPN with SAML/SSO login, built on
[openfortivpn](https://github.com/adrienverge/openfortivpn).

**Status:** several VPN accounts, SAML or password login (password in the keyring if wanted),
traffic statistics, dead-tunnel detection, clean disconnect before sleep, optional
reconnecting. Password login is untested against a real gateway.

Requires `openfortivpn` (at `/usr/bin/openfortivpn`), polkit and WebKitGTK 4.1 (building needs
`webkit2gtk4.1-devel` on Fedora).

## How it works

The panel runs one applet per output, so the tunnel is owned by an agent instead: the same
binary started with `--agent` through D-Bus activation, once per session. The applets show
its state and send it Connect/Disconnect over the session bus. The SAML login runs first, in
`cosmic-applet-fortivpn-login`, a WebKit window with its own profile that stays hidden while
the IdP session is valid. It stops at the gateway's redirect to openfortivpn's listener; the
agent then starts openfortivpn and hands it the session id, since openfortivpn waits only 50
seconds for a login. Without the window the system browser is used. The agent opens a window in
front of the user when they must act: to trust a certificate or to log in in the browser.

openfortivpn needs root, so the agent starts `cosmic-applet-fortivpn-helper` through pkexec.
The helper takes only a profile id and the login from the agent; the profiles (name, login
method, gateway, trusted certificate) are files in `/etc/cosmic-applet-fortivpn/profiles/`,
which only `cosmic-applet-fortivpn-configure` writes, and polkit requires an admin password
for that. openfortivpn's own config is never read or written: the helper passes a generated
file with `-c`. Closing the helper's stdin disconnects.

A gateway that leaves out its intermediate certificate is handled without a prompt: the
agent fetches the intermediate from the certificate's AIA address, and the helper checks the
completed chain against the system roots itself before trusting the certificate for that
connection. Otherwise the user is asked once per certificate.

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
