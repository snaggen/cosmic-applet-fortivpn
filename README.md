# cosmic-applet-fortivpn

A COSMIC panel applet for a Fortinet SSL VPN with SAML/SSO login, built on
[openfortivpn](https://github.com/adrienverge/openfortivpn).

**Status:** early skeleton. It shows a panel icon and a popover, nothing more yet.

## Build and install

Tools are pinned with [mise](https://mise.jdx.dev/):

```sh
mise install
just check      # fmt, clippy, tests
just install    # into ~/.local; override with: just prefix=/usr/local install
```

Then add the applet to the panel in COSMIC Settings → Desktop → Panel → Applets.

## Translations

Strings live in `i18n/<lang>/cosmic_applet_fortivpn.ftl` (Fluent). English is the fallback.
A new language needs the same message ids as `i18n/en`; `cargo test` checks that.

## Tools

`scripts/gateway-test.sh <host:port> [openfortivpn options]` checks by hand whether a gateway
accepts openfortivpn with SAML login.
