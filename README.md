# OpenFortiVPN for COSMIC

A [COSMIC](https://system76.com/cosmic) panel applet for Fortinet SSL VPNs, built on
[openfortivpn](https://github.com/adrienverge/openfortivpn). It is an alternative to
FortiClient. It logs in with SAML single sign-on or with a username and password. It does not
leave a dead tunnel behind after suspend or a network change.

This project is not affiliated with Fortinet.

## Features

- **Several VPN accounts**, one tunnel at a time. Connecting an account disconnects the
  current one first.
- **SAML single sign-on** in a small login window of its own. While the identity provider's
  session is valid, the login completes without showing a window. A second factor works,
  however long it takes.
- **Username and password**, optionally kept in the keyring, with an optional one-time code.
- **Gateway certificates:**
  - Some gateways leave out their intermediate certificate. This is a common
    misconfiguration that makes FortiClient ask for an exception. The applet completes the
    chain itself, without a prompt.
  - Any other certificate that does not validate is shown in a dialog. You can trust it once
    or always.
- **Dead tunnels are noticed:** when a tunnel stops carrying traffic, or its network goes
  away, the applet takes it down and reports it. It does not keep showing "connected".
- **Suspend:** the tunnel is disconnected cleanly before the system sleeps.
- **Reconnect automatically** after a lost tunnel or after resume. This is off by default.
- Traffic, address and uptime in the popover.
- A notification when a connection fails or is lost.
- English and Swedish.

## Requirements

- COSMIC desktop
- `openfortivpn` at `/usr/bin/openfortivpn`, with `pppd`
- polkit
- WebKitGTK 4.1 (`webkit2gtk4.1` on Fedora)
- A Secret Service keyring (GNOME Keyring, KeePassXC, …), only to remember passwords

To build, you need:
- Rust, pinned with [mise](https://mise.jdx.dev/)
- [just](https://just.systems/)
- the development packages of WebKitGTK 4.1 (`webkit2gtk4.1-devel` on Fedora)
- the development packages of libcosmic's dependencies

## Install

```sh
mise install          # the pinned Rust toolchain and just
just install-helper   # root helpers and polkit policy, through sudo
just install          # the applet into ~/.local
```

By default the applet goes into `~/.local` and the root helpers into `/usr/local/libexec`.
To change the locations, override `prefix` and `libexecdir`:

- **`libexecdir`:** pass the same value to both commands, since the applet is built with the
  helpers' path. For example:

  ```sh
  just libexecdir=/usr/libexec install-helper install
  ```

- **`prefix`:** a prefix outside your home directory, such as `/usr/local`, needs root for
  `just install`.

Then add **OpenFortiVPN** to the panel in COSMIC Settings → Desktop → Panel → Applets.

To remove it, run `just uninstall` and `just uninstall-helper`.

## Use

1. Click the shield in the panel. On first use, the popover asks for an account: a name and
   the gateway address (`vpn.example.com:443`). For a gateway without single sign-on, turn on
   "Log in with username and password". Saving the account needs an administrator password.
2. Click **Connect** next to the account. What happens next depends on the gateway:
   - **The gateway's certificate cannot be verified:** a dialog shows the certificate with its
     SHA-256 fingerprint. Only trust it if the fingerprint matches what your IT department
     gives you. "Always trust" stores it with the account, which needs an administrator
     password.
   - **Single sign-on:** the login window opens if the identity provider wants input. It
     closes by itself when the login is done.
   - **Password login:** a dialog asks for your username and password, and for the one-time
     code if your VPN needs one. "Remember password" keeps the password in the keyring. A
     rejected login forgets it.
3. While you are connected, the popover shows the address, uptime and traffic.

You manage accounts under **Settings** in the popover:
- add, change and remove accounts
- forget a trusted certificate
- turn on "Reconnect automatically"

Connecting needs no password, because polkit lets the active local user start the VPN
helper. Changing accounts or certificates needs an administrator password.

## How it works

### The agent

The panel runs one applet per monitor, so the tunnel belongs to an **agent** instead. The
agent is the same binary, started with `--agent` through D-Bus activation, once per session.
The applets show its state and send it requests over the session bus
(`io.github.snaggen.CosmicAppletFortivpn`). The agent also shows the dialogs.

### Root access

openfortivpn needs root:

- The agent starts `cosmic-applet-fortivpn-helper` through pkexec and gives it one request
  line. The line contains the account id, the login, and sometimes a certificate (see below).
- Everything else comes from the account files. Only `cosmic-applet-fortivpn-configure`
  writes them, behind an administrator password. So a user can only connect to accounts that
  an administrator set up.
- The helper writes a config file for openfortivpn into a root-only directory and passes it
  with `-c`. openfortivpn's own `/etc/openfortivpn/config` is never read or changed.
- Closing the helper's stdin disconnects.

### Single sign-on

openfortivpn waits only 50 seconds for the SAML login, which is too short for a second
factor. So the login runs before openfortivpn starts:

1. `cosmic-applet-fortivpn-login` runs the login in a WebKit window. Each account has its
   own browser profile.
2. The window stops at the gateway's final redirect.
3. The agent starts openfortivpn and hands it the session id.

If the window cannot run, the system browser is used instead.

### Incomplete certificate chains

The gateway certificate contains an address for its intermediate certificate (Authority
Information Access). The agent fetches the intermediate from there. The helper then validates
the completed chain against the system's root certificates itself. Only if that succeeds does
it trust the gateway certificate, and only for that one connection.

### Dead tunnels

openfortivpn has no keepalive, so the agent watches the network (netlink) and the tunnel's
traffic. It probes the tunnel by asking the VPN's own DNS server:
- when the network changes
- when data goes out for 15 seconds with nothing coming back

If the DNS server does not answer, the tunnel counts as lost.

### Files

| Path | Contents |
|---|---|
| `/etc/cosmic-applet-fortivpn/profiles/<id>.conf` | Accounts (owned by root, world-readable, no secrets) |
| `/run/cosmic-applet-fortivpn/` | The helper's lock and the generated openfortivpn config (root only, while connected) |
| `/usr/local/libexec/cosmic-applet-fortivpn-{helper,configure}` | Root helpers |
| `/usr/share/polkit-1/actions/io.github.snaggen.CosmicAppletFortivpn.policy` | polkit policy |
| `~/.local/share/cosmic-applet-fortivpn/webview/<id>/` | The login window's browser profile for each account (private) |
| `~/.config/cosmic/io.github.snaggen.CosmicAppletFortivpn/` | User settings: reconnecting, usernames |
| Keyring | Remembered passwords |

An account file looks like this:

```ini
name = Example Corp
# saml or password
method = saml
host = vpn.example.com
port = 443
# SHA-256 digest, only if the certificate was trusted by hand
trusted-cert = …
```

## Troubleshooting

The agent logs to the user journal:

```sh
journalctl --user -f | grep cosmic-applet-fortivpn
```

The log shows:
- every state change
- openfortivpn's output
- the login window's page loads, without query strings, since those can carry tokens

To check by hand whether a gateway accepts openfortivpn with SAML login, without the applet,
run `scripts/gateway-test.sh <host:port> [openfortivpn options]`.

## Development

```sh
just check                  # cargo fmt, clippy, tests
cargo test -- --ignored     # also the tests that need network (badssl.com)
```

Code that runs as root (the helpers) must not panic.

Strings live in `i18n/<lang>/cosmic_applet_fortivpn.ftl` (Fluent), with English as the
fallback. A new language needs the same message ids as `i18n/en`, and `cargo test` checks
that.

## License

GPL-3.0-only.
