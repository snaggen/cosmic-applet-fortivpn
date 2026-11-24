name := 'cosmic-applet-fortivpn'
appid := 'io.github.snaggen.CosmicAppletFortivpn'

# Install prefix. The desktop entry gets the absolute binary path, since the
# panel's PATH need not contain the prefix (it lacks ~/.local/bin by default).
prefix := env_var('HOME') / '.local'
bin-dst := prefix / 'bin' / name
# The SAML login window; the agent looks for it next to its own binary.
login-dst := prefix / 'bin' / name + '-login'
desktop-dst := prefix / 'share' / 'applications' / appid + '.desktop'
# D-Bus activation file that starts the agent (`cosmic-applet-fortivpn --agent`).
dbus-service-dst := prefix / 'share' / 'dbus-1' / 'services' / appid + '.service'

# Root-only helpers. Must be root-owned and not writable by the user, since polkit lets
# the active user run the connect helper as root without a password.
libexecdir := '/usr/local/libexec'
helper := name + '-helper'
configure := name + '-configure'
# polkit only reads actions from here.
policy-dst := '/usr/share/polkit-1/actions' / appid + '.policy'

default: build-release

# The applet finds the helpers through FORTIVPN_LIBEXECDIR, fixed at build time.
build-release *args:
    FORTIVPN_LIBEXECDIR={{libexecdir}} cargo build --release {{args}}

# Format check, lints and tests
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test

# Applet, agent and their desktop and D-Bus files, for the current user. Stops a running
# agent so the next use starts the new one; that also ends an open VPN connection.
install: build-release
    install -Dm0755 target/release/{{name}} {{bin-dst}}
    install -Dm0755 target/release/{{name}}-login {{login-dst}}
    install -d {{parent_directory(desktop-dst)}} {{parent_directory(dbus-service-dst)}}
    sed 's|^Exec=.*|Exec={{bin-dst}}|' data/{{appid}}.desktop > {{desktop-dst}}
    sed 's|@BIN@|{{bin-dst}}|' data/{{appid}}.service > {{dbus-service-dst}}
    chmod 0644 {{desktop-dst}} {{dbus-service-dst}}
    -busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
    -pkill -f '^{{bin-dst}} --agent$'

uninstall:
    -pkill -f '^{{bin-dst}} --agent$'
    rm -f {{bin-dst}} {{login-dst}} {{desktop-dst}} {{dbus-service-dst}}

# Root helpers and polkit policy, through sudo
install-helper: build-release
    sudo install -Dm0755 -o root -g root target/release/{{helper}} {{libexecdir}}/{{helper}}
    sudo install -Dm0755 -o root -g root target/release/{{configure}} {{libexecdir}}/{{configure}}
    sed 's|@LIBEXECDIR@|{{libexecdir}}|g' data/{{appid}}.policy | sudo tee {{policy-dst}} > /dev/null
    sudo chmod 0644 {{policy-dst}}

uninstall-helper:
    sudo rm -f {{libexecdir}}/{{helper}} {{libexecdir}}/{{configure}} {{policy-dst}}
