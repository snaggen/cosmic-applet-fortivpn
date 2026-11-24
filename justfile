name := 'cosmic-applet-fortivpn'
appid := 'io.github.snaggen.CosmicAppletFortivpn'

# Install prefix. The default needs ~/.local/bin on the session's PATH.
prefix := env_var('HOME') / '.local'
bin-dst := prefix / 'bin' / name
desktop-dst := prefix / 'share' / 'applications' / appid + '.desktop'

default: build-release

build-release *args:
    cargo build --release {{args}}

# Format check, lints and tests
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test

install: build-release
    install -Dm0755 target/release/{{name}} {{bin-dst}}
    install -Dm0644 data/{{appid}}.desktop {{desktop-dst}}

uninstall:
    rm -f {{bin-dst}} {{desktop-dst}}
