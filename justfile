name := 'cosmic-applet-fortivpn'
appid := 'io.github.snaggen.CosmicAppletFortivpn'

# Install prefix. The desktop entry gets the absolute binary path, since the
# panel's PATH need not contain the prefix (it lacks ~/.local/bin by default).
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
    install -d {{parent_directory(desktop-dst)}}
    sed 's|^Exec=.*|Exec={{bin-dst}}|' data/{{appid}}.desktop > {{desktop-dst}}
    chmod 0644 {{desktop-dst}}

uninstall:
    rm -f {{bin-dst}} {{desktop-dst}}
