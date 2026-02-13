set shell := ["bash", "-euo", "pipefail", "-c"]

default: check test build

check:
	cargo check --workspace --all-targets --all-features --locked

test:
	cargo test --workspace --all-targets --locked

build:
	cargo build --release --locked

serve config="":
	if [[ -n "{{config}}" ]]; then
		cargo run -- --config "{{config}}"
	else
		cargo run
	fi
