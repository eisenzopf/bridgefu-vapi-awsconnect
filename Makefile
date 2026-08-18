.PHONY: preflight preflight-tools test qualification-test sdk-test lint package validate packer-validate

preflight: preflight-tools
	$(MAKE) test
	$(MAKE) qualification-test
	$(MAKE) sdk-test
	$(MAKE) lint
	$(MAKE) package
	$(MAKE) validate
	$(MAKE) packer-validate

preflight-tools:
	@for required_tool in python3 cargo rustup npm node jq git curl ruff shellcheck actionlint cfn-lint packer; do \
		command -v "$$required_tool" >/dev/null 2>&1 || { \
			echo "required local preflight tool is missing: $$required_tool" >&2; \
			exit 1; \
		}; \
	done
	@case "$$(uname -s)/$$(uname -m)" in Linux/x86_64|Linux/aarch64|Linux/arm64|Darwin/arm64) ;; *) echo "unsupported preflight platform" >&2; exit 1 ;; esac
	@test "$$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')" = 3.12
	@test "$$(node --version | sed 's/^v//' | cut -d. -f1)" = 22
	@test "$$(npm --version | cut -d. -f1)" = 10
	@test "$$(ruff --version)" = "ruff 0.12.4"
	@test "$$(cfn-lint --version)" = "cfn-lint 1.54.0"

test:
	python3 -m unittest discover -s tests/unit -v

qualification-test:
	cargo test --locked --manifest-path qualification/sip-client/Cargo.toml
	cargo fmt --manifest-path qualification/sdp-observer/Cargo.toml -- --check
	cargo test --locked --manifest-path qualification/sdp-observer/Cargo.toml
	cargo clippy --locked --all-targets --manifest-path qualification/sdp-observer/Cargo.toml -- -D warnings
	cargo fmt --manifest-path qualification/direct-secure-probe/Cargo.toml -- --check
	cargo test --locked --manifest-path qualification/direct-secure-probe/Cargo.toml
	cargo clippy --locked --all-targets --manifest-path qualification/direct-secure-probe/Cargo.toml -- -D warnings
	@metadata="$$(cargo metadata --locked --format-version 1 --manifest-path qualification/direct-secure-probe/Cargo.toml)"; \
	printf '%s\n' "$$metadata" | jq -e '([.packages[] | select(.name == "bridgefu-direct-secure-probe") | .dependencies[] | select(.name == "rvoip-sip" and .req == "=0.3.8" and .source == "registry+https://github.com/rust-lang/crates.io-index" and .uses_default_features == false)] | length) == 1 and ([.packages[] | select(.name == "rvoip-sip" and .version == "0.3.8" and .source == "registry+https://github.com/rust-lang/crates.io-index")] | length) == 1'
	npm --prefix qualification ci --ignore-scripts
	PLAYWRIGHT_BROWSERS_PATH=0 npm --prefix qualification exec playwright install chromium
	node --check qualification/browser/agent-workspace-playwright.mjs
	node --check qualification/browser/bridgefu-web-playwright.mjs

sdk-test:
	@set -eu; \
	checkout="$$(mktemp -d "$${TMPDIR:-/tmp}/bridgefu-preflight.XXXXXX")"; \
	cleanup() { case "$$checkout" in */bridgefu-preflight.*) rm -rf -- "$$checkout" ;; *) exit 1 ;; esac; }; \
	trap cleanup EXIT HUP INT TERM; \
	repository="$$(jq -er .repository bridgefu.lock.json)"; \
	commit="$$(jq -er .commit bridgefu.lock.json)"; \
	git clone --filter=blob:none --no-checkout "$$repository" "$$checkout"; \
	git -C "$$checkout" checkout --detach "$$commit"; \
	python3 release/verify_bridgefu.py "$$checkout"; \
	npm --prefix "$$checkout/sdk/typescript" ci --ignore-scripts; \
	npm --prefix "$$checkout/sdk/typescript" test

lint:
	@for required_tool in ruff shellcheck actionlint; do \
		command -v "$$required_tool" >/dev/null 2>&1 || { \
			echo "required lint tool is missing: $$required_tool" >&2; \
			exit 1; \
		}; \
	done
	python3 -m compileall -q lambda qualification release tests
	ruff check .
	shellcheck image/install.sh image/runtime/bootstrap.sh \
		image/runtime/bridgefu-load-secrets image/runtime/bridgefu-cert-refresh \
		image/runtime/bridgefu-cert-reload image/runtime/bridgefu-run \
		release/reap_qualification.sh release/prune_ami_cache.sh
	actionlint

package:
	python3 release/build_lambdas.py --output target/lambda
	python3 release/build_release.py --version 0.1.0-dev --output target/release

validate:
	python3 release/validate.py

packer-validate:
	python3 release/validate.py --packer-only
