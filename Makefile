.PHONY: test qualification-test lint package validate packer-validate

test:
	python3 -m unittest discover -s tests/unit -v

qualification-test:
	cargo test --locked --manifest-path qualification/sip-client/Cargo.toml
	cargo fmt --manifest-path qualification/direct-secure-probe/Cargo.toml -- --check
	cargo test --locked --manifest-path qualification/direct-secure-probe/Cargo.toml
	cargo clippy --locked --all-targets --manifest-path qualification/direct-secure-probe/Cargo.toml -- -D warnings
	@metadata="$$(cargo metadata --locked --format-version 1 --manifest-path qualification/direct-secure-probe/Cargo.toml)"; \
	printf '%s\n' "$$metadata" | jq -e '([.packages[] | select(.name == "bridgefu-direct-secure-probe") | .dependencies[] | select(.name == "rvoip-sip" and .req == "=0.3.7" and .source == "registry+https://github.com/rust-lang/crates.io-index" and .uses_default_features == false)] | length) == 1 and ([.packages[] | select(.name == "rvoip-sip" and .version == "0.3.7" and .source == "registry+https://github.com/rust-lang/crates.io-index")] | length) == 1'
	npm --prefix qualification ci --ignore-scripts
	node --check qualification/browser/agent-workspace-playwright.mjs
	node --check qualification/browser/vapi-web-playwright.mjs

lint:
	python3 -m compileall -q lambda release tests
	@if command -v ruff >/dev/null 2>&1; then ruff check .; fi
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck image/install.sh image/runtime/bootstrap.sh image/runtime/bridgefu-load-secrets image/runtime/bridgefu-cert-refresh image/runtime/bridgefu-cert-reload image/runtime/bridgefu-run release/reap_qualification.sh; fi

package:
	python3 release/build_lambdas.py --output target/lambda
	python3 release/build_release.py --version 0.1.0-dev --output target/release

validate:
	python3 release/validate.py

packer-validate:
	packer init image/bridgefu.pkr.hcl
	packer validate \
		-var bridgefu_commit="$$(jq -r .commit bridgefu.lock.json)" \
		-var bridgefu_cargo_lock_sha256="$$(jq -r .cargo_lock_sha256 bridgefu.lock.json)" \
		-var candidate_id=candidate-0.1.0-dev-local-validation \
		-var distribution_repository_commit=0000000000000000000000000000000000000000 \
		-var release_version=0.1.0-dev \
		image/bridgefu.pkr.hcl
