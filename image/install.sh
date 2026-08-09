#!/usr/bin/env bash
set -euo pipefail
umask 022

sudo dnf install -y \
  cargo clang cmake curl gcc gcc-c++ git haproxy jq openssl-devel \
  pkgconf-pkg-config protobuf-compiler rust xfsprogs

# The standard Amazon Linux 2023 AMI ships with AWS CLI v2. Keep this explicit
# because the runtime uses it to read Secrets Manager and publish metrics.
aws --version 2>&1 | grep -Eq '^aws-cli/2\.'

build_root="$(mktemp -d)"
trap 'sudo rm -rf "$build_root"' EXIT
git clone --filter=blob:none "$BRIDGEFU_REPOSITORY" "$build_root/bridgefu"
git -C "$build_root/bridgefu" checkout --detach "$BRIDGEFU_COMMIT"
test "$(git -C "$build_root/bridgefu" rev-parse HEAD)" = "$BRIDGEFU_COMMIT"
test "$(sha256sum "$build_root/bridgefu/Cargo.lock" | cut -d' ' -f1)" = \
  "$BRIDGEFU_CARGO_LOCK_SHA256"

if grep -E 'source = "git\+|path = ' "$build_root/bridgefu/Cargo.lock" | \
  grep -q 'rvoip'; then
  echo "rvoip must come only from crates.io" >&2
  exit 1
fi
python3 - "$build_root/bridgefu/Cargo.lock" <<'PY'
import pathlib, sys, tomllib
lock = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
packages = [p for p in lock["package"] if p["name"].startswith("rvoip")]
if not packages or any(p["version"] != "0.3.7" for p in packages):
    raise SystemExit("every rvoip package must be exactly 0.3.7")
if any("crates.io-index" not in p.get("source", "") for p in packages):
    raise SystemExit("every rvoip package must come from crates.io")
PY

rustc --version
cargo --version
(cd "$build_root/bridgefu" && cargo build --locked --release --bin bridgefu)
sudo install -o root -g root -m 0755 \
  "$build_root/bridgefu/target/release/bridgefu" /usr/local/bin/bridgefu

sudo useradd --system --home-dir /var/lib/bridgefu --shell /sbin/nologin bridgefu || true
sudo install -d -o root -g bridgefu -m 0750 /etc/bridgefu /etc/bridgefu/tls
sudo install -d -o bridgefu -g bridgefu -m 0750 /var/lib/bridgefu
sudo install -d -o root -g root -m 0755 /usr/local/lib/bridgefu
sudo cp -a /tmp/bridgefu-runtime/. /usr/local/lib/bridgefu/
sudo install -o root -g root -m 0755 /usr/local/lib/bridgefu/render.py /usr/local/sbin/bridgefu-render
for script in bridgefu-load-secrets bridgefu-cert-refresh bridgefu-cert-reload bridgefu-run; do
  sudo install -o root -g root -m 0755 "/usr/local/lib/bridgefu/$script" "/usr/local/sbin/$script"
done
sudo install -o root -g root -m 0755 /usr/local/lib/bridgefu/bootstrap.sh /usr/local/sbin/bridgefu-bootstrap
for unit in bridgefu.service bridgefu-cert-refresh.service bridgefu-cert-refresh.timer bridgefu-cert-reload.service bridgefu-cert-reload.timer; do
  sudo install -o root -g root -m 0644 "/usr/local/lib/bridgefu/$unit" "/etc/systemd/system/$unit"
done

curl --fail --location --silent --show-error \
  https://amazoncloudwatch-agent.s3.amazonaws.com/amazon_linux/arm64/latest/amazon-cloudwatch-agent.rpm \
  --output "$build_root/amazon-cloudwatch-agent.rpm"
sudo rpm -U "$build_root/amazon-cloudwatch-agent.rpm"

sudo systemctl daemon-reload
sudo systemctl enable amazon-ssm-agent.service bridgefu-cert-refresh.timer
sudo systemctl disable bridgefu.service
sudo dnf clean all
sudo rm -rf /var/cache/dnf /root/.cargo /home/ec2-user/.cargo
sudo tee /etc/bridgefu-image-release >/dev/null <<EOF
release=$BRIDGEFU_RELEASE_VERSION
bridgefu_commit=$BRIDGEFU_COMMIT
rvoip_version=0.3.7
EOF
