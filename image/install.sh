#!/usr/bin/env bash
set -euo pipefail
umask 022

sudo dnf install -y \
  cargo clang cmake gcc gcc-c++ git gnupg2-minimal haproxy jq openssl-devel \
  logrotate opus-devel pkgconf-pkg-config protobuf-compiler rust xfsprogs

# rvoip's Opus feature dynamically links libopus on GNU Linux. Prove both the
# build metadata and runtime library are present before spending time compiling.
rpm -q opus opus-devel
pkg-config --exists opus

# The standard Amazon Linux 2023 AMI ships with AWS CLI v2 and curl-minimal.
# Keep both dependencies explicit because the runtime uses them for AWS APIs,
# Secrets Manager, metrics, metadata, and HTTPS downloads.
aws --version 2>&1 | grep -Eq '^aws-cli/2\.'
curl --version 2>&1 | grep -Eq '^Protocols:.* https( |$)'

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
if ! cargo metadata --locked --format-version 1 \
  --manifest-path "$build_root/bridgefu/Cargo.toml" | jq -e '
    [.packages[] | select(.name | startswith("rvoip"))] as $rvoip |
    ($rvoip | length > 0) and
    ([$rvoip[] | select(
      .version != "0.3.8" or
      (.source // "") != "registry+https://github.com/rust-lang/crates.io-index"
    )] | length == 0)
  ' >/dev/null; then
  echo "every rvoip package must be crates.io version 0.3.8" >&2
  exit 1
fi

rustc --version
cargo --version
(cd "$build_root/bridgefu" && \
  cargo build --locked --release --jobs 4 --bin bridgefu)
sudo install -o root -g root -m 0755 \
  "$build_root/bridgefu/target/release/bridgefu" /usr/local/bin/bridgefu
ldd /usr/local/bin/bridgefu | grep -Eq 'libopus\.so\.[0-9]+ => /'

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
sudo install -o root -g root -m 0644 /usr/local/lib/bridgefu/bridgefu.logrotate /etc/logrotate.d/bridgefu
for unit in bridgefu.service bridgefu-logrotate.service bridgefu-logrotate.timer bridgefu-cert-refresh.service bridgefu-cert-refresh.timer bridgefu-cert-reload.service bridgefu-cert-reload.timer; do
  sudo install -o root -g root -m 0644 "/usr/local/lib/bridgefu/$unit" "/etc/systemd/system/$unit"
done
sudo logrotate --debug /etc/logrotate.d/bridgefu >/dev/null

build_inputs=/tmp/bridgefu-build-inputs.json
test -f "$build_inputs"
jq -e '
  .schema == "bridgefu-ami-build-inputs/v1" and
  (.cloudwatch_agent.version | type == "string" and length >= 8) and
  ([.cloudwatch_agent.package_sha256, .cloudwatch_agent.signature_sha256,
    .cloudwatch_agent.gpg_material_sha256] | all(test("^[0-9a-f]{64}$"))) and
  (.cloudwatch_agent.gpg_fingerprint | test("^[0-9A-F]{40}$")) and
  ([.cloudwatch_agent.package_url, .cloudwatch_agent.signature_url,
    .cloudwatch_agent.key_url] | all(
      test("^https://amazoncloudwatch-agent\\.s3\\.amazonaws\\.com/")))
' "$build_inputs" >/dev/null
cloudwatch_version="$(jq -r .cloudwatch_agent.version "$build_inputs")"
cloudwatch_package_url="$(jq -r .cloudwatch_agent.package_url "$build_inputs")"
cloudwatch_package_sha256="$(jq -r .cloudwatch_agent.package_sha256 "$build_inputs")"
cloudwatch_signature_url="$(jq -r .cloudwatch_agent.signature_url "$build_inputs")"
cloudwatch_signature_sha256="$(jq -r .cloudwatch_agent.signature_sha256 "$build_inputs")"
cloudwatch_key_url="$(jq -r .cloudwatch_agent.key_url "$build_inputs")"
cloudwatch_key_sha256="$(jq -r .cloudwatch_agent.gpg_material_sha256 "$build_inputs")"
cloudwatch_fingerprint="$(jq -r .cloudwatch_agent.gpg_fingerprint "$build_inputs")"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "$cloudwatch_package_url" --output "$build_root/amazon-cloudwatch-agent.rpm"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "$cloudwatch_signature_url" \
  --output "$build_root/amazon-cloudwatch-agent.rpm.sig"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "$cloudwatch_key_url" --output "$build_root/amazon-cloudwatch-agent.gpg"
printf '%s  %s\n' "$cloudwatch_package_sha256" \
  "$build_root/amazon-cloudwatch-agent.rpm" | sha256sum --check --strict
printf '%s  %s\n' "$cloudwatch_signature_sha256" \
  "$build_root/amazon-cloudwatch-agent.rpm.sig" | sha256sum --check --strict
printf '%s  %s\n' "$cloudwatch_key_sha256" \
  "$build_root/amazon-cloudwatch-agent.gpg" | sha256sum --check --strict
cloudwatch_gnupg="$build_root/cloudwatch-gnupg"
install -d -m 0700 "$cloudwatch_gnupg"
cloudwatch_keyring="$cloudwatch_gnupg/cloudwatch-agent.gpg"
if ! GNUPGHOME="$cloudwatch_gnupg" gpg --batch --no-autostart --yes \
  --dearmor --output "$cloudwatch_keyring" \
  "$build_root/amazon-cloudwatch-agent.gpg" >/dev/null 2>&1; then
  echo "CloudWatch Agent signing key decoding failed" >&2
  exit 1
fi
observed_cloudwatch_fingerprint="$(
  GNUPGHOME="$cloudwatch_gnupg" gpg --batch --no-autostart \
    --no-default-keyring --keyring "$cloudwatch_keyring" --with-colons \
    --fingerprint | awk -F: '$1 == "fpr" {print $10}'
)"
if test "$observed_cloudwatch_fingerprint" != "$cloudwatch_fingerprint"; then
  echo "CloudWatch Agent signing key fingerprint mismatch" >&2
  exit 1
fi
if ! GNUPGHOME="$cloudwatch_gnupg" gpg --batch --no-autostart \
  --no-default-keyring --keyring "$cloudwatch_keyring" --verify \
  "$build_root/amazon-cloudwatch-agent.rpm.sig" \
  "$build_root/amazon-cloudwatch-agent.rpm" >/dev/null 2>&1; then
  echo "CloudWatch Agent detached signature verification failed" >&2
  exit 1
fi
sudo rpm -U "$build_root/amazon-cloudwatch-agent.rpm"

sudo systemctl daemon-reload
sudo systemctl enable amazon-ssm-agent.service bridgefu-cert-refresh.timer
sudo systemctl disable bridgefu.service
sudo dnf clean all
sudo rm -rf /var/cache/dnf /root/.cargo /home/ec2-user/.cargo
sudo install -d -o root -g root -m 0755 /usr/local/share/bridgefu
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' | \
  LC_ALL=C sort | sudo tee /usr/local/share/bridgefu/image-rpm-inventory.tsv \
  >/dev/null
rpm_inventory_sha256="$(sha256sum \
  /usr/local/share/bridgefu/image-rpm-inventory.tsv | cut -d' ' -f1)"
sudo tee /etc/bridgefu-image-release >/dev/null <<EOF
release=$BRIDGEFU_RELEASE_VERSION
bridgefu_commit=$BRIDGEFU_COMMIT
rvoip_version=0.3.8
source_ami_id=$BRIDGEFU_SOURCE_AMI_ID
cloudwatch_agent_version=$cloudwatch_version
cloudwatch_agent_sha256=$cloudwatch_package_sha256
rpm_inventory_sha256=$rpm_inventory_sha256
EOF
