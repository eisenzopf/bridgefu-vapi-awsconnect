#!/usr/bin/env bash
set -euo pipefail

region=us-west-2
max_age_seconds=$((14 * 24 * 60 * 60))
expected_account_id="${EXPECTED_AWS_ACCOUNT_ID:?EXPECTED_AWS_ACCOUNT_ID is required}"
keep_build_sha256="${KEEP_AMI_BUILD_SHA256:-}"
[[ "$expected_account_id" =~ ^[0-9]{12}$ ]]
[[ -z "$keep_build_sha256" || "$keep_build_sha256" =~ ^[0-9a-f]{64}$ ]]
test "$(aws sts get-caller-identity --query Account --output text)" = \
  "$expected_account_id"

work="$(mktemp -d /tmp/bridgefu-ami-cache-prune.XXXXXX)"
chmod 0700 "$work"
trap 'rm -rf -- "$work"' EXIT

aws ec2 describe-images --owners self --region "$region" \
  --filters Name=tag:BridgefuAmiBuildCache,Values=bridgefu-ami-cache-v1 \
  > "$work/images.json"
image_count="$(jq '.Images | length' "$work/images.json")"
test "$image_count" -le 25
now_epoch="$(date -u +%s)"

exact_tag() {
  document="$1"
  key="$2"
  jq -er --arg key "$key" \
    '[.Tags[] | select(.Key == $key) | .Value] |
     if length == 1 then .[0] else error("tag is not unique") end' \
    <<<"$document"
}

while IFS= read -r encoded; do
  image="$(printf '%s' "$encoded" | base64 --decode)"
  ami_id="$(jq -er '.ImageId | select(test("^ami-[0-9a-f]{17}$"))' \
    <<<"$image")"
  build_sha256="$(exact_tag "$image" BridgefuAmiBuildSha256)"
  bridgefu_commit="$(exact_tag "$image" BridgefuCommit)"
  release_version="$(exact_tag "$image" BridgefuReleaseInput)"
  [[ "$build_sha256" =~ ^[0-9a-f]{64}$ ]]
  [[ "$bridgefu_commit" =~ ^[0-9a-f]{40}$ ]]
  [[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]
  if [[ "$build_sha256" = "$keep_build_sha256" ]]; then
    continue
  fi
  created_at="$(jq -er .CreationDate <<<"$image")"
  created_epoch="$(python - "$created_at" <<'PY'
import datetime as dt
import sys

value = dt.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
if value.tzinfo is None:
    raise SystemExit(2)
print(int(value.timestamp()))
PY
)"
  age_seconds="$((now_epoch - created_epoch))"
  test "$age_seconds" -ge 0
  if (( age_seconds < max_age_seconds )); then
    continue
  fi

  jq -n --argjson image "$image" '{Images:[$image]}' > "$work/image.json"
  aws ec2 describe-image-attribute --region "$region" --image-id "$ami_id" \
    --attribute launchPermission > "$work/image-permissions.json"
  snapshot_id="$(jq -er \
    '.BlockDeviceMappings | if length == 1 then .[0].Ebs.SnapshotId
     else error("cache block device is not unique") end' <<<"$image")"
  aws ec2 describe-snapshots --owner-ids self --region "$region" \
    --snapshot-ids "$snapshot_id" > "$work/snapshot.json"
  aws ec2 describe-snapshot-attribute --region "$region" \
    --snapshot-id "$snapshot_id" --attribute createVolumePermission \
    > "$work/snapshot-permissions.json"
  python release/ami_cache.py verify \
    --image "$work/image.json" \
    --image-permissions "$work/image-permissions.json" \
    --snapshot "$work/snapshot.json" \
    --snapshot-permissions "$work/snapshot-permissions.json" \
    --account-id "$expected_account_id" \
    --build-sha256 "$build_sha256" \
    --bridgefu-commit "$bridgefu_commit" \
    --release-version "$release_version" > "$work/verification.json"
  test "$(jq -r .ami_id "$work/verification.json")" = "$ami_id"
  test "$(jq -r .snapshot_id "$work/verification.json")" = "$snapshot_id"

  aws ec2 deregister-image --region "$region" --image-id "$ami_id"
  for attempt in 1 2 3 4 5; do
    remaining="$(aws ec2 describe-images --owners self --region "$region" \
      --image-ids "$ami_id" --query 'length(Images)' --output text)"
    [[ "$remaining" = 0 ]] && break
    test "$attempt" -lt 5
    sleep "$((attempt * 2))"
  done
  test "$remaining" = 0
  for attempt in 1 2 3 4 5; do
    if aws ec2 delete-snapshot --region "$region" --snapshot-id "$snapshot_id"; then
      break
    fi
    test "$attempt" -lt 5
    sleep "$((attempt * 2))"
  done
  for attempt in 1 2 3 4 5; do
    if ! aws ec2 describe-snapshots --owner-ids self --region "$region" \
      --snapshot-ids "$snapshot_id" >/dev/null 2>&1; then
      break
    fi
    test "$attempt" -lt 5
    sleep "$((attempt * 2))"
  done
done < <(jq -r '.Images[] | @base64' "$work/images.json")
