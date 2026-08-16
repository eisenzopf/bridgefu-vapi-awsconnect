"""Fail-closed SQLite reset used only by disposable live qualification."""

# ruff: noqa: S608 -- SQL statements below are fixed migration-table queries.

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Mapping
from typing import Any


class TestDatabaseResetError(RuntimeError):
    """The qualification database reset contract was not satisfied."""


PRODUCER = "bridgefu-qualification-database-reset@1"
STAGES = {
    "direct-secure-preflight",
    "bridgefu-web-sdk-handoff",
    "vapi-sip-transfer",
}
EXECUTION_ID = re.compile(r"^bfq-[a-z0-9-]{4,28}$")


def _validate(execution_id: str, stage: str) -> None:
    if EXECUTION_ID.fullmatch(execution_id) is None or stage not in STAGES:
        raise TestDatabaseResetError("database reset identity is invalid")


def reset_script(execution_id: str, stage: str) -> str:
    """Build the rollback-guarded program that replaces one test database."""
    _validate(execution_id, stage)
    execution = shlex.quote(execution_id)
    stage_value = shlex.quote(stage)
    return f"""set -euo pipefail
umask 077
execution={execution}
stage={stage_value}
database=/var/lib/bridgefu/bridgefu.db
run=/var/lib/bridgefu/qualification/$execution-db-reset-$stage
backup=$run/previous
bridgefu_ready() {{
  curl --silent --show-error --max-time 2 http://127.0.0.1:9090/readyz 2>/dev/null |
    python3 -c 'import json,sys; value=json.load(sys.stdin); raise SystemExit(0 if value.get("ok") is True and value.get("dependencies", {{}}).get("call_runtime") == "healthy" else 1)' >/dev/null 2>&1
}}
wait_bridgefu_ready() {{
  for _ in $(seq 1 90); do
    systemctl is-active --quiet bridgefu.service && bridgefu_ready && return 0
    sleep 1
  done
  return 1
}}
prove_bridgefu_stable() {{
  for _ in $(seq 1 3); do
    sleep 5
    systemctl is-active --quiet bridgefu.service && bridgefu_ready || return 1
  done
}}
active_calls() {{
  python3 - "$database" <<'PY'
import sqlite3
import sys
database = sys.argv[1]
connection = sqlite3.connect(f"file:{{database}}?mode=ro", uri=True, timeout=10)
try:
    value = connection.execute(
        "SELECT COUNT(*) FROM calls WHERE call_state NOT IN ('ended', 'failed')"
    ).fetchone()[0]
finally:
    connection.close()
print(value)
PY
}}
fresh_database() {{
  python3 - "$database" <<'PY'
import sqlite3
import sys
database = sys.argv[1]
connection = sqlite3.connect(f"file:{{database}}?mode=ro", uri=True, timeout=10)
try:
    calls = connection.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    metadata = connection.execute(
        "SELECT COUNT(*) FROM repository_metadata WHERE singleton = 1"
    ).fetchone()[0]
finally:
    connection.close()
raise SystemExit(0 if calls == 0 and metadata == 1 else 1)
PY
}}
restore_previous() {{
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -d "$backup" ] && [ ! -L "$backup" ]; then
    systemctl stop bridgefu.service >/dev/null 2>&1 || true
    rm -f "$database" "$database-wal" "$database-shm"
    for suffix in db db-wal db-shm; do
      [ ! -e "$backup/$suffix" ] || mv "$backup/$suffix" "/var/lib/bridgefu/bridgefu.$suffix" >/dev/null 2>&1 || true
    done
    systemctl start bridgefu.service >/dev/null 2>&1 || true
    wait_bridgefu_ready >/dev/null 2>&1 || true
  fi
  exit "$status"
}}
trap restore_previous EXIT
[ "$(id -u)" -eq 0 ]
[ -f "$database" ] && [ ! -L "$database" ]
[ ! -e "$run" ] && [ ! -L "$run" ]
[ "$(active_calls)" = 0 ]
install -d -o root -g bridgefu -m 0750 "$run"
install -d -o root -g bridgefu -m 0750 "$backup"
systemctl stop bridgefu.service
systemctl is-active --quiet bridgefu.service && exit 1 || true
[ "$(active_calls)" = 0 ]
for suffix in db db-wal db-shm; do
  source=/var/lib/bridgefu/bridgefu.$suffix
  if [ -e "$source" ]; then
    [ -f "$source" ] && [ ! -L "$source" ]
    mv "$source" "$backup/$suffix"
  fi
done
[ -f "$backup/db" ]
systemctl start bridgefu.service
wait_bridgefu_ready
prove_bridgefu_stable
[ -f "$database" ] && [ ! -L "$database" ]
fresh_database
rm -f "$backup/db" "$backup/db-wal" "$backup/db-shm"
rmdir "$backup" "$run"
trap - EXIT
printf '%s\n' '{{"schema_version":1,"producer":"{PRODUCER}","stage":"{stage}","test_delete_verified":true,"prior_calls_terminal":true,"fresh_database":true,"bridgefu_ready":true,"redacted":true}}'
"""


def cleanup_script(execution_id: str, stage: str) -> str:
    """Build an idempotent recovery program for a cancelled/failed reset."""
    _validate(execution_id, stage)
    execution = shlex.quote(execution_id)
    stage_value = shlex.quote(stage)
    return f"""set -euo pipefail
umask 077
execution={execution}
stage={stage_value}
database=/var/lib/bridgefu/bridgefu.db
run=/var/lib/bridgefu/qualification/$execution-db-reset-$stage
backup=$run/previous
bridgefu_ready() {{
  curl --silent --show-error --max-time 2 http://127.0.0.1:9090/readyz 2>/dev/null |
    python3 -c 'import json,sys; value=json.load(sys.stdin); raise SystemExit(0 if value.get("ok") is True and value.get("dependencies", {{}}).get("call_runtime") == "healthy" else 1)' >/dev/null 2>&1
}}
wait_bridgefu_ready() {{
  for _ in $(seq 1 90); do
    systemctl is-active --quiet bridgefu.service && bridgefu_ready && return 0
    sleep 1
  done
  return 1
}}
[ "$(id -u)" -eq 0 ]
if [ -d "$backup" ] && [ ! -L "$backup" ]; then
  systemctl stop bridgefu.service >/dev/null 2>&1 || true
  rm -f "$database" "$database-wal" "$database-shm"
  for suffix in db db-wal db-shm; do
    [ ! -e "$backup/$suffix" ] || mv "$backup/$suffix" "/var/lib/bridgefu/bridgefu.$suffix"
  done
  systemctl start bridgefu.service
  wait_bridgefu_ready
  rmdir "$backup" "$run"
elif [ -e "$run" ] || [ -L "$run" ]; then
  exit 1
else
  wait_bridgefu_ready
fi
[ ! -e "$run" ] && [ ! -L "$run" ]
printf '%s\n' '{{"schema_version":1,"producer":"{PRODUCER}","stage":"{stage}","pending_backup_absent":true,"bridgefu_ready":true,"redacted":true}}'
"""


def parse_reset_result(raw: str, stage: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.strip())
    except (AttributeError, json.JSONDecodeError) as error:
        raise TestDatabaseResetError("database reset evidence is invalid") from error
    expected = {
        "schema_version": 1,
        "producer": PRODUCER,
        "stage": stage,
        "test_delete_verified": True,
        "prior_calls_terminal": True,
        "fresh_database": True,
        "bridgefu_ready": True,
        "redacted": True,
    }
    if value != expected:
        raise TestDatabaseResetError("database reset evidence is invalid")
    return value


def parse_cleanup_result(raw: str, stage: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.strip())
    except (AttributeError, json.JSONDecodeError) as error:
        raise TestDatabaseResetError(
            "database reset cleanup evidence is invalid"
        ) from error
    expected = {
        "schema_version": 1,
        "producer": PRODUCER,
        "stage": stage,
        "pending_backup_absent": True,
        "bridgefu_ready": True,
        "redacted": True,
    }
    if value != expected:
        raise TestDatabaseResetError("database reset cleanup evidence is invalid")
    return value
