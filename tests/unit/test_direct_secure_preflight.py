from __future__ import annotations

import json
import subprocess
import unittest

from qualification import direct_secure_preflight as PREFLIGHT

EXECUTION = "bfq-test1234"
REGION = "us-west-2"
BUCKET = "bridgefu-artifacts-test"
KEY = f"qualification/{EXECUTION}/direct-secure-probe"
DIGEST = "a" * 64


class DirectSecurePreflightTests(unittest.TestCase):
    def test_probe_contract_is_exact_typed_and_redacted(self):
        expected = PREFLIGHT.expected_probe_result()
        self.assertEqual(PREFLIGHT.validate_probe_result(expected), expected)
        self.assertEqual(
            PREFLIGHT.parse_probe_result(json.dumps(expected, separators=(",", ":"))),
            expected,
        )

        mutations = (
            (("signaling", "transport"), "udp"),
            (("signaling", "correlation_header_count"), True),
            (("signaling", "inbound_200"), False),
            (("signaling", "outbound_ack"), False),
            (("signaling", "contact_host"), "ipv4"),
            (("signaling", "contact_sips"), False),
            (("signaling", "contact_tls"), False),
            (("media", "keying"), "none"),
            (("media", "contexts_installed"), 1),
            (("media", "dtmf_requested"), False),
            (("hangup", "cleanup_observed"), False),
        )
        for path, replacement in mutations:
            with self.subTest(path=path):
                changed = json.loads(json.dumps(expected))
                changed[path[0]][path[1]] = replacement
                with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
                    PREFLIGHT.validate_probe_result(changed)

        changed = PREFLIGHT.expected_probe_result()
        changed["private_uri"] = "sips:private-token@example.invalid"
        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.validate_probe_result(changed)

    def test_bounded_json_parsers_reject_ambiguous_or_non_contract_values(self):
        duplicate = '{"probe_process_absent":true,"probe_process_absent":true}'
        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.parse_cleanup_receipt(duplicate)
        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.parse_cleanup_receipt('{"probe_process_absent":NaN}')
        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.parse_probe_result("x" * (PREFLIGHT.MAX_RESULT_BYTES + 1))

    def test_cleanup_receipt_contains_only_exact_booleans(self):
        receipt = {name: True for name in PREFLIGHT.CLEANUP_FIELDS}
        self.assertEqual(PREFLIGHT.validate_cleanup_receipt(receipt), receipt)
        self.assertEqual(PREFLIGHT.parse_cleanup_receipt(json.dumps(receipt)), receipt)
        for name in PREFLIGHT.CLEANUP_FIELDS:
            with self.subTest(name=name):
                changed = dict(receipt)
                changed[name] = 1
                with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
                    PREFLIGHT.validate_cleanup_receipt(changed)
        receipt["passed"] = True
        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.validate_cleanup_receipt(receipt)

    def test_probe_program_is_hash_bound_memory_only_and_restores_in_exit_trap(self):
        first = PREFLIGHT.probe_script(EXECUTION, REGION, BUCKET, KEY, DIGEST)
        second = PREFLIGHT.probe_script(EXECUTION, REGION, BUCKET, KEY, DIGEST)
        self.assertEqual(first, second)
        paths = PREFLIGHT.remote_paths(EXECUTION)

        for required in (
            "set -euo pipefail",
            "umask 077",
            "exec 3>&2 2>/dev/null",
            f"bucket={BUCKET}",
            f"key={KEY}",
            f"expected_sha256={DIGEST}",
            "aws s3api get-object",
            "sha256sum --check --status",
            f"run={paths.run}",
            f"probe={paths.probe}",
            "owned_paths_safe || return 1",
            "trap on_exit EXIT",
            "restore_owned || status=1",
            "binary_absent || return 1",
            'private_cidr = f"{private}/32"',
            'export BFQ_PUBLIC_IP="$BRIDGEFU_PUBLIC_IP"',
            'public = ipaddress.ip_address(os.environ["BFQ_PUBLIC_IP"])',
            "socket.getaddrinfo(",
            "if resolved != {private}:",
            'media_public = f"  media_public_addr: {public}:0\\n"',
            'f"  media_public_addr: {private}:0 # {marker}\\n"',
            "vapi_signaling_cidrs:",
            "bfq-direct-secure-preflight-",
            "os.O_CREAT | os.O_EXCL",
            "/v1/routes/support/calls",
            '"Authorization": "Bearer " + bearer',
            '"Idempotency-Key": idempotency',
            "NoRedirect",
            "stdin=subprocess.PIPE",
            '"--request-stdin"',
            "process.communicate(private_request, timeout=120)",
            "finally:",
            "del request",
            'private_request = ""',
            "if observed != expected",
            'phase=emit_result\ncat "$result"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, first)

        for forbidden in (
            "rm -rf",
            "--sip-uri",
            "--correlation",
            "--bearer",
            "sips:aaaaaaaa",
            "bf1_aaaaaaaa",
            "do-not-retain",
            "api.vapi.ai",
            "/etc/hosts",
            "advertised_addr:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, first)
        self.assertEqual(first.count('cat "$result"'), 1)
        self.assertEqual(first.count("stdout=subprocess.DEVNULL"), 1)
        self.assertEqual(first.count("stderr=subprocess.DEVNULL"), 1)
        self._assert_shell_and_embedded_python_syntax(first)

    def test_cleanup_program_is_exact_idempotent_and_boolean_only(self):
        paths = PREFLIGHT.remote_paths(EXECUTION)
        script = PREFLIGHT.cleanup_script(EXECUTION, paths.probe)
        for required in (
            "set +e",
            "exec 2>/dev/null",
            f"run={paths.run}",
            f"probe={paths.probe}",
            "run_safe=false",
            '[ "$run_safe" = true ] || return 1',
            "stop_owned",
            "binary_absent",
            "cp --preserve=all",
            "cmp -s",
            "systemctl restart bridgefu.service",
            '"private_dns_verified":%s',
            'rmdir "$run"',
            'printf \'{"probe_process_absent":%s,',
            "exit 0",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertNotIn("rm -rf", script)
        self.assertNotIn("Bearer", script)
        self._assert_shell_and_embedded_python_syntax(script)

        with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
            PREFLIGHT.cleanup_script(EXECUTION, "/usr/local/bin/bridgefu")

    def test_builder_rejects_cross_execution_targets_and_shell_injection(self):
        invalid = (
            ("bfq-test1234;id", REGION, BUCKET, KEY, DIGEST),
            (EXECUTION, "us-west-2;id", BUCKET, KEY, DIGEST),
            (EXECUTION, REGION, "bridgefu..bucket", KEY, DIGEST),
            (
                EXECUTION,
                REGION,
                BUCKET,
                "qualification/bfq-another/direct-secure-probe",
                DIGEST,
            ),
            (EXECUTION, REGION, BUCKET, KEY + ";id", DIGEST),
            (EXECUTION, REGION, BUCKET, KEY, "A" * 64),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(PREFLIGHT.DirectSecurePreflightError):
                    PREFLIGHT.probe_script(*arguments)

    def _assert_shell_and_embedded_python_syntax(self, script: str) -> None:
        checked = subprocess.run(
            ["bash", "-n"],
            input=script,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        marker = "python3 - <<'PY' >/dev/null 2>&1\n"
        for index, section in enumerate(script.split(marker)[1:]):
            source = section.split("\nPY\n", 1)[0]
            compile(source, f"<direct-secure-heredoc-{index}>", "exec")


if __name__ == "__main__":
    unittest.main()
