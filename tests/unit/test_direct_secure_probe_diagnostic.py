from __future__ import annotations

import ast
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from qualification.diagnostics import run_direct_secure_probe as DIRECT  # noqa: E402


def arguments(output: Path) -> SimpleNamespace:
    return SimpleNamespace(
        profile="qualification-admin",
        region="us-west-2",
        stack="bridgefu-bfq-test1234",
        execution="bfq-test1234",
        probe_path="/usr/local/bin/bridgefu-direct-secure-probe",
        output=output,
    )


def valid_result() -> dict:
    return {
        "schema_version": 1,
        "producer": "bridgefu-direct-secure-probe@1",
        "signaling": {
            "scheme": "sips",
            "transport": "tls",
            "invite_count": 1,
            "correlation_header_count": 1,
            "answered": True,
            "inbound_200": True,
            "outbound_ack": True,
            "contact_host": "dns",
            "contact_sips": True,
            "contact_tls": True,
            "trace_redacted": True,
        },
        "media": {
            "profile": "RTP/SAVP",
            "keying": "SDES-SRTP",
            "contexts_installed": True,
            "audio_opened": True,
            "marker_frames_sent": 10,
            "codec": "PCMU",
            "dtmf_requested": True,
            "in_band_dtmf_frames_sent": 15,
            "rfc4733_dtmf_sent": True,
        },
        "hangup": {"local_bye_completed": True, "cleanup_observed": True},
        "redacted": True,
    }


class Runner:
    def run(self, arguments, **kwargs):
        return ""

    def probe(self, arguments, **kwargs):
        return 0, "", ""


class Harness(DIRECT.DirectSecureProbe):
    def __init__(self, args, failure: str | None = None):
        super().__init__(args, Runner())
        self.failure = failure
        self.remote_calls = 0
        self.scripts: list[str] = []
        self.cancel_attempted = False

    def discover_target(self):
        return DIRECT.Target(
            "i-0123456789abcdef0",
            "assistant_1234",
            "bridgefu-artifacts-test",
            ("192.0.2.10/32", "192.0.2.11/32"),
        )

    def remote_cleanup(self, target):
        self.remote_calls += 1
        values = {
            "probe_process_absent": True,
            "configuration_restored": True,
            "private_dns_verified": True,
            "run_artifacts_absent": True,
            "bridgefu_active": True,
        }
        if self.remote_calls > 1 and self.failure in values:
            values[self.failure] = False
        return values

    def send_shell(self, target, script):
        self.scripts.append(script)
        return "12345678-1234-1234-1234-123456789012"

    def invocation(self, target, command_id, timeout):
        return {
            "Status": "Success",
            "StandardOutputContent": json.dumps(valid_result()),
        }

    def cancel_command(self, target, command_id):
        self.cancel_attempted = True
        return self.failure != "ssm_command_terminal"


class DirectSecureProbeDiagnosticTests(unittest.TestCase):
    def test_happy_path_retains_only_private_closed_vocabulary_results(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "evidence"
            probe = Harness(arguments(output))
            probe.run_direct()
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"direct-secure-probe.json", "direct-cleanup-receipt.json"},
            )
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                retained = path.read_text(encoding="utf-8")
                for forbidden in (
                    "sips:",
                    "bf1_",
                    "Bearer ",
                    "192.0.2.",
                    "X-Correlation-Id",
                ):
                    self.assertNotIn(forbidden, retained)
            receipt = json.loads(
                (output / "direct-cleanup-receipt.json").read_text(encoding="utf-8")
            )
            self.assertTrue(receipt["passed"])
            self.assertTrue(probe.cancel_attempted)

    def test_each_cleanup_failure_is_evidenced_and_fails_closed(self):
        fields = (
            "ssm_command_terminal",
            "probe_process_absent",
            "configuration_restored",
            "private_dns_verified",
            "run_artifacts_absent",
            "bridgefu_active",
        )
        for field in fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as parent:
                output = Path(parent) / "evidence"
                probe = Harness(arguments(output), field)
                with self.assertRaises(DIRECT.DiagnosticError):
                    probe.run_direct()
                receipt = json.loads(
                    (output / "direct-cleanup-receipt.json").read_text(encoding="utf-8")
                )
                self.assertFalse(receipt[field])
                self.assertFalse(receipt["passed"])
                self.assertTrue((output / "direct-secure-probe.json").is_file())

    def test_probe_result_contract_is_exact_and_all_success_derived(self):
        DIRECT.validate_probe_result(valid_result())
        for path, value in (
            (("signaling", "transport"), "udp"),
            (("signaling", "correlation_header_count"), 2),
            (("signaling", "inbound_200"), False),
            (("signaling", "outbound_ack"), False),
            (("signaling", "contact_host"), "ipv4"),
            (("signaling", "contact_sips"), False),
            (("signaling", "contact_tls"), False),
            (("media", "keying"), "none"),
            (("media", "contexts_installed"), False),
            (("media", "dtmf_requested"), False),
            (("hangup", "cleanup_observed"), False),
        ):
            with self.subTest(path=path):
                changed = json.loads(json.dumps(valid_result()))
                changed[path[0]][path[1]] = value
                with self.assertRaises(DIRECT.DiagnosticError):
                    DIRECT.validate_probe_result(changed)
        changed = valid_result()
        changed["private"] = "sips:secret"
        with self.assertRaises(DIRECT.DiagnosticError):
            DIRECT.validate_probe_result(changed)

    def test_remote_program_uses_memory_only_secrets_and_exact_owned_mutations(self):
        probe = Harness(arguments(Path("unused")))
        script = probe.probe_script()
        cleanup = probe.remote_cleanup_script()
        self.assertNotIn("\n\n", script)
        self.assertNotIn("\n\n", cleanup)
        self.assertTrue(all(0 < len(line) <= 8192 for line in cleanup.splitlines()))
        self.assertIn("local-ipv4", script)
        self.assertIn('private_cidr = f"{private}/32"', script)
        self.assertIn(
            'public = ipaddress.ip_address(os.environ["BFQ_PUBLIC_IP"])', script
        )
        self.assertIn('media_public = f"  media_public_addr: {public}:0\\n"', script)
        self.assertIn('f"  media_public_addr: {private}:0 # {marker}\\n"', script)
        self.assertIn("socket.getaddrinfo(", script)
        self.assertIn("if resolved != {private}:", script)
        self.assertIn("vapi_signaling_cidrs", script)
        self.assertIn("BFQ_EXPECTED_CIDRS", script)
        self.assertIn("BFQ_SIP_HOSTNAME", script)
        self.assertIn("/v1/routes/support/calls", script)
        self.assertIn("/run/bridgefu/runtime.env", script)
        self.assertIn('"Authorization": "Bearer " + bearer', script)
        self.assertIn("stdin=subprocess.PIPE", script)
        self.assertIn("stderr=subprocess.PIPE", script)
        self.assertIn("probe_failure_", script)
        self.assertIn("inbound_200=(yes|no)", script)
        self.assertIn("outbound_ack=(yes|no)", script)
        self.assertIn("contact=(absent|redacted|ipv4|dns)", script)
        self.assertIn("contact_sips=(unknown|yes|no)", script)
        self.assertIn("contact_tls=(unknown|yes|no)", script)
        self.assertIn(
            "_200_{failure.group(3)}_ack_{failure.group(4)}",
            script,
        )
        self.assertIn("--request-stdin", script)
        self.assertIn("--send-dtmf", script)
        self.assertIn("trap on_exit EXIT", script)
        self.assertIn("NoRedirect", script)
        self.assertIn("if observed != expected", script)
        self.assertIn("cp --preserve=all", script)
        self.assertIn("cmp -s", script)
        self.assertIn("systemctl restart bridgefu.service", script)
        self.assertNotIn("rm -rf", script + cleanup)
        self.assertNotIn("/etc/hosts", script + cleanup)
        self.assertNotIn("advertised_addr:", script + cleanup)
        self.assertIn("binary_absent", cleanup)
        self.assertIn('rmdir "$run"', cleanup)
        for forbidden in (
            "sips:aaaaaaaa",
            "bf1_aaaaaaaa",
            "do-not-retain-bearer",
        ):
            self.assertNotIn(forbidden, script)
        for label, value in (("probe", script), ("cleanup", cleanup)):
            with self.subTest(shell_syntax=label):
                checked = subprocess.run(
                    ["bash", "-n"],
                    input=value,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(checked.returncode, 0, checked.stderr)
        embedded = script.split("python3 - <<'PY' >/dev/null 2>&1\n")[1:]
        self.assertEqual(len(embedded), 2)
        for program in embedded:
            ast.parse(program.split("\nPY\n", 1)[0])

    def test_invalid_target_or_output_is_rejected_before_remote_changes(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "evidence"
            output.mkdir()
            probe = Harness(arguments(output))
            with self.assertRaises(DIRECT.DiagnosticError):
                probe.validate_inputs()
        args = arguments(Path("unused"))
        args.stack = "another-stack"
        with self.assertRaises(DIRECT.DiagnosticError):
            Harness(args).validate_inputs()


if __name__ == "__main__":
    unittest.main()
