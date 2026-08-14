from __future__ import annotations

import json
import subprocess
import unittest
from types import SimpleNamespace

from qualification import controller as CONTROLLER
from qualification import test_database_reset as RESET


class TestDatabaseResetTests(unittest.TestCase):
    def test_reset_program_is_bash_valid_and_fail_closed(self):
        script = RESET.reset_script("bfq-test1234", "bridgefu-web-sdk-handoff")
        result = subprocess.run(
            ["bash", "-n"], input=script, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "SELECT COUNT(*) FROM calls WHERE call_state NOT IN ('ended', 'failed')",
            script,
        )
        self.assertGreaterEqual(script.count('[ "$(active_calls)" = 0 ]'), 2)
        self.assertLess(
            script.index("systemctl stop bridgefu.service"),
            script.index('mv "$source" "$backup/$suffix"'),
        )
        self.assertIn("trap restore_previous EXIT", script)
        self.assertIn("fresh_database", script)
        self.assertIn("prove_bridgefu_stable", script)
        self.assertNotIn("SELECT call_id", script)

    def test_cleanup_program_restores_only_a_pending_exact_backup(self):
        script = RESET.cleanup_script("bfq-test1234", "vapi-sip-transfer")
        result = subprocess.run(
            ["bash", "-n"], input=script, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('if [ -d "$backup" ] && [ ! -L "$backup" ]; then', script)
        self.assertIn("systemctl stop bridgefu.service", script)
        self.assertIn("systemctl start bridgefu.service", script)
        self.assertIn("wait_bridgefu_ready", script)
        self.assertIn('[ ! -e "$run" ] && [ ! -L "$run" ]', script)

    def test_only_the_three_disposable_scenarios_are_accepted(self):
        for stage in RESET.STAGES:
            RESET.reset_script("bfq-test1234", stage)
        for stage in ("production", "", "vapi-sip-transfer; touch /tmp/x"):
            with (
                self.subTest(stage=stage),
                self.assertRaises(RESET.TestDatabaseResetError),
            ):
                RESET.reset_script("bfq-test1234", stage)

    def test_reset_and_cleanup_evidence_are_exact(self):
        stage = "direct-secure-preflight"
        reset = {
            "schema_version": 1,
            "producer": RESET.PRODUCER,
            "stage": stage,
            "test_delete_verified": True,
            "prior_calls_terminal": True,
            "fresh_database": True,
            "bridgefu_ready": True,
            "redacted": True,
        }
        cleanup = {
            "schema_version": 1,
            "producer": RESET.PRODUCER,
            "stage": stage,
            "pending_backup_absent": True,
            "bridgefu_ready": True,
            "redacted": True,
        }
        self.assertEqual(RESET.parse_reset_result(json.dumps(reset), stage), reset)
        self.assertEqual(
            RESET.parse_cleanup_result(json.dumps(cleanup), stage), cleanup
        )
        reset["fresh_database"] = False
        with self.assertRaises(RESET.TestDatabaseResetError):
            RESET.parse_reset_result(json.dumps(reset), stage)

    def test_controller_requires_testdelete_and_records_the_exact_stage(self):
        stage = "bridgefu-web-sdk-handoff"

        class Aws:
            def __init__(self):
                self.ids = iter(("reset-command", "cleanup-command"))
                self.calls = []

            def text(self, arguments, timeout=900):
                self.calls.append(arguments)
                return next(self.ids)

            def json(self, arguments, timeout=900):
                command_id = arguments[arguments.index("--command-id") + 1]
                if command_id == "reset-command":
                    value = {
                        "schema_version": 1,
                        "producer": RESET.PRODUCER,
                        "stage": stage,
                        "test_delete_verified": True,
                        "prior_calls_terminal": True,
                        "fresh_database": True,
                        "bridgefu_ready": True,
                        "redacted": True,
                    }
                else:
                    value = {
                        "schema_version": 1,
                        "producer": RESET.PRODUCER,
                        "stage": stage,
                        "pending_backup_absent": True,
                        "bridgefu_ready": True,
                        "redacted": True,
                    }
                return {
                    "Status": "Success",
                    "StandardOutputContent": json.dumps(value),
                }

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(execution_id="bfq-test1234")
        controller.outputs = {
            "BridgefuInstanceId": "i-0123456789abcdef0",
            "QualificationDataRetentionMode": "TestDelete",
        }
        controller.processes = []
        controller.ssm_commands = []
        controller.database_reset_evidence = {}
        controller.aws = Aws()
        controller.reset_test_database(stage)
        self.assertEqual(controller.database_reset_evidence[stage]["stage"], stage)
        self.assertEqual(controller.ssm_commands, [])
        self.assertEqual(len(controller.aws.calls), 2)

        controller.outputs["QualificationDataRetentionMode"] = "ProductionRetain"
        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "DataRetentionMode=TestDelete"
        ):
            controller.reset_test_database(stage)
        self.assertEqual(len(controller.aws.calls), 2)


if __name__ == "__main__":
    unittest.main()
