from __future__ import annotations

import inspect
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from qualification import bridgefu_web_runtime as RUNTIME
from qualification import controller as CONTROLLER

ROOT = Path(__file__).resolve().parents[2]
BRIDGEFU = Path("/Users/jonathan/Developer/bridgefu-main-clean/target/debug/bridgefu")


def runtime_config() -> dict:
    return RUNTIME.build_runtime_config(
        region="us-west-2",
        deployment_id="bfq-runtime-test",
        sip_hostname="bfq-runtime-test.vapi-internal.com",
        public_ip="203.0.113.10",
        connect_instance_arn=(
            "arn:aws:connect:us-west-2:123456789012:instance/"
            "11111111-1111-1111-1111-111111111111"
        ),
        connect_flow_id="22222222-2222-2222-2222-222222222222",
        vapi_sip_username="bfq_runtime_test",
        signaling_port=18443,
    )


class BridgefuWebRuntimeTests(unittest.TestCase):
    def test_live_install_never_compiles_bridgefu_on_the_qualification_runner(self):
        source = inspect.getsource(CONTROLLER.Controller.install_web_runtime)
        self.assertNotIn("cargo", source)
        self.assertNotIn("bridgefu_checkout", source)
        self.assertIn("run_web_runtime_ssm", source)
        secret_arn = (
            "arn:aws:secretsmanager:us-west-2:123456789012:"  # noqa: S105
            "secret:bridgefu-runtime-test"
        )
        remote_script = RUNTIME.install_script(
            execution_id="bfq-runtime-test",
            region="us-west-2",
            bucket="bridgefu-artifacts-test",
            object_key="qualification/bfq-runtime-test/web-runtime/bridgefu.json",
            config_sha256="a" * 64,
            auth_secret_arn=secret_arn,
        )
        self.assertIn(
            '"$wrapper" validate "$run/bridgefu.yaml.candidate"', remote_script
        )
        self.assertLess(
            remote_script.index('"$wrapper" validate "$run/bridgefu.yaml.candidate"'),
            remote_script.index(
                "install -o root -g bridgefu -m 0640 "
                '"$run/bridgefu.yaml.candidate" "$config"'
            ),
        )

    def test_config_is_canonical_secret_free_and_owns_exact_routes(self):
        value = runtime_config()
        encoded = RUNTIME.encode_runtime_config(value)
        self.assertEqual(json.loads(encoded), value)
        self.assertNotIn(b"vapi-password", encoded)
        self.assertIn(
            f"env:{RUNTIME.VAPI_PASSWORD_ENV}",
            str(value["sip_profiles"]["qualification-vapi-assistant"]),
        )
        self.assertEqual(
            set(value["api"]["routes"]),
            {RUNTIME.WEB_ROUTE_ID, RUNTIME.CONNECT_ROUTE_ID},
        )
        self.assertEqual(
            value["api"]["route_attachments"]["webrtc"]["signaling_uri"],
            "wss://bfq-runtime-test.vapi-internal.com:18443/webrtc",
        )
        self.assertEqual(
            value["api"]["route_attachments"]["webrtc"]["ice_servers"],
            [{"urls": ["stun:stun.kinesisvideo.us-west-2.amazonaws.com:443"]}],
        )
        expected_stun = [
            {"urls": ["stun:stun.kinesisvideo.us-west-2.amazonaws.com:443"]}
        ]
        self.assertEqual(
            value["generic_bridge"]["webrtc"]["ice_servers"], expected_stun
        )
        self.assertEqual(value["generic_bridge"]["webrtc"]["nat_1to1_ips"], [])
        self.assertEqual(value["generic_bridge"]["sip_bind"], "127.0.0.1:5070")
        target = "sip:bfq_runtime_test@sip.vapi.ai:5061;transport=tls"
        self.assertEqual(
            value["api"]["routes"][RUNTIME.WEB_ROUTE_ID]["destination"]["endpoint"][
                "config"
            ]["uri"],
            target,
        )
        self.assertEqual(
            value["sip_profiles"]["qualification-vapi-assistant"]["allowed_targets"],
            [target],
        )
        self.assertIs(value["generic_bridge"]["webrtc"]["trickle_ice"], True)

    @unittest.skipUnless(BRIDGEFU.is_file(), "pinned Bridgefu binary is unavailable")
    def test_exact_pinned_bridgefu_accepts_the_generated_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bridgefu.json"
            path.write_bytes(RUNTIME.encode_runtime_config(runtime_config()))
            env = os.environ.copy()
            env.update(
                BRIDGEFU_API_BEARER_TOKEN="b" * 32,
                BRIDGEFU_CONTROL_HMAC_KEY="h" * 32,
                BRIDGEFU_QUALIFICATION_VAPI_SIP_PASSWORD="p" * 32,
            )
            result = subprocess.run(
                [os.fspath(BRIDGEFU), "--config", os.fspath(path), "validate"],
                text=True,
                capture_output=True,
                env=env,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_identity_and_port_boundaries_fail_closed(self):
        with self.assertRaises(RUNTIME.WebRuntimeContractError):
            RUNTIME.build_runtime_config(
                region="eu-west-1",
                deployment_id="bfq-runtime-test",
                sip_hostname="bfq-runtime-test.vapi-internal.com",
                public_ip="203.0.113.10",
                connect_instance_arn=(
                    "arn:aws:connect:us-west-2:123456789012:instance/"
                    "11111111-1111-1111-1111-111111111111"
                ),
                connect_flow_id="flow",
                vapi_sip_username="user",
                signaling_port=443,
            )

    def test_generated_ssm_scripts_are_secret_free_and_bash_valid(self):
        install = RUNTIME.install_script(
            execution_id="bfq-runtime-test",
            region="us-west-2",
            bucket="bridgefu-test-bucket",
            object_key="qualification/bfq-runtime-test/web-runtime.json",
            config_sha256="a" * 64,
            auth_secret_arn=(  # noqa: S106 -- ARN, not the secret value.
                "arn:aws:secretsmanager:us-west-2:123456789012:"
                "secret:bridgefu/bfq-runtime-test/vapi-sip-auth-AbCd"
            ),
        )
        cleanup = RUNTIME.cleanup_script(execution_id="bfq-runtime-test")
        reachability = RUNTIME.vapi_tls_reachability_script()
        for script in (install, cleanup, reachability):
            self.assertNotIn("vapi-password", script)
            result = subprocess.run(
                ["bash", "-n"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(all(len(line) <= 8192 for line in script.splitlines()))

        wrapper = install.split(
            "cat > \"$wrapper\" <<'BRIDGEFU_QUALIFICATION_WRAPPER'\n", 1
        )[1].split("\nBRIDGEFU_QUALIFICATION_WRAPPER\n", 1)[0]
        wrapper_result = subprocess.run(
            ["bash", "-n"],
            input=wrapper,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(wrapper_result.returncode, 0, wrapper_result.stderr)
        embedded_python = wrapper.split(
            "python3 - /run/bridgefu/qualification-vapi.env 3<<<\"$secret\" <<'PY'\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        compile(embedded_python, "bridgefu-qualification-web-runtime", "exec")
        self.assertIn('rstrip("\\n")', embedded_python)
        self.assertIn('+ "\\n")', embedded_python)
        self.assertIn(
            '"$wrapper" validate "$run/bridgefu.yaml.candidate" >/dev/null',
            install,
        )
        self.assertEqual(install.count("printf '%s\\n' '{\"schema_version\":1"), 1)
        self.assertEqual(install.count("systemctl restart bridgefu.service"), 1)
        self.assertIn(
            "if ! wait_bridgefu_ready 90 || ! prove_bridgefu_renewal_stable; then",
            install,
        )
        self.assertLess(
            install.index("bridgefu_lease_lost\n  systemctl restart"),
            install.index("ss -ltnH"),
        )
        self.assertIn("for _ in $(seq 1 3); do\n    sleep 5", install)
        self.assertEqual(cleanup.count("systemctl restart bridgefu.service"), 1)
        self.assertIn(
            'value.get("dependencies", {}).get("call_runtime") == "lease_lost"',
            cleanup,
        )
        self.assertIn("if ! wait_bridgefu_ready 90; then", cleanup)
        self.assertLess(
            cleanup.index("bridgefu_lease_lost\n  systemctl restart"),
            cleanup.index("prove_bridgefu_renewal_stable\nrm -f"),
        )
        self.assertIn("for _ in $(seq 1 3); do\n    sleep 5", cleanup)
        self.assertNotIn("cat /", cleanup)

        reachability_python = reachability.split("python3 - <<'PY'\n", 1)[1].split(
            "\nPY", 1
        )[0]
        compile(reachability_python, "bridgefu-vapi-tls-reachability", "exec")
        self.assertNotIn("print(", reachability_python.rsplit("print(", 1)[0])
        commands = [line for line in reachability.splitlines() if line]
        encoded = CONTROLLER.encode_ssm_shell_parameters(commands)
        self.assertEqual(json.loads(encoded), {"commands": commands})
        self.assertTrue(all(commands))

    def test_closed_runtime_results_are_exact(self):
        install = {
            "schema_version": 1,
            "producer": "bridgefu-web-runtime@1",
            "configuration_installed": True,
            "bridgefu_ready": True,
            "wss_listener_ready": True,
            "redacted": True,
        }
        cleanup = {
            "schema_version": 1,
            "producer": "bridgefu-web-runtime@1",
            "configuration_restored": True,
            "overlay_absent": True,
            "wrapper_absent": True,
            "dropin_absent": True,
            "bridgefu_ready": True,
            "redacted": True,
        }
        self.assertEqual(RUNTIME.validate_install_result(install), install)
        self.assertEqual(RUNTIME.validate_cleanup_result(cleanup), cleanup)
        reachability = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-tls-reachability@1",
            "dns": True,
            "tcp": True,
            "tls": True,
            "category": "passed",
            "redacted": True,
        }
        self.assertEqual(
            RUNTIME.validate_vapi_tls_reachability(reachability), reachability
        )
        changed = dict(cleanup, bridgefu_ready=False)
        with self.assertRaises(RUNTIME.WebRuntimeContractError):
            RUNTIME.validate_cleanup_result(changed)
        with self.assertRaises(RUNTIME.WebRuntimeContractError):
            RUNTIME.validate_vapi_tls_reachability(
                dict(reachability, tcp=False, tls=False, category="timeout")
            )

    def test_cleanup_restarts_once_only_for_the_latched_lease_lost_state(self):
        cleanup = RUNTIME.cleanup_script(execution_id="bfq-runtime-test")
        functions = "bridgefu_ready()" + cleanup.split("bridgefu_ready()", 1)[1].split(
            '[ "$(id -u)" -eq 0 ]', 1
        )[0]
        harness = functions + r'''
restart_count=0
probe_state="${PROBE_STATE:?}"
systemctl() {
  if [ "$1" = "is-active" ]; then
    return 0
  fi
  if [ "$1" = "restart" ]; then
    restart_count=$((restart_count + 1))
    probe_state=healthy
    return 0
  fi
  return 64
}
curl() {
  if [ "$probe_state" = "healthy" ]; then
    printf '%s\n' '{"ok":true,"dependencies":{"call_runtime":"healthy"}}'
  elif [ "$probe_state" = "lease_lost" ]; then
    printf '%s\n' '{"ok":false,"dependencies":{"call_runtime":"lease_lost"}}'
  else
    printf '%s\n' '{"ok":false,"dependencies":{"call_runtime":"degraded"}}'
  fi
}
sleep() { :; }
status=0
if ! wait_bridgefu_ready 1; then
  if systemctl is-active --quiet bridgefu.service && bridgefu_lease_lost; then
    systemctl restart bridgefu.service
    wait_bridgefu_ready 1 || status=$?
  else
    status=1
  fi
fi
if [ "$status" -eq 0 ]; then
  prove_bridgefu_renewal_stable || status=$?
fi
printf 'status=%s restarts=%s\n' "$status" "$restart_count"
'''
        for state, expected in (
            ("healthy", "status=0 restarts=0"),
            ("lease_lost", "status=0 restarts=1"),
            ("degraded", "status=1 restarts=0"),
        ):
            result = subprocess.run(
                ["bash"],
                input=harness,
                text=True,
                capture_output=True,
                env={**os.environ, "PROBE_STATE": state},
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def test_vapi_tls_preflight_runs_before_temporary_resource_creation(self):
        source = (ROOT / "qualification" / "controller.py").read_text()
        web_smoke = source.split("    def _web_smoke(\n", 1)[1].split(
            "\n    def cleanup_sip_transients", 1
        )[0]
        self.assertLess(
            web_smoke.index("vapi_tls_reachability_script"),
            web_smoke.index("provision_ready_temporary_vapi_phone"),
        )


if __name__ == "__main__":
    unittest.main()
