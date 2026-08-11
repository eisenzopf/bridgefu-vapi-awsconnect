from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "image" / "runtime"


class ImageRuntimeRendererTests(unittest.TestCase):
    def test_renderer_loads_templates_from_installed_library_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory)
            executable = installed / "usr/local/sbin/bridgefu-render"
            templates = installed / "usr/local/lib/bridgefu"
            executable.parent.mkdir(parents=True)
            templates.mkdir(parents=True)
            shutil.copy2(RUNTIME / "render.py", executable)
            for name in (
                "bridgefu.yaml.tmpl",
                "haproxy.cfg.tmpl",
                "prometheus.yaml",
                "cloudwatch-agent.json.tmpl",
            ):
                shutil.copy2(RUNTIME / name, templates / name)

            for path in (
                "etc/bridgefu",
                "etc/haproxy",
                "opt/aws/amazon-cloudwatch-agent/var",
                "opt/aws/amazon-cloudwatch-agent/etc",
            ):
                (installed / path).mkdir(parents=True)

            environment = {
                **os.environ,
                "BRIDGEFU_RENDER_ROOT": os.fspath(installed),
                "BRIDGEFU_DEPLOYMENT_ID": "bfq-test",
                "AWS_REGION": "us-west-2",
                "BRIDGEFU_SIP_HOSTNAME": "bridgefu.example.com",
                "BRIDGEFU_CONTROL_HOSTNAME": "control.example.com",
                "BRIDGEFU_PUBLIC_IP": "203.0.113.10",
                "BRIDGEFU_PRIVATE_IP": "10.0.0.10",
                "CONNECT_INSTANCE_ARN": (
                    "arn:aws:connect:us-west-2:123456789012:instance/abc-123"
                ),
                "CONNECT_ENTRY_FLOW_ID": "flow-123",
                "BRIDGEFU_SIP_SECURITY": "sip_rtp",
                "BRIDGEFU_MAX_CONCURRENT_CALLS": "10",
                "VAPI_SIGNALING_CIDRS": "198.51.100.0/24",
                "BRIDGEFU_RUNTIME_LOG_GROUP": "/bridgefu/runtime",
                "BRIDGEFU_PROMETHEUS_LOG_GROUP": "/bridgefu/prometheus",
            }
            subprocess.run(
                [sys.executable, os.fspath(executable)],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            self.assertIn(
                "deployment_id: bfq-test",
                (installed / "etc/bridgefu/bridgefu.yaml").read_text(),
            )
            self.assertIn(
                "bind 10.0.0.10:443",
                (installed / "etc/haproxy/haproxy.cfg").read_text(),
            )
            cloudwatch = json.loads(
                (
                    installed
                    / "opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json"
                ).read_text()
            )
            self.assertEqual(cloudwatch["agent"]["region"], "us-west-2")

            environment["BRIDGEFU_SIP_SECURITY"] = "sips_optional_srtp"
            subprocess.run(
                [sys.executable, os.fspath(executable)],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            bridgefu = (installed / "etc/bridgefu/bridgefu.yaml").read_text()
            self.assertIn("sip_security: sips_optional_srtp", bridgefu)
            self.assertIn("sip_tls:", bridgefu)
            self.assertIn("bind: 0.0.0.0:5061", bridgefu)
            self.assertIn("certificate_chain: /etc/bridgefu/tls/fullchain.pem", bridgefu)
            self.assertIn(
                "ssl crt /etc/haproxy/bridgefu.pem",
                (installed / "etc/haproxy/haproxy.cfg").read_text(),
            )


if __name__ == "__main__":
    unittest.main()
