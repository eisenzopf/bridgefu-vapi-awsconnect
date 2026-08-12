from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "image" / "runtime"


class RuntimeObservabilityTests(unittest.TestCase):
    def test_cloudwatch_tails_systemd_runtime_log_not_docker(self):
        template = (RUNTIME / "cloudwatch-agent.json.tmpl").read_text()
        rendered = template.replace("__AWS_REGION__", "us-west-2")
        rendered = rendered.replace("__RUNTIME_LOG_GROUP__", "/bridgefu/runtime")
        rendered = rendered.replace("__PROMETHEUS_LOG_GROUP__", "/bridgefu/prometheus")
        rendered = rendered.replace("__DEPLOYMENT_ID__", "bfq-test")
        config = json.loads(rendered)
        collected = config["logs"]["logs_collected"]["files"]["collect_list"]

        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0]["file_path"], "/var/log/bridgefu/bridgefu.log")
        self.assertEqual(collected[0]["log_stream_name"], "{instance_id}")
        self.assertNotIn("docker", template.lower())

    def test_systemd_captures_stdout_and_stderr_in_private_runtime_log(self):
        service = (RUNTIME / "bridgefu.service").read_text()

        self.assertIn("LogsDirectory=bridgefu", service)
        self.assertIn("LogsDirectoryMode=0750", service)
        self.assertIn("StandardOutput=append:/var/log/bridgefu/bridgefu.log", service)
        self.assertIn("StandardError=append:/var/log/bridgefu/bridgefu.log", service)
        self.assertIn("UMask=0027", service)
        self.assertIn("/var/log/bridgefu", service)

        config = (RUNTIME / "bridgefu.yaml.tmpl").read_text()
        self.assertIn("log_level: info", config)
        self.assertIn("log_format: json", config)

    def test_bootstrap_creates_private_log_before_cloudwatch_starts(self):
        bootstrap = (RUNTIME / "bootstrap.sh").read_text()
        create = "touch /var/log/bridgefu/bridgefu.log"
        protect = "chmod 0640 /var/log/bridgefu/bridgefu.log"
        cloudwatch = "record_step cloudwatch-agent-start"
        service = "record_step bridgefu-service-start"

        for expected in (create, protect, cloudwatch, service):
            self.assertIn(expected, bootstrap)
        self.assertLess(bootstrap.index(create), bootstrap.index(cloudwatch))
        self.assertLess(bootstrap.index(protect), bootstrap.index(cloudwatch))
        self.assertLess(bootstrap.index(cloudwatch), bootstrap.index(service))
        self.assertIn("tail --lines=80 /var/log/bridgefu/bridgefu.log", bootstrap)
        self.assertNotIn("journalctl", bootstrap)

    def test_rotation_has_bounded_size_count_and_does_not_require_restart(self):
        policy = (RUNTIME / "bridgefu.logrotate").read_text()
        timer = (RUNTIME / "bridgefu-logrotate.timer").read_text()
        service = (RUNTIME / "bridgefu-logrotate.service").read_text()

        self.assertRegex(policy, r"(?m)^\s*size\s+16M$")
        match = re.search(r"(?m)^\s*rotate\s+(\d+)$", policy)
        self.assertIsNotNone(match)
        self.assertLessEqual(int(match.group(1)), 6)
        for directive in (
            "compress",
            "delaycompress",
            "copytruncate",
            "create 0640 bridgefu bridgefu",
            "su bridgefu bridgefu",
        ):
            self.assertIn(directive, policy)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn(
            "ExecStart=/usr/sbin/logrotate --state /var/lib/bridgefu/logrotate.status",
            service,
        )
        self.assertNotIn("systemctl restart bridgefu", policy)

    def test_image_installs_and_enables_rotation_policy(self):
        install = (ROOT / "image" / "install.sh").read_text()

        package_block = install.split("sudo dnf install -y", 1)[1].split("\n\n", 1)[0]
        self.assertRegex(package_block, r"(?:^|\s)logrotate(?:\s|$)")
        self.assertIn(
            "/usr/local/lib/bridgefu/bridgefu.logrotate /etc/logrotate.d/bridgefu",
            install,
        )
        self.assertIn("bridgefu-logrotate.service", install)
        self.assertIn("bridgefu-logrotate.timer", install)
        self.assertIn("logrotate --debug /etc/logrotate.d/bridgefu", install)
        bootstrap = (RUNTIME / "bootstrap.sh").read_text()
        self.assertIn("systemctl enable --now bridgefu-logrotate.timer", bootstrap)


if __name__ == "__main__":
    unittest.main()
