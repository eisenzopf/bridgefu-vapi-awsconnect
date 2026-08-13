from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUALIFICATION = ROOT / "qualification"


class QualificationAssetTests(unittest.TestCase):
    def pinned_bridgefu_checkout(self) -> Path:
        candidates = [
            Path(os.environ["BRIDGEFU_CHECKOUT"])
            if "BRIDGEFU_CHECKOUT" in os.environ
            else None,
            ROOT / "target" / "pinned-bridgefu",
            ROOT.parent / "bridgefu-main-clean",
        ]
        for candidate in candidates:
            if (
                candidate is not None
                and (candidate / "sdk/typescript/package.json").is_file()
            ):
                return candidate
        self.fail("the exact pinned Bridgefu checkout is required for SDK bundle tests")

    def test_matrix_contains_only_the_two_release_smokes(self):
        text = (QUALIFICATION / "matrix.yaml").read_text()
        scenarios = set(re.findall(r"^  - id: ([a-z0-9-]+)$", text, re.M))
        self.assertEqual(scenarios, {"vapi-sip-transfer", "bridgefu-web-sdk-handoff"})
        for removed_scope in ("soak", "failure_drill", "sip-rtp-pcmu"):
            self.assertNotIn(removed_scope, text)
        self.assertIn("dtmf_source_to_agent", text)

    def test_sip_source_uses_exact_crates_io_rvoip_037(self):
        crate = tomllib.loads((QUALIFICATION / "sip-client" / "Cargo.toml").read_text())
        self.assertEqual(
            crate["dependencies"]["rvoip-sip"],
            {"version": "=0.3.7", "default-features": False},
        )
        lock = (QUALIFICATION / "sip-client" / "Cargo.lock").read_text()
        package = lock.split('name = "rvoip-sip"', 1)[1].split("[[package]]", 1)[0]
        self.assertIn('version = "0.3.7"', package)
        self.assertIn(
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            package,
        )

    def test_web_sdk_is_referenced_from_bridgefu_not_copied(self):
        self.assertFalse((QUALIFICATION / "web-sdk").exists())
        lock = json.loads((ROOT / "bridgefu.lock.json").read_text())
        self.assertEqual(
            lock["repository"], "https://github.com/eisenzopf/bridgefu.git"
        )
        self.assertRegex(lock["commit"], r"^[0-9a-f]{40}$")
        browser = (
            QUALIFICATION / "browser" / "bridgefu-web-playwright.mjs"
        ).read_text()
        self.assertIn('join(ROOT, "qualification/package.json")', browser)
        for forbidden in ("VAPI_PUBLIC_KEY", "--assistant-id", "webCall"):
            self.assertNotIn(forbidden, browser)
        self.assertIn('required(options, "--route-attachment")', browser)
        self.assertIn('required(options, "--prompt-pcm")', browser)
        self.assertIn('required(options, "--signaling-hostname")', browser)
        self.assertIn("--host-resolver-rules=MAP", browser)
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(
            "node --check qualification/browser/bridgefu-web-playwright.mjs",
            makefile,
        )
        self.assertNotIn("vapi-web-playwright.mjs", makefile)
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("Test the exact pinned Bridgefu browser SDK", workflow)
        self.assertIn(
            "npm --prefix target/pinned-bridgefu/sdk/typescript test", workflow
        )

    def test_bridgefu_web_demo_site_is_owned_and_built_by_this_repository(self):
        controller = (QUALIFICATION / "controller.py").read_text()
        package = json.loads((QUALIFICATION / "package.json").read_text())
        self.assertNotIn("build-recipe-demo-site.py", controller)
        build_site = controller.split("    def build_site", 1)[1].split(
            "\n    def authenticate_agent", 1
        )[0]
        self.assertIn("prepare_demo_site_archive(", build_site)
        self.assertIn("self.args.demo_site_sha256", build_site)
        run = controller.split("    def run(self)", 1)[1].split("\ndef parser()", 1)[0]
        self.assertLess(
            run.index('self.phase = "web_site_validation"'),
            run.index('self.phase = "preflight"'),
        )
        self.assertNotIn("@vapi-ai/web", package.get("dependencies", {}))
        self.assertEqual(package["devDependencies"]["esbuild"], "0.28.1")
        app = (QUALIFICATION / "demo-site" / "app.js").read_text()
        self.assertIn('from "@bridgefu/webrtc-browser"', app)
        for forbidden in ("@vapi-ai/web", "VAPI_PUBLIC_KEY", "webCall", "new Vapi"):
            self.assertNotIn(forbidden, app)
        for name in ("index.html", "style.css", "app.js"):
            self.assertTrue((QUALIFICATION / "demo-site" / name).is_file())

        checkout = self.pinned_bridgefu_checkout()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            for output in (first, second):
                subprocess.run(
                    [
                        "python3",
                        str(QUALIFICATION / "build_demo_site.py"),
                        "--output",
                        str(output),
                        "--bridgefu-checkout",
                        str(checkout),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            first_archive = first / "demo-site.zip"
            second_archive = second / "demo-site.zip"
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            with zipfile.ZipFile(first_archive) as bundle:
                self.assertEqual(
                    sorted(bundle.namelist()),
                    sorted(
                        [
                            "index.html",
                            "style.css",
                            "app.js",
                            "app.js.LEGAL.txt",
                            "third-party-licenses.json",
                        ]
                    ),
                )
            manifest = json.loads((first / "manifest.json").read_text())
            source_lock = json.loads((ROOT / "bridgefu.lock.json").read_text())
            self.assertEqual(
                manifest["producer"],
                "bridgefu-vapi-awsconnect-qualification-site@2",
            )
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["bridgefu_commit"], source_lock["commit"])
            self.assertEqual(
                manifest["bridgefu_cargo_lock_sha256"],
                source_lock["cargo_lock_sha256"],
            )
            self.assertEqual(
                manifest["bridgefu_sdk"]["name"], "@bridgefu/webrtc-browser"
            )
            with zipfile.ZipFile(first_archive) as bundle:
                javascript = bundle.read("app.js").decode()
            for forbidden in ("@vapi-ai/web", "VAPI_PUBLIC_KEY", "webCall"):
                self.assertNotIn(forbidden, javascript)
            for marker in (
                "bridgefu.handoff.v1",
                "rvoip.webrtc.v1",
                "bridgefu.attach.",
            ):
                self.assertIn(marker, javascript)

    def test_packer_creates_runtime_staging_directory_before_upload(self):
        packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()
        create = 'inline = ["install -d -m 0755 /tmp/bridgefu-runtime"]'
        upload = 'destination = "/tmp/bridgefu-runtime/"'
        self.assertIn(create, packer)
        self.assertIn(upload, packer)
        self.assertLess(packer.index(create), packer.index(upload))

    def test_release_creates_packer_manifest_parent_before_build(self):
        workflow = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        build = workflow.split(
            "      - name: Build and copy private candidate AMIs\n", 1
        )[1].split("\n      - name:", 1)[0]
        self.assertIn("mkdir -p target", build)
        self.assertIn("packer build", build)
        self.assertLess(build.index("mkdir -p target"), build.index("packer build"))

    def test_static_sip_client_links_opus_dependencies_and_launches_in_ci(self):
        workflows = [
            (ROOT / ".github" / "workflows" / name).read_text()
            for name in ("ci.yml", "candidate.yml", "remote-qualification.yml")
        ]
        for workflow in workflows:
            self.assertIn(
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER: "
                "aarch64-linux-musl-gcc",
                workflow,
            )
            self.assertIn(
                "RUSTFLAGS: -C link-arg=-Wl,-Bstatic -C link-arg=-lm -C link-arg=-lc",
                workflow,
            )
            self.assertIn("aarch64-unknown-linux-musl", workflow)
            self.assertIn("--help >/dev/null", workflow)
        self.assertIn("runs-on: ubuntu-24.04-arm", workflows[0])

    def test_image_verifies_al2023_preinstalled_aws_cli_and_curl(self):
        install = (ROOT / "image" / "install.sh").read_text()
        package_block = install.split("sudo dnf install -y", 1)[1].split("\n\n", 1)[0]
        self.assertNotIn("awscli2", package_block)
        self.assertNotRegex(package_block, r"(?:^|\s)curl(?:\s|$)")
        self.assertIn("aws --version 2>&1 | grep -Eq '^aws-cli/2\\.'", install)
        self.assertIn(
            "curl --version 2>&1 | grep -Eq '^Protocols:.* https( |$)'", install
        )

    def test_image_audits_rvoip_without_python_tomllib(self):
        install = (ROOT / "image" / "install.sh").read_text()
        self.assertNotIn("tomllib", install)
        self.assertIn("cargo metadata --locked --format-version 1", install)
        self.assertIn('select(.name | startswith("rvoip"))', install)
        self.assertIn(
            '(.source // "") != "registry+https://github.com/rust-lang/crates.io-index"',
            install,
        )

    def test_image_build_has_memory_headroom_and_bounded_cargo_jobs(self):
        packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()
        install = (ROOT / "image" / "install.sh").read_text()
        self.assertIn('instance_type = "m7g.2xlarge"', packer)
        self.assertIn("cargo build --locked --release --jobs 4 --bin bridgefu", install)

    def test_certificate_passphrase_preserves_exact_secret_bytes(self):
        refresh = (ROOT / "image" / "runtime" / "bridgefu-cert-refresh").read_text()
        self.assertIn("--output json", refresh)
        self.assertIn("jq -erj", refresh)
        self.assertNotIn('--output text > "$work/passphrase"', refresh)
        self.assertIn('passphrase_length="$(wc -c < "$work/passphrase")"', refresh)

    def test_bootstrap_reports_certificate_refresh_failures_exactly(self):
        bootstrap = (ROOT / "image" / "runtime" / "bootstrap.sh").read_text()
        marker = "record_step certificate-refresh"
        refresh = "/usr/local/sbin/bridgefu-cert-refresh"
        self.assertIn(marker, bootstrap)
        self.assertLess(bootstrap.index(marker), bootstrap.index(refresh))

    def test_image_installs_and_verifies_opus_build_and_runtime_dependencies(self):
        install = (ROOT / "image" / "install.sh").read_text()
        package_block = install.split("sudo dnf install -y", 1)[1].split("\n\n", 1)[0]
        self.assertIn("opus-devel", package_block)
        self.assertIn("rpm -q opus opus-devel", install)
        self.assertIn("pkg-config --exists opus", install)
        self.assertIn(
            "ldd /usr/local/bin/bridgefu | grep -Eq 'libopus\\.so\\.[0-9]+ => /'",
            install,
        )

    def test_disposable_connect_template_cannot_target_an_existing_instance(self):
        text = (
            QUALIFICATION / "cloudformation" / "disposable-connect.yaml"
        ).read_text()
        self.assertIn("Type: AWS::Connect::Instance", text)
        parameters = text.split("\nParameters:\n", 1)[1].split("\nResources:\n", 1)[0]
        self.assertNotIn("ConnectInstanceArn:", parameters)
        self.assertIn("DeletionPolicy: Delete", text)
        self.assertIn("AutoAccept: true", text)

    def test_disposable_stack_owns_exact_host_split_horizon_sip_dns(self):
        qualification = (QUALIFICATION / "cloudformation" / "template.yaml").read_text()
        product = (ROOT / "cloudformation" / "template.yaml").read_text()
        runtime = (ROOT / "cloudformation" / "nested" / "runtime.yaml").read_text()

        zone = qualification.split("  QualificationSipPrivateHostedZone:\n", 1)[
            1
        ].split("\n  QualificationSipPrivateRecord:\n", 1)[0]
        record = qualification.split("  QualificationSipPrivateRecord:\n", 1)[1].split(
            "\nOutputs:\n", 1
        )[0]
        self.assertIn("Type: AWS::Route53::HostedZone", zone)
        self.assertIn("Name: !Ref SipHostname", zone)
        self.assertIn("VPCId: !GetAtt Candidate.Outputs.BridgefuVpcId", zone)
        self.assertIn("ManagedBy, Value: bridgefu-qualification", zone)
        self.assertIn("DeletionPolicy: Delete", zone)
        self.assertIn("Type: AWS::Route53::RecordSet", record)
        self.assertIn("HostedZoneId: !Ref QualificationSipPrivateHostedZone", record)
        self.assertIn(
            "ResourceRecords: [!GetAtt Candidate.Outputs.BridgefuInstancePrivateIp]",
            record,
        )
        self.assertIn("BridgefuVpcId:", product)
        self.assertIn("BridgefuInstancePrivateIp:", product)
        self.assertNotIn("QualificationSipPrivateHostedZone", product + runtime)
        self.assertNotIn("Disposable split-horizon SIP DNS", product + runtime)
        role = (ROOT / "publisher" / "qualification-role.yaml").read_text()
        self.assertIn("ProveQualificationPrivateDnsDeleted", role)
        self.assertIn("Action: route53:GetHostedZone", role)
        self.assertIn(
            "Resource: !Sub 'arn:${AWS::Partition}:route53:::hostedzone/*'", role
        )

    def test_tag_publication_consumes_a_prequalified_immutable_receipt(self):
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        publication = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertIn(
            "needs: [build-private-candidate, qualify-regions-sequentially]", candidate
        )
        self.assertIn("for REGION in us-west-2 us-east-1; do", candidate)
        self.assertNotIn("matrix:\n        region: [us-west-2, us-east-1]", candidate)
        self.assertIn("qualification/controller.py run", candidate)
        self.assertIn("bridgefu-vapi-sip-smoke", candidate)
        self.assertNotIn("--retain-on-failure", candidate)
        self.assertIn("bridgefu-qualified-candidate-receipt/v1", publication)
        self.assertIn("kms verify", publication)
        self.assertIn("modify-image-attribute", publication)
        self.assertNotIn("packer build", publication)

    def test_live_workflows_install_the_exact_session_manager_plugin(self):
        version = "1.2.835.0"
        digest = "7c6dcad12518571cc7959a713e6a8ae1bdf6ed66fd9bee37dc189e39ca58ae03"
        for workflow_name in ("candidate.yml", "remote-qualification.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text()
            self.assertIn(f"session_manager_version={version}", workflow)
            self.assertIn(f"session_manager_sha256={digest}", workflow)
            self.assertIn(
                "session-manager-downloads/plugin/$session_manager_version/"
                "ubuntu_64bit/session-manager-plugin.deb",
                workflow,
            )
            self.assertIn("sha256sum --check --strict", workflow)
            self.assertIn("sudo dpkg --install", workflow)
            self.assertIn("session-manager-plugin --version", workflow)

    def test_release_aws_sessions_cover_bounded_build_and_live_runs(self):
        qualification_role = (
            ROOT / "publisher" / "qualification-role.yaml"
        ).read_text()
        publisher_role = (ROOT / "publisher" / "oidc-role.yaml").read_text()
        self.assertIn("MaxSessionDuration: 10800", qualification_role)
        candidate_role = publisher_role.split("  CandidateBuilderRole:\n", 1)[1].split(
            "\n  PublisherRole:", 1
        )[0]
        self.assertIn("MaxSessionDuration: 10800", candidate_role)
        for workflow_name in ("candidate.yml", "remote-qualification.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text()
            credential_block = workflow.split(
                "role-to-assume: ${{ vars.AWS_QUALIFICATION_ROLE_ARN }}", 1
            )[1].split("\n      - name:", 1)[0]
            self.assertIn("role-duration-seconds: 10800", credential_block)
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        candidate_role_blocks = candidate.split(
            "role-to-assume: ${{ vars.AWS_CANDIDATE_ROLE_ARN }}"
        )[1:]
        self.assertEqual(len(candidate_role_blocks), 2)
        for credential_block in candidate_role_blocks:
            self.assertIn(
                "role-duration-seconds: 10800",
                credential_block.split("\n      - name:", 1)[0],
            )

    def test_publication_requires_signed_secure_preflight_attestations(self):
        publication = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        receipt_gate = publication.split(
            "      - name: Resolve tag and download its immutable qualified receipt\n",
            1,
        )[1].split("\n      - name:", 1)[0]
        for assertion in (
            ".evidence_schema_version == 2",
            ".secure_preflight_passed == true",
            ".required_checks_passed == true",
            '.scenario_ids == ["bridgefu-web-sdk-handoff","vapi-sip-transfer"]',
            ".zero_resource_proof == true",
        ):
            self.assertGreaterEqual(receipt_gate.count(assertion), 2)
        self.assertLess(
            receipt_gate.index(".secure_preflight_passed == true"),
            receipt_gate.index("aws kms verify"),
        )
        self.assertLess(
            publication.index(".secure_preflight_passed == true"),
            publication.index(
                "      - name: Stage exact signed release receipt copies privately"
            ),
        )

    def test_sdp_observer_is_diagnostics_only_and_exactly_pinned(self):
        crate = tomllib.loads(
            (QUALIFICATION / "sdp-observer" / "Cargo.toml").read_text()
        )
        self.assertEqual(
            crate["dependencies"]["rvoip-sip-core"],
            "=0.3.7",
        )
        lock = (QUALIFICATION / "sdp-observer" / "Cargo.lock").read_text()
        package = lock.split('name = "rvoip-sip-core"', 1)[1].split("[[package]]", 1)[0]
        self.assertIn('version = "0.3.7"', package)
        self.assertIn(
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            package,
        )
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn(
            "cargo test --locked --manifest-path qualification/sdp-observer/Cargo.toml",
            ci,
        )
        self.assertIn("cargo clippy --locked --all-targets", ci)
        observer_job = ci.split("  sdp-diagnostics:\n", 1)[1].split(
            "\n  qualification-client:\n", 1
        )[0]
        self.assertIn('select(.name == "rvoip-sip-core")', observer_job)
        self.assertNotIn('select(.name == "rvoip-sip")', observer_job)
        for workflow in ("candidate.yml", "release.yml", "remote-qualification.yml"):
            self.assertNotIn(
                "qualification/sdp-observer",
                (ROOT / ".github" / "workflows" / workflow).read_text(),
            )

    def test_direct_secure_probe_is_exactly_pinned_and_candidate_packaged(self):
        crate = tomllib.loads(
            (QUALIFICATION / "direct-secure-probe" / "Cargo.toml").read_text()
        )
        self.assertEqual(
            crate["dependencies"]["rvoip-sip"],
            {"version": "=0.3.7", "default-features": False},
        )
        lock = (QUALIFICATION / "direct-secure-probe" / "Cargo.lock").read_text()
        package = lock.split('name = "rvoip-sip"', 1)[1].split("[[package]]", 1)[0]
        self.assertIn('version = "0.3.7"', package)
        self.assertIn(
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            package,
        )

        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn(
            "cargo fmt --manifest-path qualification/direct-secure-probe/Cargo.toml",
            ci,
        )
        self.assertIn(
            "--manifest-path qualification/direct-secure-probe/Cargo.toml",
            ci,
        )
        self.assertIn("cargo clippy --locked --all-targets", ci)
        self.assertIn(
            "name: qualification-native-clients-${{ github.sha }}",
            ci,
        )
        self.assertIn(
            "qualification/sip-client/target/aarch64-unknown-linux-musl/"
            "release/bridgefu-vapi-sip-smoke",
            ci,
        )
        self.assertIn(
            "qualification/direct-secure-probe/target/"
            "aarch64-unknown-linux-musl/release/bridgefu-direct-secure-probe",
            ci,
        )
        self.assertIn("retention-days: 7", ci)

        workflows = {
            name: (ROOT / ".github" / "workflows" / name).read_text()
            for name in ("ci.yml", "candidate.yml", "remote-qualification.yml")
        }
        for workflow in workflows.values():
            self.assertIn(
                "qualification/direct-secure-probe/target/"
                "aarch64-unknown-linux-musl/release/bridgefu-direct-secure-probe",
                workflow,
            )
            self.assertIn("file \"$binary\" | grep -F 'ARM aarch64'", workflow)
            self.assertIn("file \"$binary\" | grep -F 'statically linked'", workflow)
            self.assertIn('"$binary" --help >/dev/null', workflow)
            self.assertIn('.req == "=0.3.7"', workflow)
            self.assertIn(
                '.source == "registry+https://github.com/rust-lang/crates.io-index"',
                workflow,
            )

        candidate = workflows["candidate.yml"]
        self.assertIn(
            "upload_candidate_object target/candidate/bridgefu-direct-secure-probe",
            candidate,
        )
        self.assertNotIn(
            "bridgefu-direct-secure-probe",
            (ROOT / ".github" / "workflows" / "release.yml").read_text(),
        )

    def test_live_workflows_gate_on_the_packaged_secure_preflight(self):
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        remote = (
            ROOT / ".github" / "workflows" / "remote-qualification.yml"
        ).read_text()
        for workflow, probe_path in (
            (candidate, "target/candidate/bridgefu-direct-secure-probe"),
            (
                remote,
                "target/qualification-client/bridgefu-direct-secure-probe",
            ),
        ):
            controller_runs = workflow.count("qualification/controller.py run")
            self.assertGreater(controller_runs, 0)
            self.assertEqual(workflow.count("--direct-secure-probe"), controller_runs)
            self.assertIn(f"--direct-secure-probe {probe_path}", workflow)

        evidence_v2 = json.loads(
            (QUALIFICATION / "schemas" / "evidence-v2.schema.json").read_text()
        )
        required_preflight_checks = evidence_v2["properties"]["secure_preflight"][
            "properties"
        ]["checks"]["required"]
        receipt_gate = candidate.split(
            "      - name: Verify both regional qualifications and seal the receipt\n",
            1,
        )[1]
        self.assertIn(".schema_version == 2", receipt_gate)
        self.assertIn(".secure_preflight.passed == true", receipt_gate)
        self.assertIn("exact_true_checks", receipt_gate)
        for check in required_preflight_checks:
            self.assertIn(f'"{check}"', receipt_gate)
        self.assertIn(
            '([.scenarios[].id] | sort) == ["bridgefu-web-sdk-handoff","vapi-sip-transfer"]',
            receipt_gate,
        )
        for attestation in (
            "evidence_schema_version",
            "secure_preflight_passed",
            "required_checks_passed",
            "scenario_ids",
        ):
            self.assertIn(attestation, candidate)
            self.assertIn(attestation, remote)
        for signed_receipt_gate in (candidate, remote):
            self.assertIn(".evidence_schema_version == 2", signed_receipt_gate)
            self.assertIn(
                ".secure_preflight_passed == true",
                signed_receipt_gate,
            )
            self.assertIn(".required_checks_passed == true", signed_receipt_gate)
            self.assertIn(
                '.scenario_ids == ["bridgefu-web-sdk-handoff","vapi-sip-transfer"]',
                signed_receipt_gate,
            )

    def test_controller_proves_and_removes_every_disposable_resource_class(self):
        controller = (QUALIFICATION / "controller.py").read_text()
        for proof in (
            "customer_stack_absent",
            "connect_instance_absent",
            "temporary_vapi_resources_absent",
            "test_credentials_absent",
            "qualification_objects_absent",
            "qualification_private_dns_absent",
            "qualification_acm_validation_records_absent",
            "bridgefu_sip_invite_evidence",
            "bridgefu_correlation_evidence",
        ):
            self.assertIn(proof, controller)

    def test_both_smokes_gate_on_concrete_dtmf_observations(self):
        controller = (QUALIFICATION / "controller.py").read_text()
        agent = (
            QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"
        ).read_text()
        web = (QUALIFICATION / "browser" / "bridgefu-web-playwright.mjs").read_text()
        sip = (QUALIFICATION / "sip-client" / "src" / "main.rs").read_text()
        evidence_schema = (
            QUALIFICATION / "schemas" / "evidence-v1.schema.json"
        ).read_text()
        self.assertNotIn("CHECKS = {", controller)
        self.assertIn("dtmf_source_to_agent_observed", agent)
        self.assertIn("dtmf_agent_to_source_observed", web)
        self.assertIn("dtmf_source_to_agent_frames_sent", sip)
        self.assertIn('"dtmf_source_to_agent": {"const": true}', evidence_schema)

    def test_connect_available_is_selected_before_either_source_starts(self):
        controller = (QUALIFICATION / "controller.py").read_text()
        web = controller.split("    def web_smoke(", 1)[1].split(
            "    def cleanup_sip_transients(", 1
        )[0]
        sip = controller.split("    def _sip_smoke(", 1)[1].split(
            "    def verify_scenario(", 1
        )[0]
        self.assertLess(
            web.index("ensure_connect_agent_available"),
            web.index("bridgefu-web-playwright.mjs"),
        )
        self.assertLess(
            sip.index("ensure_connect_agent_available"),
            sip.index('"send-command"'),
        )


if __name__ == "__main__":
    unittest.main()
