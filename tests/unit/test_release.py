from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def reaper_source() -> str:
    return (
        (ROOT / ".github" / "workflows" / "release-reaper.yml").read_text()
        + "\n"
        + (ROOT / "release" / "reap_qualification.sh").read_text()
    )


class ReleaseContractTests(unittest.TestCase):
    def supported_regions(self) -> set[str]:
        catalog = json.loads((ROOT / "release" / "regions.json").read_text())
        return {item["code"] for item in catalog["regions"]}

    def test_public_template_prompts_only_for_customer_configuration(self):
        text = (ROOT / "cloudformation" / "template.yaml").read_text()
        parameter_text = text.split("\nParameters:\n", 1)[1].split("\nMappings:\n", 1)[
            0
        ]
        parameters = set(re.findall(r"^  ([A-Za-z0-9]+):", parameter_text, re.M))
        self.assertEqual(
            parameters,
            {
                "DeploymentId",
                "InstanceType",
                "ConnectInstanceArn",
                "TargetContactFlowArn",
                "PublicHostedZoneId",
                "SipHostname",
                "VapiApiKeySecretArn",
                "VapiModel",
                "VapiVoiceId",
                "ScreenPopFieldsJson",
                "RoutingJson",
                "ContextTtlSeconds",
                "MaxConcurrentCalls",
                "LogRetentionDays",
                "AlarmEmail",
                "DataRetentionMode",
                "SipSecurity",
            },
        )
        for forbidden in (
            "AmiId",
            "ArtifactBucket",
            "ArtifactKey",
            "NestedTemplateBaseUrl",
            "BridgefuImageUri",
            "SubnetId",
            "VapiApiKey",
        ):
            self.assertNotIn(forbidden, parameters)

    def test_release_templates_pin_nested_stacks_and_lambda_object_versions(self):
        root = (ROOT / "cloudformation" / "template.yaml").read_text()
        qualification = (
            ROOT / "qualification" / "cloudformation" / "template.yaml"
        ).read_text()
        nested = {
            name: (ROOT / "cloudformation" / "nested" / name).read_text()
            for name in ("configuration.yaml", "handoff-service.yaml", "vapi.yaml")
        }

        nested_template_tokens = {
            "configuration": "NESTED_CONFIGURATION_VERSION_ID_URLENCODED",
            "network": "NESTED_NETWORK_VERSION_ID_URLENCODED",
            "handoff-service": "NESTED_HANDOFF_SERVICE_VERSION_ID_URLENCODED",
            "connect": "NESTED_CONNECT_VERSION_ID_URLENCODED",
            "runtime": "NESTED_RUNTIME_VERSION_ID_URLENCODED",
            "vapi": "NESTED_VAPI_VERSION_ID_URLENCODED",
            "observability": "NESTED_OBSERVABILITY_VERSION_ID_URLENCODED",
        }
        for template_name, token in nested_template_tokens.items():
            self.assertIn(f"/nested/{template_name}.yaml?versionId=__{token}__", root)
        self.assertIn(
            "disposable-connect.yaml?versionId="
            "__QUALIFICATION_DISPOSABLE_CONNECT_VERSION_ID_URLENCODED__",
            qualification,
        )
        self.assertIn(
            "__PRODUCT_TEMPLATE_URL__?versionId="
            "__PRODUCT_TEMPLATE_VERSION_ID_URLENCODED__",
            qualification,
        )

        expected_lambda_versions = {
            "ConfigurationArtifactVersion": "CONFIGURATION_ARTIFACT_VERSION",
            "VapiProvisionerArtifactVersion": "VAPI_PROVISIONER_ARTIFACT_VERSION",
            "HandoffPrepareArtifactVersion": "HANDOFF_PREPARE_ARTIFACT_VERSION",
            "HandoffTransferArtifactVersion": "HANDOFF_TRANSFER_ARTIFACT_VERSION",
            "HandoffLookupArtifactVersion": "HANDOFF_LOOKUP_ARTIFACT_VERSION",
        }
        mapping = root.split("  RegionRelease:\n", 1)[1].split("\nRules:\n", 1)[0]
        for attribute, token in expected_lambda_versions.items():
            for region_token in ("US_EAST_1", "US_WEST_2"):
                self.assertIn(f"{attribute}: __{token}_{region_token}__", mapping)

        self.assertEqual(nested["configuration.yaml"].count("S3ObjectVersion:"), 1)
        self.assertEqual(nested["handoff-service.yaml"].count("S3ObjectVersion:"), 3)
        self.assertEqual(nested["vapi.yaml"].count("S3ObjectVersion:"), 1)
        self.assertIn(
            "S3ObjectVersion: !Ref ConfigurationArtifactVersion",
            nested["configuration.yaml"],
        )
        for parameter in (
            "PrepareArtifactVersion",
            "TransferArtifactVersion",
            "LookupArtifactVersion",
        ):
            self.assertIn(
                f"S3ObjectVersion: !Ref {parameter}",
                nested["handoff-service.yaml"],
            )
        self.assertIn(
            "S3ObjectVersion: !Ref ProvisionerArtifactVersion",
            nested["vapi.yaml"],
        )

    def test_phased_builder_renders_raw_and_url_encoded_exact_versions(self):
        version_id = "stage+one/object=version"
        lambda_names = (
            "configuration.zip",
            "vapi_provisioner.zip",
            "prepare_handoff.zip",
            "transfer_destination.zip",
            "connect_lookup.zip",
        )
        nested_names = (
            "configuration.yaml",
            "network.yaml",
            "handoff-service.yaml",
            "connect.yaml",
            "runtime.yaml",
            "vapi.yaml",
            "observability.yaml",
        )
        versions = {
            "schema": "bridgefu-release-object-versions/v1",
            "lambda": {
                region: {name: version_id for name in lambda_names}
                for region in self.supported_regions()
            },
            "nested": {name: version_id for name in nested_names},
            "qualification": {"disposable-connect.yaml": version_id},
            "product_template": version_id,
        }
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            versions_path = temporary / "versions.json"
            versions_path.write_text(json.dumps(versions))
            output = temporary / "release"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--versions-file",
                    str(versions_path),
                    "--release-prefix",
                    "diagnostics/build-123",
                    "--output",
                    str(output),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            product = (output / "cloudformation" / "template.yaml").read_text()
            qualification = (
                output / "qualification" / "cloudformation" / "template.yaml"
            ).read_text()
            encoded = urllib.parse.quote(version_id, safe="")
            self.assertIn(f'ConfigurationArtifactVersion: "{version_id}"', product)
            self.assertIn(
                "ConfigurationArtifactKey: "
                "diagnostics/build-123/1.2.3-test/artifacts/lambda/configuration.zip",
                product,
            )
            self.assertNotIn("ArtifactKey: releases/", product)
            self.assertIn("/diagnostics/build-123/1.2.3-test/", product)
            self.assertIn(f"configuration.yaml?versionId={encoded}", product)
            self.assertIn(f"disposable-connect.yaml?versionId={encoded}", qualification)
            self.assertIn(
                f"cloudformation/template.yaml?versionId={encoded}", qualification
            )
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertTrue(manifest["object_versions"]["exact"])
            quick_create = json.loads((output / "quick-create-links.json").read_text())[
                "launch"
            ]
            template_url = urllib.parse.parse_qs(
                urllib.parse.urlsplit(quick_create).fragment.split("?", 1)[1]
            )["templateURL"][0]
            self.assertNotIn("versionId", template_url)

    def test_builder_rejects_version_ids_that_can_escape_yaml_scalars(self):
        lambda_names = (
            "configuration.zip",
            "vapi_provisioner.zip",
            "prepare_handoff.zip",
            "transfer_destination.zip",
            "connect_lookup.zip",
        )
        nested_names = (
            "configuration.yaml",
            "network.yaml",
            "handoff-service.yaml",
            "connect.yaml",
            "runtime.yaml",
            "vapi.yaml",
            "observability.yaml",
        )
        unsafe = "version: injected"
        versions = {
            "schema": "bridgefu-release-object-versions/v1",
            "lambda": {
                region: {name: unsafe for name in lambda_names}
                for region in self.supported_regions()
            },
            "nested": {name: unsafe for name in nested_names},
            "qualification": {"disposable-connect.yaml": unsafe},
            "product_template": unsafe,
        }
        with tempfile.TemporaryDirectory() as directory:
            versions_path = Path(directory) / "versions.json"
            versions_path.write_text(json.dumps(versions))
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--versions-file",
                    str(versions_path),
                    "--output",
                    str(Path(directory) / "release"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid exact S3 VersionId", result.stderr)

    def test_plain_sip_is_confined_to_disposable_qualification(self):
        root = (ROOT / "cloudformation" / "template.yaml").read_text()
        qualification = (
            ROOT / "qualification" / "cloudformation" / "template.yaml"
        ).read_text()
        nested = {
            name: (ROOT / "cloudformation" / "nested" / name).read_text()
            for name in ("runtime.yaml", "handoff-service.yaml", "observability.yaml")
        }
        parameter = root.split("  SipSecurity:\n", 1)[1].split("\nMappings:\n", 1)[0]
        self.assertIn("Default: sips_optional_srtp", parameter)
        self.assertIn(
            "AllowedValues: [sips_optional_srtp, sips_srtp, sip_rtp]", parameter
        )
        safety_rule = root.split("  PlainSipOnlyForDisposableTests:\n", 1)[1].split(
            "\nConditions:\n", 1
        )[0]
        self.assertIn("!Equals [!Ref SipSecurity, sips_optional_srtp]", safety_rule)
        self.assertIn("!Equals [!Ref SipSecurity, sips_srtp]", safety_rule)
        self.assertIn("!Equals [!Ref DataRetentionMode, TestDelete]", safety_rule)
        self.assertEqual(root.count("SipSecurity: !Ref SipSecurity"), 1)
        self.assertEqual(
            root.count("SipSecurity: !GetAtt Configuration.Outputs.SipSecurity"),
            3,
        )
        self.assertIn("Default: sips_optional_srtp", qualification)
        self.assertIn(
            "AllowedValues: [sips_optional_srtp, sips_srtp, sip_rtp]",
            qualification,
        )
        self.assertIn("SipSecurity: !Ref SipSecurity", qualification)
        self.assertIn("DataRetentionMode: TestDelete", qualification)
        for text in nested.values():
            self.assertIn("Default: sips_optional_srtp", text)
            self.assertIn(
                "AllowedValues: [sips_optional_srtp, sips_srtp, sip_rtp]", text
            )
        for name in ("runtime.yaml", "observability.yaml"):
            self.assertIn(
                "SecureSip: !Not [!Equals [!Ref SipSecurity, sip_rtp]]",
                nested[name],
            )

    def test_web_sdk_smoke_owns_exact_us_vapi_tls_egress(self):
        qualification = (
            ROOT / "qualification" / "cloudformation" / "template.yaml"
        ).read_text()
        customer_runtime = (
            ROOT / "cloudformation" / "nested" / "runtime.yaml"
        ).read_text()
        for logical_id, next_logical_id, cidr in (
            (
                "QualificationVapiTlsEgress1",
                "QualificationVapiTlsEgress2",
                "44.229.228.186/32",
            ),
            (
                "QualificationVapiTlsEgress2",
                "DirectHandoffLogGroup",
                "44.238.177.138/32",
            ),
        ):
            resource = qualification.split(f"  {logical_id}:\n", 1)[1].split(
                f"\n  {next_logical_id}:\n", 1
            )[0]
            self.assertIn("Type: AWS::EC2::SecurityGroupEgress", resource)
            self.assertIn(
                "GroupId: !GetAtt Candidate.Outputs.BridgefuGatewaySecurityGroupId",
                resource,
            )
            self.assertIn("FromPort: 5061", resource)
            self.assertIn("ToPort: 5061", resource)
            self.assertIn(f"CidrIp: {cidr}", resource)
        self.assertNotIn("QualificationVapiTlsEgress", customer_runtime)

    def test_release_contains_versioned_quick_create_links_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--output",
                    directory,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            output = Path(directory)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertFalse(manifest["contains_secrets"])
            self.assertEqual(manifest["bridgefu"]["required_rvoip_version"], "0.3.7")
            self.assertEqual(
                set(manifest["supported_regions"]), self.supported_regions()
            )
            links = json.loads((output / "quick-create-links.json").read_text())
            self.assertEqual(set(links), {"launch"})
            parsed = urllib.parse.urlsplit(links["launch"])
            self.assertEqual(parsed.netloc, "console.aws.amazon.com")
            self.assertNotIn("region", urllib.parse.parse_qs(parsed.query))
            query = urllib.parse.parse_qs(parsed.fragment.split("?", 1)[1])
            self.assertEqual(query["stackName"], ["bridgefu-vapi-connect"])
            self.assertEqual(query["param_InstanceType"], ["t4g.large"])
            self.assertIn("/releases/1.2.3-test/", query["templateURL"][0])

    def test_deployment_region_uses_aws_console_for_both_us_connect_regions(self):
        text = (ROOT / "cloudformation" / "template.yaml").read_text()
        mapping = text.split("  RegionRelease:\n", 1)[1].split("\nRules:\n", 1)[0]
        mapped_regions = set(re.findall(r"^    ([a-z0-9-]+):$", mapping, re.M))
        self.assertEqual(mapped_regions, self.supported_regions())
        rule = text.split("  SupportedRegion:\n", 1)[1].split("\nConditions:\n", 1)[0]
        for region in self.supported_regions():
            self.assertIn(region, rule)
        self.assertNotIn("DeploymentRegion:", text)
        self.assertEqual(self.supported_regions(), {"us-west-2", "us-east-1"})

    def test_region_release_file_must_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            regions = Path(directory) / "regions.json"
            regions.write_text(
                json.dumps(
                    {
                        "us-west-2": {
                            "ami_id": "ami-00000000000000000",
                            "bucket": "example-us-west-2",
                        }
                    }
                )
            )
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--regions-file",
                    str(regions),
                    "--output",
                    str(Path(directory) / "release"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exactly the regions", result.stderr)

    def test_release_builder_refuses_to_replace_unowned_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            output.mkdir()
            (output / "customer-file.txt").write_text("keep me\n")
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((output / "customer-file.txt").read_text(), "keep me\n")

    def test_release_builder_binds_and_verifies_distribution_commit(self):
        commit = "1" * 40
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--repository-commit",
                    commit,
                    "--output",
                    str(output),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                manifest["distribution_source"]["repository_commit"], commit
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--verify-existing",
                    str(output),
                    "--expected-version",
                    "1.2.3-test",
                    "--expected-repository-commit",
                    commit,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            artifact = output / manifest["artifacts"][0]["path"]
            artifact.write_bytes(artifact.read_bytes() + b"tampered")
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--verify-existing",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("digest mismatch", result.stderr)

    def test_candidate_build_and_tag_publication_are_separate(self):
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        publication = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertIn("workflow_dispatch:", candidate)
        self.assertIn("packer build", candidate)
        self.assertIn("candidates/qualified/$VERSION/$GITHUB_SHA", candidate)
        self.assertIn("for REGION in us-west-2 us-east-1; do", candidate)
        self.assertNotIn("matrix:\n        region: [us-west-2, us-east-1]", candidate)
        self.assertIn("qualification/controller.py run", candidate)
        self.assertIn("release_objects", candidate)
        self.assertNotIn(
            'test "$(jq -r .release_ready bridgefu.lock.json)" = true', candidate
        )
        self.assertIn("push:\n    tags: ['v*']", publication)
        self.assertNotIn("packer build", publication)
        self.assertNotIn('--version "$VERSION"', publication)
        self.assertIn("candidates/qualified/$version/$GITHUB_SHA", publication)
        self.assertIn("signed dual-region qualification receipt", publication)
        self.assertIn("--version-id", publication)
        self.assertLess(
            publication.index("Make the exact qualified AMIs public first"),
            publication.index("Publish exact release object versions"),
        )
        self.assertLess(
            publication.index("Publish exact release object versions"),
            publication.index("Update mutable latest pointers"),
        )

    def test_public_s3_reads_require_the_publication_tag(self):
        bucket = (ROOT / "publisher" / "bucket.yaml").read_text()
        self.assertIn("PublicQualifiedReleaseRead", bucket)
        self.assertIn("- s3:GetObject\n", bucket)
        self.assertIn("- s3:GetObjectVersion\n", bucket)
        self.assertIn(
            "s3:ExistingObjectTag/bridgefu-publication-status: published", bucket
        )
        self.assertNotIn("PublicImmutableReleaseRead", bucket)

    def test_candidate_and_publisher_roles_have_separate_mutation_powers(self):
        policy = (ROOT / "publisher" / "oidc-role.yaml").read_text()
        candidate = policy.split("  CandidateBuilderRole:\n", 1)[1].split(
            "\n  PublisherRole:\n", 1
        )[0]
        publisher = policy.split("\n  PublisherRole:\n", 1)[1].split("\nOutputs:\n", 1)[
            0
        ]
        self.assertIn("candidates/*", candidate)
        self.assertIn("releases/*", candidate)
        self.assertNotIn("s3:PutObjectTagging", candidate)
        self.assertNotIn("ec2:ModifyImageAttribute", candidate)
        self.assertIn("s3:PutObjectVersionTagging", publisher)
        self.assertIn("ec2:ModifyImageAttribute", publisher)
        self.assertNotIn("ec2:RunInstances", publisher)

    def test_workflow_run_reaper_covers_candidate_cancellation(self):
        workflow = (ROOT / ".github" / "workflows" / "release-reaper.yml").read_text()
        reaper = reaper_source()
        self.assertIn("workflow_run:", reaper)
        self.assertIn("Build and qualify private candidate", reaper)
        self.assertIn("Publish qualified release", reaper)
        self.assertIn("Remote live qualification", reaper)
        self.assertIn("workflow_run.conclusion != 'success'", reaper)
        self.assertIn("delete-stack", reaper)
        self.assertIn("delete-objects", reaper)
        self.assertIn("Remove=[{Group=all}]", reaper)
        self.assertNotIn("environment: production-release", reaper)
        self.assertNotIn("environment: live-qualification", reaper)
        self.assertNotIn("AWS_CANDIDATE_ROLE_ARN", reaper)
        self.assertNotIn("AWS_PUBLISH_ROLE_ARN", reaper)
        self.assertNotIn("AWS_QUALIFICATION_ROLE_ARN", reaper)
        self.assertEqual(workflow.count("environment: release-recovery"), 3)
        self.assertEqual(workflow.count("AWS_RECOVERY_ROLE_ARN"), 3)
        policy = (ROOT / "publisher" / "oidc-role.yaml").read_text()
        recovery = policy.split("  RecoveryRole:\n", 1)[1].split("\nOutputs:\n", 1)[0]
        self.assertIn("environment:${GitHubRecoveryEnvironment}", recovery)
        self.assertIn(
            "token.actions.githubusercontent.com:ref: refs/heads/main", recovery
        )
        self.assertIn(
            "token.actions.githubusercontent.com:workflow: Reap incomplete release work",
            recovery,
        )

    def test_candidate_sealing_rejects_string_false_booleans(self):
        jq = shutil.which("jq")
        self.assertIsNotNone(jq)
        if jq is None:
            self.fail("jq is required for release-contract tests")
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        evidence_filter_match = re.search(
            r"jq -e --arg version.*?--arg bridgefu_commit.*?\\\n"
            r"\s+'(def exact_true_checks.*)' \"\$evidence\"",
            candidate,
            re.S,
        )
        self.assertIsNotNone(evidence_filter_match)
        if evidence_filter_match is None:
            self.fail("candidate evidence jq filter is missing")
        evidence_filter = evidence_filter_match.group(1)
        schema = json.loads(
            (ROOT / "qualification" / "schemas" / "evidence-v2.schema.json").read_text()
        )
        secure_required = schema["properties"]["secure_preflight"]["properties"][
            "checks"
        ]["required"]
        scenario_checks = schema["properties"]["scenarios"]["items"]["properties"][
            "checks"
        ]["required"]
        checks = {name: True for name in scenario_checks}
        evidence = {
            "schema_version": 2,
            "release": "1.2.3",
            "region": "us-west-2",
            "bridgefu_commit": "a" * 40,
            "redacted": True,
            "secure_preflight": {
                "passed": True,
                "checks": {name: True for name in secure_required},
            },
            "vapi_provisioning_resilience": {
                "schema_version": 1,
                "producer": "bridgefu-vapi-provisioning-resilience@1",
                "ambiguous_create_reconciled": True,
                "first_cycle_deleted": True,
                "second_cycle_recreated": True,
                "exact_owner_resources_present": True,
                "redacted": True,
                "passed": True,
            },
            "scenarios": [
                {
                    "id": "vapi-sip-transfer",
                    "passed": True,
                    "checks": dict(checks),
                },
                {
                    "id": "bridgefu-web-sdk-handoff",
                    "passed": True,
                    "checks": {**checks, "dtmf_agent_to_source": True},
                },
            ],
            "teardown": {
                name: True for name in schema["properties"]["teardown"]["required"]
            },
        }
        jq_args = [
            jq,
            "-e",
            "--arg",
            "version",
            "1.2.3",
            "--arg",
            "region",
            "us-west-2",
            "--arg",
            "bridgefu_commit",
            "a" * 40,
            evidence_filter,
        ]

        def evidence_status(value: object) -> int:
            return subprocess.run(  # noqa: S603
                jq_args,
                input=json.dumps(value),
                text=True,
                capture_output=True,
                check=False,
            ).returncode

        self.assertEqual(evidence_status(evidence), 0)
        for path in (
            ("secure_preflight", "checks", "tls_transport"),
            (
                "vapi_provisioning_resilience",
                "ambiguous_create_reconciled",
            ),
            ("scenarios", 0, "passed"),
            ("scenarios", 1, "checks", "audio_agent_to_source"),
            ("teardown", "customer_stack_absent"),
        ):
            changed = json.loads(json.dumps(evidence))
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = "false"
            self.assertNotEqual(evidence_status(changed), 0)

        computation_match = re.search(
            r"--argjson west_required_checks_passed "
            r"\"\$\(jq '([^']+)' target/qualification/us-west-2/evidence.json\)\"",
            candidate,
        )
        self.assertIsNotNone(computation_match)
        if computation_match is None:
            self.fail("candidate receipt computation jq filter is missing")
        changed = json.loads(json.dumps(evidence))
        changed["vapi_provisioning_resilience"]["passed"] = "false"
        computed = subprocess.run(  # noqa: S603
            [jq, "-c", computation_match.group(1)],
            input=json.dumps(changed),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(computed.stdout.strip(), "false")

        zero_filter_match = re.search(
            r"jq -e '(\(\.customer_stack_absent.*?"
            r"\.redacted == true\))' \\\n\s+\"\$zero\"",
            candidate,
            re.S,
        )
        self.assertIsNotNone(zero_filter_match)
        if zero_filter_match is None:
            self.fail("candidate zero-state jq filter is missing")
        zero = {
            "customer_stack_absent": True,
            "connect_instance_absent": True,
            "temporary_vapi_resources_absent": True,
            "test_credentials_absent": True,
            "qualification_objects_absent": True,
            "qualification_private_dns_absent": True,
            "qualification_acm_validation_records_absent": True,
            "redacted": True,
        }
        valid_zero = subprocess.run(  # noqa: S603
            [jq, "-e", zero_filter_match.group(1)],
            input=json.dumps(zero),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(valid_zero.returncode, 0)
        zero["customer_stack_absent"] = "false"
        invalid_zero = subprocess.run(  # noqa: S603
            [jq, "-e", zero_filter_match.group(1)],
            input=json.dumps(zero),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(invalid_zero.returncode, 0)

    def test_reaper_preserves_only_the_exact_signed_qualification(self):
        jq = shutil.which("jq")
        self.assertIsNotNone(jq)
        if jq is None:
            self.fail("jq is required for release-contract tests")
        reaper = (ROOT / ".github" / "workflows" / "release-reaper.yml").read_text()
        self.assertNotIn("journal is sealed as qualified", reaper)
        self.assertGreaterEqual(reaper.count("SIGNING_KEY_ARN:"), 2)
        self.assertGreaterEqual(
            reaper.count('aws kms verify --key-id "$SIGNING_KEY_ARN"'),
            2,
        )
        self.assertNotIn("jq -r .signing_key_arn", reaper)
        for claim in (
            ".evidence_schema_version == 2",
            ".secure_preflight_passed == true",
            ".required_checks_passed == true",
            '.scenario_ids == ["bridgefu-web-sdk-handoff","vapi-sip-transfer"]',
            ".zero_resource_proof == true",
            '.release_objects | type == "array" and length > 0',
        ):
            self.assertGreaterEqual(reaper.count(claim), 2)

        receipt_filter_match = re.search(
            r"jq -e --arg version.*?--arg signing_key.*?\\\n"
            r"\s+'([^']+)' \\\n\s+sealed-receipt.json",
            reaper,
            re.S,
        )
        self.assertIsNotNone(receipt_filter_match)
        if receipt_filter_match is None:
            self.fail("candidate-reaper receipt jq filter is missing")
        receipt_filter = receipt_filter_match.group(1)
        attestation = {
            "evidence_schema_version": 2,
            "secure_preflight_passed": True,
            "required_checks_passed": True,
            "scenario_ids": ["bridgefu-web-sdk-handoff", "vapi-sip-transfer"],
            "zero_resource_proof": True,
        }
        receipt = {
            "schema": "bridgefu-qualified-candidate-receipt/v1",
            "version": "1.2.3",
            "repository": {"commit": "a" * 40},
            "candidate_id": "candidate-1.2.3-abcdef12",
            "signing_key_arn": "expected-key",
            "regional_amis": {"us-west-2": {}, "us-east-1": {}},
            "qualification": {
                "us-west-2": dict(attestation),
                "us-east-1": dict(attestation),
            },
            "release_objects": [
                {
                    "region": "us-east-1",
                    "bucket": "bucket",
                    "key": "releases/1.2.3/manifest.json",
                    "version_id": "version-1",
                }
            ],
        }
        jq_args = [
            jq,
            "-e",
            "--arg",
            "version",
            "1.2.3",
            "--arg",
            "commit",
            "a" * 40,
            "--arg",
            "candidate_id",
            "candidate-1.2.3-abcdef12",
            "--arg",
            "signing_key",
            "expected-key",
            receipt_filter,
        ]

        def receipt_status(value: object) -> int:
            return subprocess.run(  # noqa: S603
                jq_args,
                input=json.dumps(value),
                text=True,
                capture_output=True,
                check=False,
            ).returncode

        self.assertEqual(receipt_status(receipt), 0)
        for field in (
            "secure_preflight_passed",
            "required_checks_passed",
            "zero_resource_proof",
        ):
            changed = json.loads(json.dumps(receipt))
            changed["qualification"]["us-west-2"][field] = "false"
            self.assertNotEqual(receipt_status(changed), 0)
        wrong_schema = json.loads(json.dumps(receipt))
        wrong_schema["qualification"]["us-east-1"]["evidence_schema_version"] = "2"
        self.assertNotEqual(receipt_status(wrong_schema), 0)
        wrong_scenarios = json.loads(json.dumps(receipt))
        wrong_scenarios["qualification"]["us-east-1"]["scenario_ids"] = [
            "vapi-sip-transfer"
        ]
        self.assertNotEqual(receipt_status(wrong_scenarios), 0)
        wrong_key = json.loads(json.dumps(receipt))
        wrong_key["signing_key_arn"] = "attacker-controlled-key"
        self.assertNotEqual(receipt_status(wrong_key), 0)
        duplicate_inventory = json.loads(json.dumps(receipt))
        duplicate_inventory["release_objects"].append(
            dict(duplicate_inventory["release_objects"][0])
        )
        self.assertNotEqual(receipt_status(duplicate_inventory), 0)

    def test_candidate_and_reaper_use_exact_ownership_at_cancellation_windows(self):
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        reaper = (ROOT / ".github" / "workflows" / "release-reaper.yml").read_text()
        packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()
        for tag in ("BridgefuCandidateId", "BridgefuRepositoryCommit"):
            self.assertIn(tag, packer)
            self.assertIn(tag, reaper)
        self.assertIn("journal_ami us-west-2", candidate)
        self.assertIn(".release_objects +=", candidate)
        self.assertIn(".candidate_objects +=", candidate)
        self.assertIn("--arg version_id", candidate)
        self.assertIn(".regional_amis | to_entries[]", reaper)
        self.assertIn("Name=tag:BridgefuCandidateId,Values=$candidate_id", reaper)
        self.assertIn("discover_candidate_versions", reaper)
        self.assertIn('.Metadata["candidate-id"] // empty', reaper)
        self.assertNotIn("Name=tag:BridgefuRelease,Values=$version", reaper)
        self.assertNotIn(
            'delete_prefix_versions "$region" "$bucket" "releases/$version/"',
            reaper,
        )
        self.assertIn('array_name="${ownership_class}_objects"', reaper)
        self.assertIn('--version-id "$version_id"', reaper)

    def test_publication_and_rollback_are_attempt_owned_and_fail_closed(self):
        publication = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        reaper = (ROOT / ".github" / "workflows" / "release-reaper.yml").read_text()
        self.assertIn("bridgefu-publication-attempt", publication)
        self.assertIn("BridgefuPublicationAttempt", publication)
        self.assertIn("--if-none-match '*'", publication)
        self.assertIn("release_receipt_objects", publication)
        self.assertIn("latest_objects", publication)
        self.assertIn(
            "Verify the complete public state belongs to this attempt", publication
        )
        self.assertIn(
            'publication_attempt="$SOURCE_RUN_ID-$SOURCE_RUN_ATTEMPT"', reaper
        )
        self.assertIn("group: bridgefu-vapi-awsconnect-release", reaper)
        self.assertIn("A newer publication attempt owns", reaper)
        self.assertIn("describe-snapshot-attribute", reaper)
        self.assertIn("describe-image-attribute", reaper)
        self.assertNotIn("|| true", reaper)
        self.assertNotIn("--prefix latest/", reaper)

    def test_candidate_qualifies_and_validates_exact_versioned_root_urls(self):
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        remote = (
            ROOT / ".github" / "workflows" / "remote-qualification.yml"
        ).read_text()
        for phase in ("assets", "product", "complete"):
            self.assertIn(f"--render-phase {phase}", candidate)
        self.assertIn("object-versions.json", candidate)
        self.assertIn('template_url="https://$east_bucket', candidate)
        self.assertIn('--template-url "$template_url"', candidate)
        self.assertIn("?versionId=$encoded_version", candidate)
        self.assertIn("exact_candidate_version", remote)
        self.assertIn('--version-id "$receipt_version"', remote)
        self.assertIn("aws kms verify --region us-east-1", remote)
        self.assertIn("?versionId=$QUALIFICATION_TEMPLATE_VERSION", remote)

    def test_recovery_deletes_only_the_exact_journaled_vapi_phone(self):
        reaper = reaper_source()
        self.assertIn(
            'journal_key="qualification/$execution_id/ownership/vapi-phone.json"',
            reaper,
        )
        self.assertIn('phone_url="https://api.vapi.ai/phone-number/$phone_id"', reaper)
        self.assertIn(".assistantId == $assistant_id", reaper)
        self.assertIn(".name == $name", reaper)
        self.assertIn("--request DELETE", reaper)
        self.assertIn('test "$status" = 404', reaper)
        self.assertIn("/phone-number?limit=100", reaper)
        self.assertIn('type == "array" and length < 100', reaper)
        self.assertNotIn('echo "$vapi_key"', reaper)
        policy = (ROOT / "publisher" / "oidc-role.yaml").read_text()
        recovery = policy.split("  RecoveryRole:\n", 1)[1].split("\nOutputs:\n", 1)[0]
        secret_access = recovery.split(
            "- Sid: ReadExactRegionalVapiKeysForOrphanCleanup", 1
        )[1].split("- Sid:", 1)[0]
        self.assertIn("!Ref VapiApiKeySecretArnUsWest2", secret_access)
        self.assertIn("!Ref VapiApiKeySecretArnUsEast1", secret_access)
        self.assertNotIn("Resource: '*'", secret_access)

    def test_qualification_runner_can_only_mutate_tagged_disposable_agent(self):
        policy = (ROOT / "publisher" / "qualification-role.yaml").read_text()
        self.assertIn("connect:ListUsers", policy)
        self.assertIn("connect:ListAgentStatuses", policy)
        self.assertIn("connect:PutUserStatus", policy)
        listing = policy.split("- Sid: ListAgentStatusesForQualification", 1)[1].split(
            "- Sid: SetStatusOnlyOnTaggedDisposableInstanceAndUser", 1
        )[0]
        self.assertIn("instance/*/agent-state/*", listing)
        self.assertNotIn("instance/*/agent/*", listing)
        tagged = policy.split(
            "- Sid: SetStatusOnlyOnTaggedDisposableInstanceAndUser", 1
        )[1].split("- Sid: UseSelectedAgentStatusForQualification", 1)[0]
        self.assertIn("instance/*'", tagged)
        self.assertIn("instance/*/agent/*", tagged)
        self.assertIn("aws:ResourceTag/ManagedBy: bridgefu-qualification", tagged)
        self.assertNotIn("Resource: '*'", tagged)
        selected_status = policy.split(
            "- Sid: UseSelectedAgentStatusForQualification", 1
        )[1].split("- Sid:", 1)[0]
        self.assertIn("instance/*/agent-state/*", selected_status)
        self.assertNotIn("instance/*/agent/*", selected_status)
        self.assertNotIn("Resource: '*'", selected_status)
        full_role = policy.split("  QualificationRunnerRole:\n", 1)[1]
        self.assertEqual(full_role.count("Action: connect:PutUserStatus"), 2)

    def test_test_retention_mode_deletes_vapi_qualification_resources(self):
        root = (ROOT / "cloudformation" / "template.yaml").read_text()
        nested = (ROOT / "cloudformation" / "nested" / "vapi.yaml").read_text()
        self.assertIn(
            "RetainVapiResourcesOnDelete: !GetAtt Configuration.Outputs.RetainVapiResourcesOnDelete",
            root,
        )
        self.assertIn(
            "RetainVapiResourcesOnDelete: !Ref RetainVapiResourcesOnDelete",
            nested,
        )

    def test_github_roles_bind_the_immutable_repository_subject(self):
        subject = (
            "repo:${GitHubRepositoryOwner}@${GitHubRepositoryOwnerId}/"
            "${GitHubRepositoryName}@${GitHubRepositoryId}:"
            "environment:${GitHubEnvironment}"
        )
        for template_name in ("oidc-role.yaml", "qualification-role.yaml"):
            text = (ROOT / "publisher" / template_name).read_text()
            self.assertIn("GitHubRepositoryOwnerId:", text)
            self.assertIn("GitHubRepositoryId:", text)
            self.assertIn(subject, text)
            self.assertNotIn(
                "repo:${GitHubRepository}:environment:${GitHubEnvironment}", text
            )

    def test_publisher_can_validate_release_templates_remotely(self):
        text = (ROOT / "publisher" / "oidc-role.yaml").read_text()
        statement = text.split("              - Sid: ValidateReleaseTemplates\n", 1)[
            1
        ].split("              - Effect:", 1)[0]
        self.assertIn("Action: cloudformation:ValidateTemplate", statement)
        self.assertIn("Resource: '*'", statement)


if __name__ == "__main__":
    unittest.main()
