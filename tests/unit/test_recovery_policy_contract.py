from __future__ import annotations

import copy
import fnmatch
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "publisher" / "oidc-role.yaml"
QUALIFICATION_POLICY_PATH = ROOT / "publisher" / "qualification-role.yaml"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-reaper.yml"
QUALIFICATION_REAPER_PATH = ROOT / "release" / "reap_qualification.sh"
CANDIDATE_PATH = ROOT / ".github" / "workflows" / "candidate.yml"
REMOTE_QUALIFICATION_PATH = ROOT / ".github" / "workflows" / "remote-qualification.yml"


class CloudFormationLoader(yaml.SafeLoader):
    pass


def construct_cloudformation_tag(
    loader: CloudFormationLoader, _tag_suffix: str, node: yaml.Node
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


CloudFormationLoader.add_multi_constructor("!", construct_cloudformation_tag)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def reaper_source() -> str:
    embedded = "\n".join(
        "          " + line
        for line in QUALIFICATION_REAPER_PATH.read_text().splitlines()
    )
    return WORKFLOW_PATH.read_text() + "\n" + embedded + "\n"


def recovery_statements() -> list[dict[str, Any]]:
    loader = CloudFormationLoader(POLICY_PATH.read_text())
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    policies = document["Resources"]["RecoveryRole"]["Properties"]["Policies"]
    return policies[0]["PolicyDocument"]["Statement"]


def qualification_statements() -> list[dict[str, Any]]:
    loader = CloudFormationLoader(QUALIFICATION_POLICY_PATH.read_text())
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    policies = document["Resources"]["QualificationRunnerRole"]["Properties"][
        "Policies"
    ]
    return policies[0]["PolicyDocument"]["Statement"]


SUBSTITUTIONS = {
    "${AWS::Partition}": "aws",
    "${AWS::AccountId}": "225478700523",
    "${ArtifactBucketPrefix}": "bridgefu-vapi-awsconnect",
    "${QualificationPublicHostedZoneId}": "Z0123456789EXACT",
}


def concrete(value: str) -> str:
    for variable, replacement in SUBSTITUTIONS.items():
        value = value.replace(variable, replacement)
    return value


def allows(
    statements: list[dict[str, Any]],
    action: str,
    resource: str,
    *,
    prefix: str | None = None,
) -> bool:
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if not any(
            fnmatch.fnmatchcase(action.lower(), str(pattern).lower())
            for pattern in as_list(statement["Action"])
        ):
            continue
        if not any(
            fnmatch.fnmatchcase(resource, concrete(str(pattern)))
            for pattern in as_list(statement["Resource"])
        ):
            continue
        condition = statement.get("Condition", {})
        prefix_patterns = condition.get("StringLike", {}).get("s3:prefix")
        if prefix_patterns is not None:
            if prefix is None or not any(
                fnmatch.fnmatchcase(prefix, concrete(str(pattern)))
                for pattern in as_list(prefix_patterns)
            ):
                continue
        return True
    return False


CLI_ACTIONS = {
    ("acm", "describe-certificate"): {"acm:DescribeCertificate"},
    ("acm", "list-tags-for-certificate"): {"acm:ListTagsForCertificate"},
    ("cloudformation", "delete-stack"): {"cloudformation:DeleteStack"},
    ("cloudformation", "describe-stacks"): {"cloudformation:DescribeStacks"},
    ("cloudformation", "list-stack-resources"): {"cloudformation:ListStackResources"},
    ("cloudformation", "wait"): {"cloudformation:DescribeStacks"},
    ("ec2", "create-tags"): {"ec2:CreateTags"},
    ("ec2", "delete-snapshot"): {"ec2:DeleteSnapshot"},
    ("ec2", "delete-tags"): {"ec2:DeleteTags"},
    ("ec2", "deregister-image"): {"ec2:DeregisterImage"},
    ("ec2", "describe-image-attribute"): {"ec2:DescribeImageAttribute"},
    ("ec2", "describe-images"): {"ec2:DescribeImages"},
    ("ec2", "describe-snapshot-attribute"): {"ec2:DescribeSnapshotAttribute"},
    ("ec2", "describe-snapshots"): {"ec2:DescribeSnapshots"},
    ("ec2", "modify-image-attribute"): {"ec2:ModifyImageAttribute"},
    ("ec2", "modify-snapshot-attribute"): {"ec2:ModifySnapshotAttribute"},
    ("kms", "verify"): {"kms:Verify"},
    ("route53", "change-resource-record-sets"): {"route53:ChangeResourceRecordSets"},
    ("route53", "get-hosted-zone"): {"route53:GetHostedZone"},
    ("route53", "list-resource-record-sets"): {"route53:ListResourceRecordSets"},
    ("route53", "wait"): {"route53:GetChange"},
    ("s3api", "delete-object"): {"s3:DeleteObject", "s3:DeleteObjectVersion"},
    ("s3api", "delete-object-tagging"): {
        "s3:DeleteObjectTagging",
        "s3:DeleteObjectVersionTagging",
    },
    ("s3api", "delete-objects"): {"s3:DeleteObject", "s3:DeleteObjectVersion"},
    ("s3api", "get-object"): {"s3:GetObject", "s3:GetObjectVersion"},
    ("s3api", "get-object-tagging"): {
        "s3:GetObjectTagging",
        "s3:GetObjectVersionTagging",
    },
    # S3 authorizes HeadObject through the corresponding object read action.
    ("s3api", "head-object"): {"s3:GetObject"},
    ("s3api", "list-object-versions"): {"s3:ListBucketVersions"},
    ("s3api", "put-object"): {"s3:PutObject"},
    ("secretsmanager", "get-secret-value"): {"secretsmanager:GetSecretValue"},
    ("secretsmanager", "put-secret-value"): {"secretsmanager:PutSecretValue"},
    # GetCallerIdentity requires no identity-policy permission.
    ("sts", "get-caller-identity"): set(),
}


def workflow_commands() -> set[tuple[str, str]]:
    return set(re.findall(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)", reaper_source()))


class RecoveryPolicyContractTests(unittest.TestCase):
    def test_qualification_runner_can_delete_only_its_versioned_objects(self):
        statements = qualification_statements()
        owned = (
            "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-west-2/"
            "qualification/bfq-w-123-1/ownership/acm-validation-records.json"
        )
        unrelated = (
            "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-west-2/"
            "customer-data/context.json"
        )
        for action in ("s3:DeleteObject", "s3:DeleteObjectVersion"):
            self.assertTrue(allows(statements, action, owned))
            self.assertFalse(allows(statements, action, unrelated))

    def test_every_aws_cli_operation_has_an_explicit_policy_contract(self):
        commands = workflow_commands()
        self.assertEqual(commands - CLI_ACTIONS.keys(), set())
        actions = {
            str(action)
            for statement in recovery_statements()
            if statement.get("Effect") == "Allow"
            for action in as_list(statement["Action"])
        }
        required = {action for command in commands for action in CLI_ACTIONS[command]}
        self.assertEqual(required - actions, set())

    def test_observed_candidate_discovery_and_head_object_are_allowed(self):
        workflow = reaper_source()
        prefix_match = re.search(
            r'discover_candidate_versions candidate us-east-1 "\$east_bucket" \\\n'
            r'\s+"(candidates/\$candidate_id/)"',
            workflow,
        )
        self.assertIsNotNone(prefix_match)
        prefix = prefix_match.group(1).replace(
            "$candidate_id", "candidate-0.1.14-deadbeef-123-1"
        )
        bucket = "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-east-1"
        object_arn = f"{bucket}/{prefix}qualification/demo-site.zip"
        statements = recovery_statements()
        self.assertTrue(
            allows(statements, "s3:ListBucketVersions", bucket, prefix=prefix)
        )
        self.assertTrue(allows(statements, "s3:GetObject", object_arn))

        missing_prefix = copy.deepcopy(statements)
        listing = next(
            item for item in missing_prefix if item["Sid"] == "ListRecoveryPrefixes"
        )
        patterns = listing["Condition"]["StringLike"]["s3:prefix"]
        listing["Condition"]["StringLike"]["s3:prefix"] = [
            item for item in patterns if item != "candidates/candidate-*/*"
        ]
        self.assertFalse(
            allows(missing_prefix, "s3:ListBucketVersions", bucket, prefix=prefix)
        )

        missing_head_permission = copy.deepcopy(statements)
        for statement in missing_head_permission:
            statement["Action"] = [
                action
                for action in as_list(statement["Action"])
                if action != "s3:GetObject"
            ]
        self.assertFalse(allows(missing_head_permission, "s3:GetObject", object_arn))

    def test_recovery_s3_routes_are_complete_but_not_bucket_wide(self):
        statements = recovery_statements()
        bucket = "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-east-1"
        listed_prefixes = (
            "candidates/runs/123/1/state.json",
            "candidates/candidate-0.1.14-deadbeef-123-1/",
            "candidates/qualified/0.1.14/deadbeef/",
            "candidates/publications/123/1/state.json",
            "qualification/bfq-e-123-1/",
            "releases/0.1.14/",
            "latest/",
        )
        for prefix in listed_prefixes:
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    allows(statements, "s3:ListBucketVersions", bucket, prefix=prefix)
                )
        self.assertFalse(
            allows(
                statements,
                "s3:ListBucketVersions",
                bucket,
                prefix="customer-data/records/",
            )
        )
        self.assertFalse(
            allows(
                statements,
                "s3:GetObject",
                f"{bucket}/customer-data/records/context.json",
            )
        )

    def test_vapi_intent_recovery_permissions_are_exact_and_one_way(self):
        statements = recovery_statements()
        prefix = (
            "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-west-2/"
            "qualification/bfq-w-123-1/ownership/"
        )
        intent = prefix + "vapi-phone-intent.json"
        request = prefix + "vapi-phone-request.json"
        ownership = prefix + "vapi-phone.json"
        unrelated = prefix + "customer-phone.json"
        for action in ("s3:GetObject", "s3:GetObjectVersion"):
            self.assertTrue(allows(statements, action, intent))
            self.assertTrue(allows(statements, action, request))
            self.assertTrue(allows(statements, action, ownership))
            self.assertFalse(allows(statements, action, unrelated))
        self.assertFalse(allows(statements, "s3:PutObject", intent))
        self.assertFalse(allows(statements, "s3:PutObject", request))
        self.assertTrue(allows(statements, "s3:PutObject", ownership))
        self.assertFalse(allows(statements, "s3:PutObject", unrelated))

    def test_direct_vapi_recovery_permissions_are_journal_and_binding_scoped(self):
        statements = recovery_statements()
        prefix = (
            "arn:aws:s3:::bridgefu-vapi-awsconnect-225478700523-us-west-2/"
            "qualification/bfq-w-123-1/ownership/"
        )
        intent_names = (
            "vapi-direct-tool-intent.json",
            "vapi-direct-tool-request.json",
            "vapi-direct-assistant-intent.json",
            "vapi-direct-assistant-request.json",
        )
        ownership_names = (
            "vapi-direct-tool.json",
            "vapi-direct-assistant.json",
        )
        for name in intent_names + ownership_names:
            self.assertTrue(allows(statements, "s3:GetObject", prefix + name))
        for name in intent_names:
            self.assertFalse(allows(statements, "s3:PutObject", prefix + name))
        for name in ownership_names:
            self.assertTrue(allows(statements, "s3:PutObject", prefix + name))
        self.assertFalse(
            allows(statements, "s3:GetObject", prefix + "foreign-vapi.json")
        )
        direct_binding = (
            "arn:aws:secretsmanager:us-west-2:225478700523:secret:"
            "bridgefu/bfq-w-123-1/qualification/direct-vapi-identity-AbCdEf"
        )
        product_binding = (
            "arn:aws:secretsmanager:us-west-2:225478700523:secret:"
            "bridgefu-bfq-w-123-1-vapi-identity-AbCdEf"
        )
        foreign_binding = (
            "arn:aws:secretsmanager:us-west-2:225478700523:secret:"
            "customer/vapi-identity-AbCdEf"
        )
        self.assertTrue(
            allows(statements, "secretsmanager:GetSecretValue", direct_binding)
        )
        self.assertTrue(
            allows(statements, "secretsmanager:GetSecretValue", product_binding)
        )
        self.assertTrue(
            allows(statements, "secretsmanager:PutSecretValue", direct_binding)
        )
        self.assertFalse(
            allows(statements, "secretsmanager:PutSecretValue", product_binding)
        )
        self.assertFalse(
            allows(statements, "secretsmanager:GetSecretValue", foreign_binding)
        )

    def test_direct_vapi_recovery_is_reverse_ordered_bounded_and_fail_closed(self):
        source = QUALIFICATION_REAPER_PATH.read_text()
        prepare = source.split("prepare_exact_direct_vapi_recovery() {", 1)[1].split(
            "validate_vapi_phone_intent_journal_exact() {", 1
        )[0]
        loop = source.split("for pair in us-west-2:w us-east-1:e; do", 1)[1]
        for producer in (
            "bridgefu-vapi-direct-tool-intent@1",
            "bridgefu-vapi-direct-tool-ownership@1",
            "bridgefu-vapi-direct-assistant-intent@1",
            "bridgefu-vapi-direct-assistant-ownership@1",
        ):
            self.assertIn(producer, source)
        self.assertIn("https://api.vapi.ai/tool?limit=100", prepare)
        self.assertIn("https://api.vapi.ai/assistant?limit=100", prepare)
        self.assertIn(".server.credentialId == $credential", prepare)
        self.assertIn('.function.name == "bridgefu_direct_handoff"', prepare)
        self.assertIn(".metadata.bridgefu_owner == $owner", prepare)
        self.assertIn("($tool_ids | index($tool)) != null", prepare)
        self.assertGreaterEqual(prepare.count("length < 100"), 2)
        self.assertGreaterEqual(prepare.count('test "$direct_related_count" -le 1'), 2)
        self.assertIn(
            "Direct Vapi tool intent exists but absence cannot be proven safe.",
            prepare,
        )
        self.assertIn(
            "Direct Vapi assistant intent exists but absence cannot be proven safe.",
            prepare,
        )
        self.assertLess(
            loop.index("prepare_exact_direct_vapi_recovery"),
            loop.index("cleanup_exact_vapi_phone"),
        )
        self.assertLess(
            loop.index("cleanup_exact_vapi_phone"),
            loop.index("finish_exact_direct_vapi_recovery"),
        )
        finish = source.split("finish_exact_direct_vapi_recovery() {", 1)[1].split(
            "validate_vapi_phone_intent_journal_exact() {", 1
        )[0]
        self.assertLess(
            finish.index("put-secret-value"),
            finish.index("api.vapi.ai/assistant/$direct_recovery_assistant_id"),
        )
        self.assertLess(
            finish.index("api.vapi.ai/assistant/$direct_recovery_assistant_id"),
            finish.index("api.vapi.ai/tool/$direct_recovery_tool_id"),
        )
        self.assertNotIn('echo "$direct_vapi_key"', prepare + finish)
        self.assertIn("vapi-direct-assistant-post-delete-list.json", finish)
        self.assertIn("vapi-direct-tool-post-delete-list.json", finish)
        self.assertGreaterEqual(finish.count("length == 0"), 2)
        self.assertIn("bridgefu-vapi-direct-tool-request@1", source)
        self.assertIn("bridgefu-vapi-direct-assistant-request@1", source)
        self.assertLess(
            prepare.index('if [[ "$direct_tool_request_present" = false ]]'),
            prepare.index('load_vapi_curl_config "$direct_region"'),
        )
        self.assertLess(
            prepare.index('if [[ "$direct_assistant_request_present" = false ]]'),
            prepare.index("direct_product_binding="),
        )

    def test_vapi_key_is_loaded_through_mode_0600_curl_config_not_argv(self):
        source = QUALIFICATION_REAPER_PATH.read_text()
        match = re.search(
            r"^load_vapi_curl_config\(\) \{\n(.+?)^\}\n",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = f"load_vapi_curl_config() {{\n{match.group(1)}\n}}"
        cleanup_match = re.search(
            r"^cleanup_sensitive_files\(\) \{\n(.+?)^\}\n",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(cleanup_match)
        cleanup_function = f"cleanup_sensitive_files() {{\n{cleanup_match.group(1)}\n}}"
        secret = "_".join(("vapi", "private", "key", "TEST", "123"))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "curl.config"
            argv = Path(directory) / "curl.argv"
            script = f"""
set -euo pipefail
sensitive_files=()
VAPI_API_KEY_SECRET_ARN_US_WEST_2=arn:west
VAPI_API_KEY_SECRET_ARN_US_EAST_1=arn:east
aws() {{ printf '%s' '{secret}'; }}
curl() {{ printf '%s\n' "$@" >'{argv}'; }}
{function}
{cleanup_function}
trap cleanup_sensitive_files EXIT
load_vapi_curl_config us-west-2 '{config}'
mode="$(stat -c '%a' '{config}' 2>/dev/null || stat -f '%Lp' '{config}')"
test "$mode" = 600
grep -Fx 'header = "Authorization: Bearer {secret}"' '{config}' >/dev/null
curl --config '{config}' --silent https://api.vapi.ai/tool
if grep -F '{secret}' '{argv}' >/dev/null; then exit 10; fi
"""
            result = subprocess.run(  # noqa: S603
                ["bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse(config.exists())
        self.assertNotIn("Authorization: Bearer $", source)
        self.assertIn("trap cleanup_sensitive_files EXIT", source)

    def test_direct_vapi_journal_validators_reject_hash_and_owner_tampering(self):
        source = QUALIFICATION_REAPER_PATH.read_text()

        def shell_function(name: str) -> str:
            match = re.search(
                rf"^{name}\(\) \{{\n(.+?)^\}}\n",
                source,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match)
            return f"{name}() {{\n{match.group(1)}\n}}"

        execution_id = "bfq-w-123-1"
        region = "us-west-2"
        tool_id = "tool-owned-123"
        assistant_id = "assistant-owned-123"
        credential_id = "credential-owned-123"
        endpoint = (
            "https://abc123.execute-api.us-west-2.amazonaws.com/v1/direct-handoff"
        )
        tool_desired = {
            "type": "function",
            "function": {
                "name": "bridgefu_direct_handoff",
                "description": "exact qualification tool",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            "server": {
                "url": endpoint,
                "credentialId": credential_id,
                "timeoutSeconds": 10,
            },
            "parameters": [
                {
                    "key": "handoff_token",
                    "value": "{{ bridgefu_handoff_token }}",
                }
            ],
        }
        tool_desired_hash = hashlib.sha256(
            json.dumps(tool_desired, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        tool_core = {
            "execution_id": execution_id,
            "region": region,
            "resource_type": "tool",
            "endpoint_url": endpoint,
            "credential_id": credential_id,
            "desired_sha256": tool_desired_hash,
        }
        tool_intent_hash = hashlib.sha256(
            json.dumps(tool_core, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        tool_intent = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-direct-tool-intent@1",
            **tool_core,
            "desired": tool_desired,
            "intent_sha256": tool_intent_hash,
            "created_at": "2026-08-13T12:00:00Z",
            "redacted": True,
        }
        tool_ownership_core = {
            **tool_core,
            "tool_id": tool_id,
            "intent_sha256": tool_intent_hash,
        }
        tool_ownership = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-direct-tool-ownership@1",
            **tool_ownership_core,
            "ownership_sha256": hashlib.sha256(
                json.dumps(
                    tool_ownership_core, separators=(",", ":"), sort_keys=True
                ).encode()
            ).hexdigest(),
            "created_at": "2026-08-13T12:00:01Z",
            "redacted": True,
        }
        prompt = "[bridgefu-direct-browser-handoff@1] exact prompt"
        assistant_desired = {
            "name": f"BFQ direct {execution_id}",
            "model": {
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "temperature": 0,
                "messages": [{"role": "system", "content": prompt}],
                "toolIds": [tool_id],
            },
            "voice": {"provider": "vapi", "voiceId": "Elliot"},
            "metadata": {
                "bridgefu_qualification": execution_id,
                "bridgefu_owner": "bridgefu-direct-web-qualification@1",
            },
        }
        assistant_desired_hash = hashlib.sha256(
            json.dumps(
                assistant_desired, separators=(",", ":"), sort_keys=True
            ).encode()
        ).hexdigest()
        assistant_core = {
            "execution_id": execution_id,
            "region": region,
            "resource_type": "assistant",
            "owned_name": f"BFQ direct {execution_id}",
            "owner_marker": "bridgefu-direct-web-qualification@1",
            "tool_id": tool_id,
            "organization_id": "organization-owned-123",
            "model_name": "gpt-4.1-mini",
            "voice_id": "Elliot",
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "desired_sha256": assistant_desired_hash,
        }
        assistant_intent_hash = hashlib.sha256(
            json.dumps(assistant_core, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        assistant_intent = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-direct-assistant-intent@1",
            **assistant_core,
            "desired": assistant_desired,
            "intent_sha256": assistant_intent_hash,
            "created_at": "2026-08-13T12:00:02Z",
            "redacted": True,
        }
        assistant_ownership_core = {
            **assistant_core,
            "assistant_id": assistant_id,
            "intent_sha256": assistant_intent_hash,
        }
        assistant_ownership = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-direct-assistant-ownership@1",
            **assistant_ownership_core,
            "ownership_sha256": hashlib.sha256(
                json.dumps(
                    assistant_ownership_core,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            "created_at": "2026-08-13T12:00:03Z",
            "redacted": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = {
                "tool_intent": Path(directory) / "tool-intent.json",
                "tool_ownership": Path(directory) / "tool.json",
                "assistant_intent": Path(directory) / "assistant-intent.json",
                "assistant_ownership": Path(directory) / "assistant.json",
                "tampered": Path(directory) / "tampered.json",
            }
            paths["tool_intent"].write_text(json.dumps(tool_intent))
            paths["tool_ownership"].write_text(json.dumps(tool_ownership))
            paths["assistant_intent"].write_text(json.dumps(assistant_intent))
            paths["assistant_ownership"].write_text(json.dumps(assistant_ownership))
            tampered = copy.deepcopy(assistant_intent)
            tampered["desired"]["metadata"]["bridgefu_owner"] = "foreign-owner"
            paths["tampered"].write_text(json.dumps(tampered))
            functions = "\n".join(
                shell_function(name)
                for name in (
                    "validate_vapi_direct_tool_intent_exact",
                    "validate_vapi_direct_tool_ownership_exact",
                    "validate_vapi_direct_assistant_intent_exact",
                    "validate_vapi_direct_assistant_ownership_exact",
                )
            )
            script = f"""
set -euo pipefail
{functions}
validate_vapi_direct_tool_intent_exact {paths["tool_intent"]} \
  {execution_id} {region}
validate_vapi_direct_tool_ownership_exact {paths["tool_ownership"]} \
  {paths["tool_intent"]}
validate_vapi_direct_assistant_intent_exact {paths["assistant_intent"]} \
  {execution_id} {region}
validate_vapi_direct_assistant_ownership_exact \
  {paths["assistant_ownership"]} {paths["assistant_intent"]}
"""
            result = subprocess.run(  # noqa: S603
                ["bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
            tamper_result = subprocess.run(  # noqa: S603
                [
                    "bash",
                    "-c",
                    f"""
set -euo pipefail
{shell_function("validate_vapi_direct_assistant_intent_exact")}
validate_vapi_direct_assistant_intent_exact {paths["tampered"]} \
  {execution_id} {region}
""",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotEqual(tamper_result.returncode, 0)

    def test_direct_assistant_remote_validator_allows_omitted_org_only(self):
        source = QUALIFICATION_REAPER_PATH.read_text()
        match = re.search(
            r"^validate_remote_vapi_direct_assistant_exact\(\) \{\n(.+?)^\}\n",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = (
            f"validate_remote_vapi_direct_assistant_exact() {{\n{match.group(1)}\n}}"
        )
        desired = {
            "name": "BFQ direct bfq-w-123-1",
            "firstMessageMode": "assistant-waits-for-user",
            "model": {
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "temperature": 0,
                "messages": [
                    {
                        "role": "system",
                        "content": "[bridgefu-direct-browser-handoff@1] prompt",
                    }
                ],
                "toolIds": ["tool-owned-123"],
            },
            "voice": {"provider": "vapi", "voiceId": "Elliot"},
            "transcriber": {
                "provider": "deepgram",
                "model": "nova-3",
                "language": "en",
            },
            "artifactPlan": {"recordingEnabled": False},
            "maxDurationSeconds": 300,
            "metadata": {
                "bridgefu_qualification": "bfq-w-123-1",
                "bridgefu_owner": "bridgefu-direct-web-qualification@1",
            },
        }
        intent = {"organization_id": "organization-owned-123", "desired": desired}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent_path = root / "intent.json"
            remote_path = root / "remote.json"
            intent_path.write_text(json.dumps(intent))
            script = f"""
set -euo pipefail
{function}
validate_remote_vapi_direct_assistant_exact {remote_path} \
  assistant-owned-123 {intent_path}
"""
            for org_id, expected in (
                (None, True),
                ("", True),
                ("organization-owned-123", True),
                ("organization-foreign-123", False),
            ):
                remote = {"id": "assistant-owned-123", **desired}
                if org_id is not None:
                    remote["orgId"] = org_id
                remote_path.write_text(json.dumps(remote))
                result = subprocess.run(  # noqa: S603
                    ["bash", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                with self.subTest(org_id=org_id):
                    self.assertEqual(result.returncode == 0, expected)
            valid_defaults = {
                "id": "assistant-owned-123",
                "orgId": None,
                "createdAt": "2026-08-13T12:00:00Z",
                "updatedAt": None,
                "server": None,
                "serverMessages": [],
                "credentialIds": [],
                **desired,
            }
            valid_defaults["voice"]["fallbackPlan"] = {}
            valid_defaults["transcriber"]["smartFormat"] = True
            valid_defaults["artifactPlan"]["loggingEnabled"] = False
            adversarial = [(valid_defaults, True)]
            normalized_defaults = copy.deepcopy(valid_defaults)
            normalized_defaults["serverUrl"] = None
            normalized_defaults["hooks"] = []
            normalized_defaults["model"]["tools"] = []
            normalized_defaults["model"]["knowledgeBase"] = None
            normalized_defaults["model"]["knowledgeBaseId"] = None
            adversarial.append((normalized_defaults, True))
            second_tool = copy.deepcopy(valid_defaults)
            second_tool["model"]["toolIds"].append("foreign-tool")
            adversarial.append((second_tool, False))
            second_prompt = copy.deepcopy(valid_defaults)
            second_prompt["model"]["messages"].append(
                {"role": "system", "content": "foreign prompt"}
            )
            adversarial.append((second_prompt, False))
            inline_tool = copy.deepcopy(valid_defaults)
            inline_tool["model"]["tools"] = [{"type": "function"}]
            adversarial.append((inline_tool, False))
            external_server = copy.deepcopy(valid_defaults)
            external_server["server"] = {"url": "https://foreign.example"}
            adversarial.append((external_server, False))
            unknown_surface = copy.deepcopy(valid_defaults)
            unknown_surface["foreign"] = True
            adversarial.append((unknown_surface, False))
            changed_duration = copy.deepcopy(valid_defaults)
            changed_duration["maxDurationSeconds"] = 600
            adversarial.append((changed_duration, False))
            unsafe_voice_default = copy.deepcopy(valid_defaults)
            unsafe_voice_default["voice"]["fallbackPlan"] = {
                "voices": [{"provider": "foreign"}]
            }
            adversarial.append((unsafe_voice_default, False))
            unsafe_transcriber_default = copy.deepcopy(valid_defaults)
            unsafe_transcriber_default["transcriber"]["smartFormat"] = False
            adversarial.append((unsafe_transcriber_default, False))
            unsafe_artifact_default = copy.deepcopy(valid_defaults)
            unsafe_artifact_default["artifactPlan"]["loggingEnabled"] = True
            adversarial.append((unsafe_artifact_default, False))
            wrong_empty_server = copy.deepcopy(valid_defaults)
            wrong_empty_server["server"] = {}
            adversarial.append((wrong_empty_server, False))
            wrong_empty_hooks = copy.deepcopy(valid_defaults)
            wrong_empty_hooks["hooks"] = ""
            adversarial.append((wrong_empty_hooks, False))
            wrong_empty_tools = copy.deepcopy(valid_defaults)
            wrong_empty_tools["model"]["tools"] = {}
            adversarial.append((wrong_empty_tools, False))
            for index, (remote, expected) in enumerate(adversarial):
                remote_path.write_text(json.dumps(remote))
                result = subprocess.run(  # noqa: S603
                    ["bash", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                with self.subTest(adversarial=index):
                    self.assertEqual(result.returncode == 0, expected)

    def test_direct_tool_remote_validator_rejects_every_foreign_surface(self):
        source = QUALIFICATION_REAPER_PATH.read_text()
        match = re.search(
            r"^validate_remote_vapi_direct_tool_exact\(\) \{\n(.+?)^\}\n",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = f"validate_remote_vapi_direct_tool_exact() {{\n{match.group(1)}\n}}"
        desired = {
            "type": "function",
            "function": {
                "name": "bridgefu_direct_handoff",
                "description": "exact",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            "server": {
                "url": "https://abc.execute-api.us-west-2.amazonaws.com/v1/direct-handoff",
                "credentialId": "credential-owned-123",
                "timeoutSeconds": 10,
            },
            "parameters": [
                {
                    "key": "handoff_token",
                    "value": "{{ bridgefu_handoff_token }}",
                }
            ],
        }
        intent = {"desired": desired}
        valid = {
            "id": "tool-owned-123",
            "orgId": "organization-owned-123",
            "createdAt": "2026-08-13T12:00:00Z",
            "latestVersion": "version-owned-123",
            **desired,
        }
        changed_endpoint = copy.deepcopy(valid)
        changed_endpoint["server"]["url"] = "https://foreign.example"
        changed_function = copy.deepcopy(valid)
        changed_function["function"]["name"] = "foreign"
        unknown = copy.deepcopy(valid)
        unknown["foreign"] = True
        malformed_latest_version = copy.deepcopy(valid)
        malformed_latest_version["latestVersion"] = {"foreign": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent_path = root / "intent.json"
            remote_path = root / "remote.json"
            intent_path.write_text(json.dumps(intent))
            script = f"""
set -euo pipefail
{function}
validate_remote_vapi_direct_tool_exact {remote_path} tool-owned-123 {intent_path}
"""
            for index, (remote, expected) in enumerate(
                (
                    (valid, True),
                    (changed_endpoint, False),
                    (changed_function, False),
                    (unknown, False),
                    (malformed_latest_version, False),
                )
            ):
                remote_path.write_text(json.dumps(remote))
                result = subprocess.run(  # noqa: S603
                    ["bash", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                with self.subTest(case=index):
                    self.assertEqual(result.returncode == 0, expected)

    def test_direct_vapi_reaper_accepts_controller_emitted_journals(self):
        module_path = ROOT / "qualification" / "controller.py"
        spec = importlib.util.spec_from_file_location(
            "qualification_controller_recovery_contract", module_path
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        controller = importlib.util.module_from_spec(spec)
        qualification_path = str(ROOT / "qualification")
        sys.path.insert(0, qualification_path)
        try:
            spec.loader.exec_module(controller)
        finally:
            sys.path.remove(qualification_path)
        handoff = controller.bridgefu_web_handoff
        execution_id = "bfq-w-123-1"
        region = "us-west-2"
        endpoint = (
            "https://abc123.execute-api.us-west-2.amazonaws.com/v1/direct-handoff"
        )
        credential_id = "credential-owned-123"
        tool_id = "tool-owned-123"
        assistant_id = "assistant-owned-123"
        desired_tool = handoff.direct_tool_payload(
            endpoint_url=endpoint,
            credential_id=credential_id,
            field_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            execution_id=execution_id,
        )
        tool_intent = controller.direct_tool_intent_journal(
            execution_id,
            region,
            endpoint,
            credential_id,
            desired_tool,
            created_at="2026-08-13T12:00:00Z",
        )
        tool_ownership = controller.direct_tool_ownership_journal(
            tool_intent, tool_id, created_at="2026-08-13T12:00:01Z"
        )
        tool_request = controller.direct_vapi_request_journal(
            tool_intent,
            "0" * 32,
            authorized_at="2026-08-13T12:00:00.500Z",
        )
        desired_assistant, prompt_hash = handoff.direct_assistant_payload(
            execution_id=execution_id,
            tool_id=tool_id,
            model_name="gpt-4.1-mini",
            voice_id="Elliot",
        )
        assistant_intent = controller.direct_assistant_intent_journal(
            execution_id,
            region,
            "organization-owned-123",
            tool_id,
            "gpt-4.1-mini",
            "Elliot",
            prompt_hash,
            desired_assistant,
            created_at="2026-08-13T12:00:02Z",
        )
        assistant_ownership = controller.direct_assistant_ownership_journal(
            assistant_intent,
            assistant_id,
            created_at="2026-08-13T12:00:03Z",
        )
        assistant_request = controller.direct_vapi_request_journal(
            assistant_intent,
            "1" * 32,
            authorized_at="2026-08-13T12:00:02.500Z",
        )
        phone_intent = controller.vapi_phone_intent_journal(
            execution_id,
            region,
            controller.vapi_phone_intent(
                execution_id,
                assistant_id,
                {
                    "realm": "sip.vapi.ai",
                    "username": "bfq_0123456789abcdef",
                    "password": "_".join(("temporary", "test", "secret")),
                },
            ),
            created_at="2026-08-13T12:00:04Z",
        )
        phone_request = controller.vapi_phone_request_journal(
            phone_intent,
            "2" * 32,
            authorized_at="2026-08-13T12:00:04.500Z",
        )
        source = QUALIFICATION_REAPER_PATH.read_text()

        def shell_function(name: str) -> str:
            match = re.search(
                rf"^{name}\(\) \{{\n(.+?)^\}}\n",
                source,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match)
            return f"{name}() {{\n{match.group(1)}\n}}"

        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (
                ("tool-intent", tool_intent),
                ("tool-request", tool_request),
                ("tool", tool_ownership),
                ("assistant-intent", assistant_intent),
                ("assistant-request", assistant_request),
                ("assistant", assistant_ownership),
                ("phone-intent", phone_intent),
                ("phone-request", phone_request),
            ):
                path = Path(directory) / f"{name}.json"
                path.write_text(
                    json.dumps(value, separators=(",", ":"), sort_keys=True)
                )
                paths[name] = path
            functions = "\n".join(
                shell_function(name)
                for name in (
                    "validate_vapi_direct_tool_intent_exact",
                    "validate_vapi_direct_request_exact",
                    "validate_vapi_direct_tool_ownership_exact",
                    "validate_vapi_direct_assistant_intent_exact",
                    "validate_vapi_direct_assistant_ownership_exact",
                    "validate_vapi_phone_intent_journal_exact",
                    "validate_vapi_phone_request_journal_exact",
                )
            )
            script = f"""
set -euo pipefail
{functions}
validate_vapi_direct_tool_intent_exact {paths["tool-intent"]} \
  {execution_id} {region}
validate_vapi_direct_request_exact {paths["tool-request"]} \
  {paths["tool-intent"]} tool
validate_vapi_direct_tool_ownership_exact {paths["tool"]} \
  {paths["tool-intent"]}
validate_vapi_direct_assistant_intent_exact {paths["assistant-intent"]} \
  {execution_id} {region}
validate_vapi_direct_request_exact {paths["assistant-request"]} \
  {paths["assistant-intent"]} assistant
validate_vapi_direct_assistant_ownership_exact {paths["assistant"]} \
  {paths["assistant-intent"]}
validate_vapi_phone_intent_journal_exact {paths["phone-intent"]} \
  {execution_id} {region}
validate_vapi_phone_request_journal_exact {paths["phone-request"]} \
  {paths["phone-intent"]}
"""
            result = subprocess.run(  # noqa: S603
                ["bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_vapi_intent_recovery_is_bounded_exact_and_sealed_before_delete(self):
        workflow = reaper_source()
        recovery = workflow.split(
            "          validate_vapi_phone_intent_journal_exact() {", 1
        )[1].split("          load_exact_acm_validation_journal() {", 1)[0]
        self.assertIn("bridgefu-vapi-phone-intent@1", recovery)
        self.assertIn("bridgefu-vapi-phone-request@1", recovery)
        self.assertIn(
            'intent_key="qualification/$execution_id/ownership/vapi-phone-intent.json"',
            recovery,
        )
        self.assertIn(
            'request_key="qualification/$execution_id/ownership/vapi-phone-request.json"',
            recovery,
        )
        self.assertIn("load_latest_s3_object_exact", recovery)
        self.assertIn('test "$strict_status" = 0', recovery)
        self.assertIn("describe_stack_exact", recovery)
        self.assertIn("VapiAssistantId", recovery)
        self.assertIn("https://api.vapi.ai/phone-number?limit=100", recovery)
        self.assertIn("for attempt in $(seq 1 30); do", recovery)
        self.assertIn('type == "array" and length < 100', recovery)
        self.assertIn('test "$related_count" -le 1', recovery)
        self.assertIn(
            "Vapi phone request exists but absence cannot be proven safe.", recovery
        )
        for field in (
            '.provider == "vapi"',
            ".assistantId == $assistant_id",
            ".name == $name",
            ".sipUri == $sip_uri",
            ".authentication.realm == $authentication_realm",
            ".authentication.username == $authentication_username",
        ):
            self.assertIn(field, recovery)
        self.assertIn("bridgefu-vapi-phone-ownership@1", recovery)
        self.assertIn("--server-side-encryption AES256", recovery)
        self.assertLess(
            recovery.index("aws s3api put-object"), recovery.index("--request DELETE")
        )
        self.assertNotIn("password", recovery.lower())
        self.assertNotIn('echo "$vapi_key"', recovery)

    def test_vapi_intent_and_remote_identity_guards_reject_tampering(self):
        workflow = reaper_source()

        def shell_function(name: str) -> str:
            match = re.search(
                rf"^          {name}\(\) \{{\n(.+?)^          \}}\n",
                workflow,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match)
            return (
                f"{name}() {{\n"
                + "\n".join(
                    line.removeprefix("            ")
                    for line in match.group(1).splitlines()
                )
                + "\n}"
            )

        execution_id = "bfq-w-123-1"
        assistant_id = "11111111-1111-4111-8111-111111111111"
        username = "bfq_0123456789abcdef"
        owned = {
            "execution_id": execution_id,
            "region": "us-west-2",
            "resource_type": "phone-number",
            "owned_name": f"BFQ {execution_id} SIP smoke",
            "assistant_id": assistant_id,
            "sip_uri": f"sip:{username}@sip.vapi.ai",
            "authentication_realm": "sip.vapi.ai",
            "authentication_username": username,
        }
        canonical = json.dumps(owned, separators=(",", ":"), sort_keys=True)
        intent = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-phone-intent@1",
            **owned,
            "intent_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "created_at": "2026-08-11T12:00:00.000Z",
            "redacted": True,
        }
        phone_id = "22222222-2222-4222-8222-222222222222"
        remote = {
            "id": phone_id,
            "provider": "vapi",
            "name": owned["owned_name"],
            "assistantId": assistant_id,
            "sipUri": owned["sip_uri"],
            "authentication": {
                "realm": owned["authentication_realm"],
                "username": username,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            intent_path = Path(directory) / "intent.json"
            tampered_path = Path(directory) / "tampered.json"
            remote_path = Path(directory) / "remote.json"
            foreign_path = Path(directory) / "foreign.json"
            intent_path.write_text(json.dumps(intent))
            tampered = dict(intent)
            tampered["assistant_id"] = "foreign-assistant"
            tampered_path.write_text(json.dumps(tampered))
            remote_path.write_text(json.dumps(remote))
            foreign = copy.deepcopy(remote)
            foreign["authentication"]["username"] = "bfq_fedcba9876543210"
            foreign_path.write_text(json.dumps(foreign))
            script = f"""
set -euo pipefail
{shell_function("validate_vapi_phone_intent_journal_exact")}
{shell_function("validate_remote_vapi_phone_exact")}
validate_vapi_phone_intent_journal_exact \
  {intent_path!s} {execution_id} us-west-2
if (set -e; validate_vapi_phone_intent_journal_exact \
  {tampered_path!s} {execution_id} us-west-2); then
  exit 10
fi
validate_remote_vapi_phone_exact {remote_path!s} {phone_id} {assistant_id} \
  'BFQ {execution_id} SIP smoke' true 'sip:{username}@sip.vapi.ai' \
  sip.vapi.ai {username}
if (set -e; validate_remote_vapi_phone_exact {foreign_path!s} {phone_id} \
  {assistant_id} 'BFQ {execution_id} SIP smoke' true \
  'sip:{username}@sip.vapi.ai' sip.vapi.ai {username}); then
  exit 11
fi
"""
            result = subprocess.run(  # noqa: S603
                ["bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_acm_dns_cleanup_is_bound_to_one_hosted_zone(self):
        statements = recovery_statements()
        exact_zone = "arn:aws:route53:::hostedzone/Z0123456789EXACT"
        other_zone = "arn:aws:route53:::hostedzone/Z9999999999OTHER"
        for action in (
            "route53:GetHostedZone",
            "route53:ListResourceRecordSets",
            "route53:ChangeResourceRecordSets",
        ):
            self.assertTrue(allows(statements, action, exact_zone))
            self.assertFalse(allows(statements, action, other_zone))
        self.assertTrue(
            allows(
                statements,
                "route53:GetChange",
                "arn:aws:route53:::change/C0123456789",
            )
        )

    def test_workflow_hard_cancel_discovery_is_bounded_and_exact_match_only(self):
        workflow = reaper_source()
        discovery = workflow.split(
            "          discover_and_journal_exact_stack_acm_records() {", 1
        )[1].split("          cleanup_exact_acm_validation_records() {", 1)[0]
        cleanup = workflow.split(
            "          cleanup_exact_acm_validation_records() {", 1
        )[1].split("          for pair in us-west-2:w us-east-1:e; do", 1)[0]
        self.assertIn(
            "for depth in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16",
            discovery,
        )
        self.assertNotIn("for depth in 1 2 3 4 5 6 7 8; do", discovery)
        self.assertIn('test "$(jq \'length\' <<<"$visited_stacks")" -le 16', discovery)
        self.assertIn(
            'certificate_count="$(jq \'length\' <<<"$discovered_certificates")"',
            discovery,
        )
        self.assertIn('test "$certificate_count" -le 1', discovery)
        self.assertIn('if [[ "$certificate_count" = 0 ]]; then', discovery)
        self.assertIn("return 3", discovery)
        self.assertEqual(discovery.count('[[ -z "$physical_id" ]] && continue'), 2)
        self.assertIn(
            "^arn:aws:cloudformation:$region:$account_id:stack/bridgefu-bfq-",
            discovery,
        )
        for key, value in (
            ("Project", "bridgefu-vapi-awsconnect"),
            ("ManagedBy", "bridgefu-cloudformation"),
            ("BridgefuExecutionId", '"$execution_id"'),
            ("BridgefuRecipe", "vapi-amazon-connect-screen-pop@1"),
        ):
            self.assertIn(f"exact_tag {key} {value}", discovery)
        self.assertIn("endswith($suffix) and contains($execution_id)", discovery)
        self.assertIn('test "$current" = "$(jq -cS . <<<"$owned")"', cleanup)
        self.assertNotRegex(
            cleanup, r"list-resource-record-sets[^\n]*--max-items (?!1)"
        )
        self.assertNotIn("list-hosted-zones", workflow)
        self.assertNotIn("list-certificates", workflow)
        self.assertNotIn('if ! journal_head="$(aws s3api head-object', workflow)
        self.assertIn("load_latest_s3_object_exact()", workflow)
        self.assertIn("describe_stack_exact()", workflow)
        self.assertIn("Stack with id .+ does not exist", workflow)
        self.assertIn("(aws: \\[ERROR\\]: )?An error occurred", workflow)
        caller = workflow.split("          for pair in us-west-2:w us-east-1:e; do", 1)[
            1
        ].split("\n\n  delete-failed-private-candidate:", 1)[0]
        self.assertNotIn(
            'if aws cloudformation describe-stacks --region "$region"', caller
        )
        self.assertIn("for attempt in $(seq 1 180); do", caller)
        self.assertNotIn("if load_exact_acm_validation_journal", caller)
        self.assertNotIn("if discover_and_journal_exact_stack_acm_records", caller)
        self.assertIn("run_strict load_exact_acm_validation_journal", caller)
        self.assertIn("run_strict discover_and_journal_exact_stack_acm_records", caller)
        self.assertIn("3|4) ;;", caller)
        self.assertIn("CREATE_IN_PROGRESS|REVIEW_IN_PROGRESS)", caller)
        self.assertIn(
            "CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|DELETE_FAILED)\n"
            '                      test "$strict_status" = 3',
            caller,
        )
        self.assertLess(
            caller.index("3|4) ;;"),
            caller.index("aws cloudformation delete-stack"),
        )

    def test_stack_absence_accepts_current_aws_cli_error_prefix(self):
        source = QUALIFICATION_REAPER_PATH.read_text()
        function = source.split("describe_stack_exact() {", 1)[1].split(
            "delete_prefix_versions() {", 1
        )[0]
        program = f"""set -euo pipefail
strict_status=0
run_strict() {{
  set +e
  (
    set -e
    "$@"
  )
  strict_status="$?"
  set -e
  return 0
}}
describe_stack_exact() {{{function}
aws() {{
  printf '%s\\n' 'aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id bridgefu-bfq-w-test-1 does not exist' >&2
  return 254
}}
run_strict describe_stack_exact us-west-2 bridgefu-bfq-w-test-1 stack.json
test "$strict_status" = 3
"""
        completed = subprocess.run(
            ["bash"], input=program, text=True, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_incomplete_acm_metadata_is_retryable_but_conflicts_are_not(self):
        workflow = reaper_source()
        discovery = workflow.split(
            "          discover_and_journal_exact_stack_acm_records() {", 1
        )[1].split("          cleanup_exact_acm_validation_records() {", 1)[0]

        def extract_function(name: str) -> str:
            match = re.search(
                rf"^            {name}\(\) \{{\n(.+?)^            \}}\n",
                discovery,
                re.MULTILINE | re.DOTALL,
            )
            if match is None:
                self.fail(f"missing {name} helper")
            return (
                name
                + "() {\n"
                + "\n".join(
                    line.removeprefix("              ")
                    for line in match.group(1).splitlines()
                )
                + "\n}"
            )

        exact_tag = extract_function("exact_tag")
        complete_options = extract_function("complete_domain_validation_options")
        script = f"""
set -uo pipefail
{exact_tag}
{complete_options}
capture() {{
  set +e
  (
    set -e
    "$@"
  )
  captured="$?"
  set -e
}}
certificate_tags='{{"Tags":[]}}'
capture exact_tag Project bridgefu-vapi-awsconnect
test "$captured" = 4
certificate_tags='{{"Tags":[{{"Key":"Project","Value":"foreign"}}]}}'
capture exact_tag Project bridgefu-vapi-awsconnect
test "$captured" != 0
test "$captured" != 4
certificate_tags='{{"Tags":[{{"Key":"Project","Value":"bridgefu-vapi-awsconnect"}}]}}'
capture exact_tag Project bridgefu-vapi-awsconnect
test "$captured" = 0
certificate='{{"Certificate":{{"DomainValidationOptions":[]}}}}'
capture complete_domain_validation_options
test "$captured" = 4
certificate='{{"Certificate":{{"DomainValidationOptions":[
  {{"ResourceRecord":{{"Name":"_a.example.com.","Type":"CNAME","Value":"_one"}}}},
  {{}}
]}}}}'
capture complete_domain_validation_options
test "$captured" = 4
certificate='{{"Certificate":{{"DomainValidationOptions":[
  {{"ResourceRecord":{{"Name":"_a.example.com.","Type":"CNAME","Value":"_one"}}}},
  {{"ResourceRecord":{{"Name":"_b.example.com.","Type":"CNAME","Value":"_two"}}}}
]}}}}'
capture complete_domain_validation_options
test "$captured" = 0
certificate='{{"Certificate":{{"DomainValidationOptions":[{{}},{{}},{{}}]}}}}'
capture complete_domain_validation_options
test "$captured" != 0
test "$captured" != 4
"""
        result = subprocess.run(  # noqa: S603
            ["bash", "-c", script], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_strict_runner_stops_failed_ownership_guard_before_mutation(self):
        workflow = reaper_source()
        match = re.search(
            r"^          run_strict\(\) \{\n(.+?)^          \}\n",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        helper = (
            "run_strict() {\n"
            + "\n".join(
                line.removeprefix("            ")
                for line in match.group(1).splitlines()
            )
            + "\n}"
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "mutation-reached"
            script = f"""
set -euo pipefail
strict_status=0
{helper}
ownership_operation() {{
  test expected = changed
  printf reached > {marker!s}
}}
run_strict ownership_operation
test "$strict_status" -ne 0
test ! -e {marker!s}
"""
            result = subprocess.run(  # noqa: S603
                ["bash", "-c", script], text=True, capture_output=True, check=False
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hard_cancel_acm_filter_returns_canonical_record_sets_not_boolean(self):
        workflow = reaper_source()
        discovery = workflow.split(
            "          discover_and_journal_exact_stack_acm_records() {", 1
        )[1].split("          cleanup_exact_acm_validation_records() {", 1)[0]
        match = re.search(
            r"record_sets=\"\$\(jq -cer '(.+?)' <<<\"\$certificate\"\)\"",
            discovery,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        certificate = {
            "Certificate": {
                "DomainValidationOptions": [
                    {
                        "ResourceRecord": {
                            "Name": "_b.bfq-test.example.com.",
                            "Type": "CNAME",
                            "Value": "_proof-b.acm-validations.aws.",
                        }
                    },
                    {
                        "ResourceRecord": {
                            "Name": "_a.bfq-test.example.com.",
                            "Type": "CNAME",
                            "Value": "_proof-a.acm-validations.aws.",
                        }
                    },
                ]
            }
        }
        result = subprocess.run(  # noqa: S603
            ["jq", "-cer", match.group(1)],
            input=json.dumps(certificate),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertIsInstance(parsed, list)
        self.assertEqual(
            [item["name"] for item in parsed],
            [
                "_a.bfq-test.example.com.",
                "_b.bfq-test.example.com.",
            ],
        )
        self.assertTrue(all(item["type"] == "CNAME" for item in parsed))

        route53_match = re.search(
            r"current=\"\$\(jq -c --arg name \"\$name\" \\\n"
            r"\s+'(.+?)' \\\n\s+<<<\"\$listing\"\)\"",
            discovery,
            re.DOTALL,
        )
        self.assertIsNotNone(route53_match)
        absent = subprocess.run(  # noqa: S603
            [
                "jq",
                "-c",
                "--arg",
                "name",
                "_a.bfq-test.example.com.",
                route53_match.group(1),
            ],
            input=json.dumps({"ResourceRecordSets": []}),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertEqual(absent.stdout, "")
        self.assertIn('if [[ -z "$current" ]]; then', discovery)
        self.assertIn("continue", discovery)
        self.assertIn("'{name, type, resource_records}'", discovery)

    def test_demo_site_is_built_once_before_aws_mutation_and_hash_bound(self):
        candidate = CANDIDATE_PATH.read_text()
        remote = REMOTE_QUALIFICATION_PATH.read_text()
        build_marker = "Build the immutable qualification demo site before AWS mutation"
        journal_marker = "Journal ownership and prove the version is unused"
        credential_marker = "aws-actions/configure-aws-credentials@v4"
        self.assertLess(candidate.index(build_marker), candidate.index(journal_marker))
        self.assertLess(
            candidate.index(build_marker), candidate.index(credential_marker)
        )
        self.assertEqual(candidate.count("python qualification/build_demo_site.py"), 1)
        self.assertIn(
            "upload_candidate_object \\\n"
            "            target/candidate/qualification-demo-site/demo-site.zip \\\n"
            "            qualification/demo-site.zip",
            candidate,
        )
        for workflow in (candidate, remote):
            with self.subTest(
                workflow="candidate" if workflow is candidate else "remote"
            ):
                self.assertIn("--version-id", workflow)
                self.assertIn("demo-site-manifest.json", workflow)
                self.assertIn("--demo-site-archive", workflow)
                self.assertIn("--demo-site-sha256", workflow)
                self.assertIn(
                    "sha256sum target/qualification-inputs/demo-site.zip", workflow
                )

    def test_qualification_reaper_stays_below_github_run_expression_limit(self):
        workflow = WORKFLOW_PATH.read_text()
        script = QUALIFICATION_REAPER_PATH.read_text()
        run_blocks = re.findall(
            r"(?m)^(\s*)run: \|\n((?:(?:\1  .*|\s*)\n?)*)", workflow
        )
        self.assertTrue(run_blocks)
        self.assertTrue(all(len(body.encode()) < 21_000 for _, body in run_blocks))
        self.assertIn("- uses: actions/checkout@v4", workflow)
        self.assertIn("ref: ${{ github.event.workflow_run.head_sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("run: bash release/reap_qualification.sh", workflow)
        self.assertTrue(script.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"))
        self.assertNotIn("${{", script)

    def test_all_reaper_bulk_deletes_require_exact_nonquiet_receipts(self):
        source = reaper_source()
        self.assertNotIn("Quiet: true", source)
        self.assertEqual(source.count("Quiet: false"), 3)
        self.assertEqual(source.count('--argjson requested "$deletes"'), 3)
        self.assertEqual(source.count(".Deleted // []"), 6)
        self.assertEqual(
            source.count("$requested.Objects | sort_by(.Key, .VersionId)"), 3
        )

        requested = {
            "Objects": [
                {"Key": "qualification/bfq-test/a", "VersionId": "version-a"},
                {"Key": "qualification/bfq-test/b", "VersionId": "version-b"},
            ],
            "Quiet": False,
        }
        receipt_filter = """
          ((.Errors // []) | length == 0) and
          ((.Deleted // []) | length == ($requested.Objects | length)) and
          (((.Deleted // []) | map({Key, VersionId}) |
              sort_by(.Key, .VersionId)) ==
           ($requested.Objects | sort_by(.Key, .VersionId)))
        """
        for deleted, expected in (
            (list(requested["Objects"]), True),
            ([requested["Objects"][0]], False),
            (
                [
                    requested["Objects"][0],
                    {"Key": "qualification/bfq-test/b", "VersionId": "wrong"},
                ],
                False,
            ),
        ):
            with self.subTest(deleted=deleted):
                result = subprocess.run(  # noqa: S603
                    [
                        "jq",
                        "-e",
                        "--argjson",
                        "requested",
                        json.dumps(requested, separators=(",", ":")),
                        receipt_filter,
                    ],
                    input=json.dumps({"Deleted": deleted}),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
