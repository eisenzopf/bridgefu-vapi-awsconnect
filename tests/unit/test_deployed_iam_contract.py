from __future__ import annotations

import copy
import importlib.util
import os
import stat
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "verify_deployed_iam.py"
SPEC = importlib.util.spec_from_file_location("verify_deployed_iam", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("deployed IAM verifier could not be imported")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def policy(statements):
    values = []
    for statement in statements.values():
        value = {
            "Sid": statement["Sid"],
            "Effect": statement["Effect"],
            "Action": list(statement["Action"]),
            "Resource": list(statement["Resource"]),
        }
        if "Condition" in statement:
            value["Condition"] = copy.deepcopy(statement["Condition"])
        values.append(value)
    return {"Version": "2012-10-17", "Statement": values}


class DeployedIamContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = VERIFY.expected_contract(
            "aws", "123456789012", "bridgefu-vapi-awsconnect"
        )

    def test_exact_deployed_critical_statements_pass(self):
        for label in ("qualification", "recovery"):
            VERIFY.verify_policy_document(
                policy(self.contract[label]), self.contract[label], label
            )

    def test_missing_or_altered_critical_statement_fails(self):
        mutations = []
        missing = policy(self.contract["recovery"])
        missing["Statement"] = missing["Statement"][1:]
        mutations.append(missing)

        action = policy(self.contract["recovery"])
        action["Statement"][0]["Action"] = ["s3:*"]
        mutations.append(action)

        resource = policy(self.contract["recovery"])
        resource["Statement"][0]["Resource"] = ["*"]
        mutations.append(resource)

        condition = policy(self.contract["recovery"])
        condition["Statement"][0]["Condition"]["StringLike"]["s3:prefix"] = ["*"]
        mutations.append(condition)

        duplicate = policy(self.contract["recovery"])
        duplicate["Statement"].append(copy.deepcopy(duplicate["Statement"][0]))
        mutations.append(duplicate)

        for deployed in mutations:
            with (
                self.subTest(deployed=deployed),
                self.assertRaises(VERIFY.IamContractError),
            ):
                VERIFY.verify_policy_document(
                    deployed, self.contract["recovery"], "recovery"
                )

    def test_qualification_secret_write_condition_is_exact(self):
        deployed = policy(self.contract["qualification"])
        write = next(
            value
            for value in deployed["Statement"]
            if value["Sid"] == "UpdateOnlyTaggedGeneratedQualificationSecrets"
        )
        write["Condition"]["StringEquals"]["aws:ResourceTag/ManagedBy"] = "foreign"
        with self.assertRaisesRegex(VERIFY.IamContractError, "statement changed"):
            VERIFY.verify_policy_document(
                deployed, self.contract["qualification"], "qualification"
            )

    def test_verifier_is_executable_and_has_a_bounded_cli(self):
        self.assertTrue(SCRIPT.stat().st_mode & stat.S_IXUSR)
        result = subprocess.run(
            [os.fspath(SCRIPT), "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--qualification-policy", result.stdout)
        self.assertIn("--recovery-policy", result.stdout)


if __name__ == "__main__":
    unittest.main()
