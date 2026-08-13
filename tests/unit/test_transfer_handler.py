from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "lambda" / "common"
sys.path.insert(0, str(COMMON))
MODULE_PATH = ROOT / "lambda" / "transfer_destination" / "handler.py"
SPEC = importlib.util.spec_from_file_location(
    "transfer_destination_handler", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("transfer handler test module is unavailable")
HANDLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HANDLER
SPEC.loader.exec_module(HANDLER)


def api_event(route_key: str) -> dict:
    return {
        "routeKey": route_key,
        "headers": {
            "content-type": "application/json",
            "authorization": "Bearer " + "w" * 32,
        },
        "body": json.dumps(
            {
                "message": {
                    "type": "tool-calls",
                    "call": {
                        "id": "call_001",
                        "orgId": "org_001",
                        "assistantId": "assistant_001",
                    },
                    "toolCallList": [],
                }
            }
        ),
        "isBase64Encoded": False,
    }


class TransferHandlerTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "VAPI_WEBHOOK_SECRET_ARN": "arn:webhook",
                "VAPI_IDENTITY_BINDING_ARN": "arn:binding",
                "DIRECT_HANDOFF_SIGNING_KEY_SECRET_ARN": "arn:signing",
                "SCREEN_POP_FIELDS_JSON": "[]",
                "CORRELATION_KEY_SECRET_ARN": "arn:correlation",
                "DEPLOYMENT_ID": "bfq-test1234",
                "SIP_SECURITY": "sips_optional_srtp",
            },
            clear=True,
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    @staticmethod
    def secret(arn):
        return {
            "arn:webhook": "w" * 32,
            "arn:binding": json.dumps(
                {
                    "status": "bound",
                    "organization_id": "org_001",
                    "assistant_id": "assistant_001",
                }
            ),
            "arn:signing": "s" * 32,
            "arn:correlation": "c" * 32,
        }[arn]

    def test_direct_route_uses_only_direct_contract(self):
        expected = {"results": [{"toolCallId": "tool_001", "result": "accepted"}]}
        with (
            patch.object(HANDLER, "load_secret", side_effect=self.secret),
            patch.object(HANDLER, "verify_vapi_binding"),
            patch.object(HANDLER, "_store", return_value=object()),
            patch.object(HANDLER, "_direct_bridgefu") as direct_client,
            patch.object(HANDLER, "_bridgefu") as transfer_client,
            patch.object(HANDLER, "parse_fields", return_value=()),
            patch.object(
                HANDLER, "direct_browser_handoff", return_value=expected
            ) as direct,
            patch.object(HANDLER, "transfer_destination") as transfer,
            patch.object(HANDLER, "emit_operation") as emit,
        ):
            response = HANDLER.lambda_handler(
                api_event("POST /v1/direct-handoff"), None
            )
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"]), expected)
        direct.assert_called_once()
        transfer.assert_not_called()
        transfer_client.assert_not_called()
        self.assertIs(
            direct.call_args.kwargs["replace"], direct_client.return_value.replace
        )
        emit.assert_called_once_with(
            "direct_browser_handoff", "direct_started", unittest.mock.ANY
        )

    def test_transfer_route_does_not_load_direct_signing_authority(self):
        def secret_without_direct(arn):
            if arn == "arn:signing":
                self.fail("normal transfer must not read direct signing authority")
            return self.secret(arn)

        with (
            patch.object(HANDLER, "load_secret", side_effect=secret_without_direct),
            patch.object(HANDLER, "verify_vapi_binding"),
            patch.object(HANDLER, "_store", return_value=object()),
            patch.object(HANDLER, "_bridgefu") as transfer_client,
            patch.object(
                HANDLER, "transfer_destination", return_value={"destination": {}}
            ) as transfer,
            patch.object(HANDLER, "direct_browser_handoff") as direct,
            patch.object(HANDLER, "emit_operation"),
        ):
            response = HANDLER.lambda_handler(
                api_event("POST /v1/transfer-destination"), None
            )
        self.assertEqual(response["statusCode"], 200)
        transfer.assert_called_once()
        direct.assert_not_called()
        transfer_client.assert_called_once()


if __name__ == "__main__":
    unittest.main()
