from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda" / "common"))

from screen_pop import (  # noqa: E402
    MAX_CONTEXT_BYTES,
    ScreenPopConfigError,
    parse_fields,
    validate_values,
    vapi_parameters,
)


class ScreenPopLengthContractTests(unittest.TestCase):
    def test_text_length_matches_vapi_json_schema_character_semantics(self):
        fields = parse_fields(
            [
                {
                    "key": "summary",
                    "label": "Summary",
                    "description": "Short caller summary.",
                    "type": "text",
                    "required": True,
                    "max_length": 2,
                }
            ]
        )

        schema = vapi_parameters(fields)
        self.assertEqual(schema["properties"]["summary"]["maxLength"], 2)
        self.assertEqual(validate_values({"summary": "éé"}, fields), {"summary": "éé"})
        with self.assertRaisesRegex(ScreenPopConfigError, "screen_pop_value_invalid"):
            validate_values({"summary": "ééé"}, fields)

    def test_choice_limit_is_128_characters_not_128_utf8_bytes(self):
        valid_choice = "界" * 128
        fields = parse_fields(
            [
                {
                    "key": "queue",
                    "label": "Queue",
                    "description": "Selected destination queue.",
                    "type": "choice",
                    "required": True,
                    "choices": [valid_choice, "support"],
                }
            ]
        )
        self.assertEqual(validate_values({"queue": valid_choice}, fields)["queue"], valid_choice)

        with self.assertRaisesRegex(
            ScreenPopConfigError, "screen_pop_field_choice"
        ):
            parse_fields(
                [
                    {
                        "key": "queue",
                        "label": "Queue",
                        "description": "Selected destination queue.",
                        "type": "choice",
                        "required": True,
                        "choices": ["界" * 129, "support"],
                    }
                ]
            )

    def test_serialized_context_remains_bounded_in_utf8_bytes(self):
        fields = parse_fields(
            [
                {
                    "key": f"field_{index}",
                    "label": f"Field {index}",
                    "description": "Bounded value.",
                    "type": "text",
                    "required": True,
                    "max_length": 1024,
                }
                for index in range(8)
            ]
        )
        values = {field.key: "界" * 1024 for field in fields}
        self.assertGreater(
            len(str(values).encode("utf-8")),
            MAX_CONTEXT_BYTES,
        )
        with self.assertRaisesRegex(ScreenPopConfigError, "screen_pop_values_too_large"):
            validate_values(values, fields)


if __name__ == "__main__":
    unittest.main()
