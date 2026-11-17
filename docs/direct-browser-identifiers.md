# Session identifiers and Vapi call references in Connect

Use Amazon Connect contact attributes to carry identifiers through a direct
browser handoff. The browser stays attached to Bridgefu while
`bridgefu_direct_handoff` replaces the Vapi SIP leg with Amazon Connect. There
is no return SIP transfer on this path.

The browser add-on and its provisioning commands live in
[vapi-bridgefu-connect](https://github.com/vapi-eisen/vapi-bridgefu-connect/blob/main/docs/05-web-sdk-handoff.md).
The base CloudFormation stack alone configures the SIP-transfer path.

## Identifier contract

| Value | Source | Connect contact attribute |
| --- | --- | --- |
| Application session identifier | A configured text field supplied to the handoff tool | `screen_pop_value_N`, where N is the field's one-based position |
| Vapi call reference | Authenticated tool event `message.call.id` | `vapi_call_reference` |
| Bridgefu correlation identifier | Server-generated handoff/session binding | `correlation_id` |

These identifiers have different meanings. Do not replace `correlation_id`
with application input or use the Bridgefu `call_id` as the Vapi call ID.
The call reference is stored by the handoff backend; it is not a model
argument or a configurable screen-pop field. `vapi_call_reference` is a
reserved field key.

## Configure an application session field

Add a text field to the product stack's `ScreenPopFieldsJson`. The key, label,
description, maximum length, required flag, and position are configurable.
This one-field example is illustrative; preserve the other fields your
deployment needs, up to the eight-field limit.

```json
[
  {
    "key": "customer_session_id",
    "label": "Session ID",
    "description": "The caller's application session identifier, preserving leading zeros",
    "type": "text",
    "required": true,
    "max_length": 32
  }
]
```

Keep the product lookup Lambda, browser handoff Lambda, session creator, and
Vapi tool schema on the same configuration. The lab's `web-setup` command
reads `ScreenPopFieldsJson` and `ScreenPopSchemaHash` from the product stack
outputs and builds a new direct tool's parameters from those fields. It does
not rewrite a tool that already exists. After a field-schema change, refresh
the add-on and explicitly update the existing direct tool's function parameter
schema through the Vapi API or dashboard. Preserve its server and static
parameters. Start a new browser session; existing rows carry the earlier
schema hash.

The shipped lab prompt asks for the default four fields. Update the dedicated
browser assistant's prompt to collect your configured fields and call
`bridgefu_direct_handoff` once with their exact values. Preserve the static
`handoff_token` parameter and the assistant identity binding.

For identifiers collected through caller keypad input, enable this on the
Vapi SIP assistant:

```json
{
  "keypadInputPlan": {
    "enabled": true,
    "timeoutSeconds": 0,
    "delimiters": ["#"]
  }
}
```

Ask the caller to finish with `#`. Treat the entry as a string, preserve
leading zeros, and pass the digits without the delimiter. The generic field
validator enforces text length and control-character restrictions; it does
not enforce a digit-only format. Add application validation if your format
requires it. The lab demo's DTMF button sends only `9`; an application keypad
must send the actual identifier and delimiter through the browser SDK.

## Map attributes in your destination flow

The wrapper flow copies the lookup response into contact attributes before
entering your destination flow. In a **Set contact attributes** block in that
destination flow, choose your own destination names. For the example above:

| Destination attribute (example) | Source |
| --- | --- |
| `customer_session_id` | `$.Attributes.screen_pop_value_1` |
| `vapi_call_id` | `$.Attributes.vapi_call_reference` |

Use the actual field position if the session field is not first. The wrapper
does not automatically create an attribute named after the configured field
key. Check `$.Attributes.context_available` before using the context; failed
lookups deliberately let the voice contact continue.

Configure your Custom LLM with `metadataSendMode: "variable"` when it needs
the call object. Compare its request's `call.id` with `vapi_call_reference`.
Keep the Custom LLM's tool-calling support enabled so the handoff executes.

## Deploying the direct-browser call-reference fix

The fix adds `vapi_call_reference` to the existing conditional update in
`DynamoHandoffStore.prepare_direct()`. It preserves token, expiry, identity,
content, and retry checks. The lookup and Connect wrapper already support
this field, so no DynamoDB schema migration or gateway rebuild is needed.
Historical rows missing the reference are not backfilled; verify a new call.

Build the Lambda artifacts from the patched source:

```sh
python3 -m unittest discover -s tests/unit -p test_aws_runtime.py -v
python3 release/build_lambdas.py --output target/lambda
```

Deploy `transfer_destination.zip` to the function serving the browser
`/v1/direct-handoff` endpoint. For the lab add-on, upload it to a versioned S3
bucket in the stack's region and update the add-on through CloudFormation,
preserving its template and all other parameters:

- `ReleaseArtifactBucket`: the bucket containing the patched ZIP.
- `TransferArtifactKey`: its object key.
- `TransferArtifactVersion`: its exact S3 object version.

Record the previous three values for rollback. Never overwrite published
release objects. The stock lab provisioning command rediscovers the base
stack's released artifact; rerunning it can select the old artifact again.
Preserve or reapply the patched coordinates until a release includes this fix.

## Verify and roll back

Start a new browser call and submit a synthetic session identifier such as
`001234#`. Confirm that the assistant invokes the handoff, the agent receives
the call, `context_available` is `true`, the session attribute equals
`001234`, and `vapi_call_reference` equals the actual Vapi call ID. Neither
value should be confused with the generated correlation identifier. Check
audio in both directions and that hanging up ends both sides.

The regression test covers preparation, Connect lookup, leading-zero
preservation, and a retry after the handoff starts. It uses a DynamoDB test
double; it does not replace a live deployment check.

To roll back the Lambda, restore the previous artifact bucket, key, and
version through CloudFormation. Restore any separately changed assistant
configuration or destination-flow mappings from their saved copies. The
additional stored call reference does not prevent the earlier code from
reading the row.
