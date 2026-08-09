# Release smoke tests

These tests qualify the AMIs and CloudFormation templates built by this
repository. They are maintainer release gates, not customer deployment steps.

Both tests create a fresh disposable Amazon Connect instance and a new Vapi
template assistant, connect a call to the generated Connect agent, verify the
screen pop and audio in both directions, and then remove the environment.

1. `vapi-sip-transfer`: a controlled SIP client calls a temporary Vapi SIP URI.
2. `vapi-web-transfer`: the recipe harness starts a call through the modified
   Vapi Web SDK held at the Bridgefu commit pinned by `bridgefu.lock.json`.

The Web SDK is not copied into this repository. The qualification build fetches
the pinned Bridgefu source, verifies its lock digest, and builds the SDK from
that immutable revision. The smoke controller and evidence contracts live here
because they are specific to this CloudFormation release.

No smoke may accept an existing Amazon Connect instance ARN. A successful run
must finish with evidence that its disposable Connect instance, customer stack,
temporary Vapi resources, test credentials, and qualification S3 objects are
absent.

The controller does not use a Vapi web call for the SIP test. It creates a
temporary Vapi SIP URI and runs the statically linked `rvoip-sip = 0.3.7`
client on the candidate Bridgefu host. The Web SDK test is a separate call.

## Run it

Use the **Remote live qualification** GitHub workflow for an already uploaded
candidate. Choose `us-west-2` unless the release specifically needs an East
region compatibility run. The protected `live-qualification` environment must
provide:

- `AWS_QUALIFICATION_ROLE_ARN`
- `AWS_QUALIFICATION_CLOUDFORMATION_ROLE_ARN`
- `VAPI_API_KEY_SECRET_ARN`
- `PUBLIC_HOSTED_ZONE_ID`
- `PUBLIC_HOSTED_ZONE_NAME`
- `VAPI_PUBLIC_KEY` as an environment secret

The controller keeps the Vapi private key and generated Connect password only
in process memory. Retained evidence contains hashes, fixed synthetic values,
counts, timestamps, and resource-absence booleans.

Normal tagged releases run the same controller automatically. Candidate AMIs
stay private and `latest` is not updated until both calls and teardown pass.
Failed candidates are deregistered and their versioned staging objects removed.
