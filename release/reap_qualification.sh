#!/usr/bin/env bash
set -euo pipefail
account_id="$(aws sts get-caller-identity --query Account --output text)"
strict_status=0
sensitive_files=()
cleanup_sensitive_files() {
  unset direct_secret direct_vapi_key secret_string vapi_key
  for sensitive_file in "${sensitive_files[@]}"; do
    if [[ -f "$sensitive_file" ]]; then
      rm -f -- "$sensitive_file"
    fi
  done
}
trap cleanup_sensitive_files EXIT
run_strict() {
  set +e
  (
    set -e
    "$@"
  )
  strict_status="$?"
  set -e
  return 0
}
load_latest_s3_object_exact() {
  region="$1"
  bucket="$2"
  key="$3"
  destination="$4"
  maximum_bytes="$5"
  listing="$(aws s3api list-object-versions --region "$region" \
    --bucket "$bucket" --prefix "$key" --max-keys 100 \
    --no-paginate)"
  jq -e '.IsTruncated == false' <<<"$listing" >/dev/null
  latest="$(jq -cer --arg key "$key" '
    (((.Versions // []) | map(. + {kind: "version"})) +
     ((.DeleteMarkers // []) | map(. + {kind: "delete"}))) |
    [.[] | select(.Key == $key and .IsLatest == true)] |
    if length == 0 then {kind: "absent"}
    elif length == 1 then .[0]
    else error("ambiguous latest object version") end' <<<"$listing")"
  case "$(jq -r .kind <<<"$latest")" in
    absent|delete) return 3 ;;
    version) ;;
    *) return 2 ;;
  esac
  version_id="$(jq -er '.VersionId |
    select(type == "string" and length >= 1 and length <= 1024)' \
    <<<"$latest")"
  object_head="$(aws s3api head-object --region "$region" \
    --bucket "$bucket" --key "$key" --version-id "$version_id")"
  jq -e --argjson maximum "$maximum_bytes" '
    (.ContentLength > 0 and .ContentLength <= $maximum) and
    (.ServerSideEncryption == "AES256" or
     .ServerSideEncryption == "aws:kms")' \
    <<<"$object_head" >/dev/null
  aws s3api get-object --region "$region" --bucket "$bucket" \
    --key "$key" --version-id "$version_id" "$destination" >/dev/null
}
describe_stack_exact() {
  region="$1"
  stack_name="$2"
  destination="$3"
  error_file="${destination}.error"
  set +e
  aws cloudformation describe-stacks --region "$region" \
    --stack-name "$stack_name" >"$destination" 2>"$error_file"
  status="$?"
  set -e
  if [[ "$status" = 0 ]]; then
    jq -e --arg stack "$stack_name" '
      (.Stacks | type == "array" and length == 1) and
      .Stacks[0].StackName == $stack' "$destination" >/dev/null
    rm -f "$error_file"
    return 0
  fi
  if grep -Eq '^(aws: \[ERROR\]: )?An error occurred \(ValidationError\) when calling the DescribeStacks operation: Stack with id .+ does not exist$' \
    "$error_file"; then
    rm -f "$destination" "$error_file"
    return 3
  fi
  rm -f "$destination" "$error_file"
  return 2
}
delete_prefix_versions() {
  region="$1"
  bucket="$2"
  prefix="$3"
  for pass in 1 2 3 4 5 6 7 8 9 10; do
    : "$pass"
    listing="$(aws s3api list-object-versions --region "$region" \
      --bucket "$bucket" --prefix "$prefix")"
    deletes="$(jq -c --arg prefix "$prefix" \
      '{Objects: (((.Versions // []) + (.DeleteMarkers // [])) |
        map(select(.Key | startswith($prefix)) |
          {Key: .Key, VersionId: .VersionId}) | .[:1000]), Quiet: false}' \
      <<<"$listing")"
    [[ "$(jq '.Objects | length' <<<"$deletes")" = 0 ]] && return 0
    delete_response="$(aws s3api delete-objects --region "$region" \
      --bucket "$bucket" --delete "$deletes")"
    jq -e --argjson requested "$deletes" '
      ((.Errors // []) | length == 0) and
      ((.Deleted // []) | length == ($requested.Objects | length)) and
      (((.Deleted // []) | map({Key, VersionId}) |
          sort_by(.Key, .VersionId)) ==
       ($requested.Objects | sort_by(.Key, .VersionId)))' \
      <<<"$delete_response" >/dev/null
  done
  listing="$(aws s3api list-object-versions --region "$region" \
    --bucket "$bucket" --prefix "$prefix")"
  jq -e --arg prefix "$prefix" \
    '[((.Versions // []) + (.DeleteMarkers // []))[]? |
      select(.Key | startswith($prefix))] | length == 0' \
    <<<"$listing" >/dev/null
}
stack_output_exact() {
  stack_file="$1"
  output_key="$2"
  jq -er --arg key "$output_key" '
    [.Stacks[0].Outputs[]? | select(.OutputKey == $key) | .OutputValue] |
    if length == 1 and (.[0] | type) == "string" then .[0]
    else error("missing or ambiguous stack output") end' "$stack_file"
}
validate_vapi_direct_tool_intent_exact() {
  intent_file="$1"
  execution_id="$2"
  region="$3"
  jq -e --arg execution_id "$execution_id" --arg region "$region" '
    (keys | sort) == ["created_at","credential_id","desired",
      "desired_sha256","endpoint_url","execution_id","intent_sha256",
      "producer","redacted","region","resource_type","schema_version"] and
    .schema_version == 1 and
    .producer == "bridgefu-vapi-direct-tool-intent@1" and
    .execution_id == $execution_id and
    (.execution_id | test("^bfq-[a-z0-9-]{4,20}$")) and
    .region == $region and
    ($region == "us-west-2" or $region == "us-east-1") and
    .resource_type == "tool" and .redacted == true and
    (.credential_id | test("^[A-Za-z0-9_-]{1,128}$")) and
    (.endpoint_url | test(
      "^https://[a-z0-9-]+\\.execute-api\\.(us-west-2|us-east-1)\\.[A-Za-z0-9.-]+/v1/direct-handoff$")) and
    (.desired | type == "object") and
    .desired.type == "function" and
    .desired.function.name == "bridgefu_direct_handoff" and
    .desired.server.url == .endpoint_url and
    .desired.server.credentialId == .credential_id and
    .desired.server.timeoutSeconds == 10 and
    .desired.parameters == [{"key":"handoff_token",
      "value":"{{ bridgefu_handoff_token }}"}] and
    (.desired_sha256 | test("^[0-9a-f]{64}$")) and
    (.intent_sha256 | test("^[0-9a-f]{64}$")) and
    (.created_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$intent_file" >/dev/null
  desired_canonical="$(jq -cS .desired "$intent_file")"
  desired_hash="$(printf '%s' "$desired_canonical" |
    sha256sum | awk '{print $1}')"
  test "$desired_hash" = "$(jq -r .desired_sha256 "$intent_file")"
  canonical="$(jq -cS '
    {execution_id, region, resource_type, endpoint_url, credential_id,
     desired_sha256}' "$intent_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .intent_sha256 "$intent_file")"
}
validate_vapi_direct_tool_ownership_exact() {
  journal_file="$1"
  intent_file="$2"
  jq -e --argjson intent "$(jq . "$intent_file")" '
    (keys | sort) == ["created_at","credential_id","desired_sha256",
      "endpoint_url","execution_id","intent_sha256","ownership_sha256",
      "producer","redacted","region","resource_type","schema_version",
      "tool_id"] and
    .schema_version == 1 and
    .producer == "bridgefu-vapi-direct-tool-ownership@1" and
    .execution_id == $intent.execution_id and .region == $intent.region and
    .resource_type == "tool" and .endpoint_url == $intent.endpoint_url and
    .credential_id == $intent.credential_id and
    .desired_sha256 == $intent.desired_sha256 and
    .intent_sha256 == $intent.intent_sha256 and .redacted == true and
    (.tool_id | test("^[A-Za-z0-9_-]{1,128}$")) and
    (.ownership_sha256 | test("^[0-9a-f]{64}$")) and
    (.created_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$journal_file" >/dev/null
  canonical="$(jq -cS '
    {execution_id, region, resource_type, tool_id, endpoint_url,
     credential_id, desired_sha256, intent_sha256}' "$journal_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .ownership_sha256 "$journal_file")"
}
validate_vapi_direct_request_exact() {
  request_file="$1"
  intent_file="$2"
  resource_type="$3"
  case "$resource_type" in
    tool) request_producer="bridgefu-vapi-direct-tool-request@1" ;;
    assistant) request_producer="bridgefu-vapi-direct-assistant-request@1" ;;
    *) return 2 ;;
  esac
  jq -e --arg producer "$request_producer" --arg resource "$resource_type" \
    --argjson intent "$(jq . "$intent_file")" '
    (keys | sort) == ["attempt_state","authorized_at","execution_id",
      "intent_sha256","producer","redacted","region","request_nonce",
      "request_sha256","resource_type","schema_version"] and
    .schema_version == 1 and .producer == $producer and
    .execution_id == $intent.execution_id and .region == $intent.region and
    .resource_type == $resource and .resource_type == $intent.resource_type and
    .intent_sha256 == $intent.intent_sha256 and
    .attempt_state == "authorized" and .redacted == true and
    (.request_nonce | test("^[0-9a-f]{32}$")) and
    (.request_sha256 | test("^[0-9a-f]{64}$")) and
    (.authorized_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$request_file" >/dev/null
  canonical="$(jq -cS '
    {execution_id, region, resource_type, intent_sha256, request_nonce,
     attempt_state}' "$request_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .request_sha256 "$request_file")"
}
validate_vapi_direct_assistant_intent_exact() {
  intent_file="$1"
  execution_id="$2"
  region="$3"
  jq -e --arg execution_id "$execution_id" --arg region "$region" \
    --arg name "BFQ direct $execution_id" '
    (keys | sort) == ["created_at","desired","desired_sha256",
      "execution_id","intent_sha256","model_name","organization_id",
      "owned_name","owner_marker","producer","prompt_sha256","redacted",
      "region","resource_type","schema_version","tool_id","voice_id"] and
    .schema_version == 1 and
    .producer == "bridgefu-vapi-direct-assistant-intent@1" and
    .execution_id == $execution_id and .region == $region and
    .resource_type == "assistant" and .owned_name == $name and
    .owner_marker == "bridgefu-direct-web-qualification@1" and
    .redacted == true and
    (.tool_id | test("^[A-Za-z0-9_-]{1,128}$")) and
    (.organization_id | test("^[A-Za-z0-9_-]{1,128}$")) and
    (.model_name | type == "string" and length >= 1 and length <= 128) and
    (.voice_id | type == "string" and length >= 1 and length <= 128) and
    (.prompt_sha256 | test("^[0-9a-f]{64}$")) and
    (.desired_sha256 | test("^[0-9a-f]{64}$")) and
    (.intent_sha256 | test("^[0-9a-f]{64}$")) and
    (.desired | type == "object") and .desired.name == $name and
    .desired.metadata.bridgefu_qualification == $execution_id and
    .desired.metadata.bridgefu_owner == .owner_marker and
    .desired.model.provider == "openai" and
    .desired.model.model == .model_name and
    .desired.model.temperature == 0 and
    .desired.model.toolIds == [.tool_id] and
    (.desired.model | has("tools") | not) and
    (.desired.model.messages | type == "array" and length == 1) and
    (.desired.model.messages[0].content | contains(
      "[bridgefu-direct-browser-handoff@1]")) and
    ((.desired.model.messages[0].content | @base64) as $prompt |
      $prompt | type == "string") and
    .desired.voice == {"provider":"vapi","voiceId":.voice_id} and
    (.created_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$intent_file" >/dev/null
  prompt_hash="$(jq -j .desired.model.messages[0].content "$intent_file" |
    sha256sum | awk '{print $1}')"
  test "$prompt_hash" = "$(jq -r .prompt_sha256 "$intent_file")"
  desired_canonical="$(jq -cS .desired "$intent_file")"
  desired_hash="$(printf '%s' "$desired_canonical" |
    sha256sum | awk '{print $1}')"
  test "$desired_hash" = "$(jq -r .desired_sha256 "$intent_file")"
  canonical="$(jq -cS '
    {execution_id, region, resource_type, owned_name, owner_marker, tool_id,
     organization_id, model_name, voice_id, prompt_sha256, desired_sha256}' \
    "$intent_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .intent_sha256 "$intent_file")"
}
validate_vapi_direct_assistant_ownership_exact() {
  journal_file="$1"
  intent_file="$2"
  jq -e --argjson intent "$(jq . "$intent_file")" '
    (keys | sort) == ["assistant_id","created_at","desired_sha256",
      "execution_id","intent_sha256","model_name","organization_id",
      "owned_name","owner_marker","ownership_sha256","producer",
      "prompt_sha256","redacted","region","resource_type",
      "schema_version","tool_id","voice_id"] and
    .schema_version == 1 and
    .producer == "bridgefu-vapi-direct-assistant-ownership@1" and
    .execution_id == $intent.execution_id and .region == $intent.region and
    .resource_type == "assistant" and .owned_name == $intent.owned_name and
    .owner_marker == $intent.owner_marker and .tool_id == $intent.tool_id and
    .organization_id == $intent.organization_id and
    .model_name == $intent.model_name and .voice_id == $intent.voice_id and
    .prompt_sha256 == $intent.prompt_sha256 and
    .desired_sha256 == $intent.desired_sha256 and
    .intent_sha256 == $intent.intent_sha256 and .redacted == true and
    (.assistant_id | test("^[A-Za-z0-9_-]{1,128}$")) and
    (.ownership_sha256 | test("^[0-9a-f]{64}$")) and
    (.created_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$journal_file" >/dev/null
  canonical="$(jq -cS '
    {execution_id, region, resource_type, assistant_id, owned_name,
     owner_marker, tool_id, organization_id, model_name, voice_id,
     prompt_sha256, desired_sha256, intent_sha256}' "$journal_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .ownership_sha256 "$journal_file")"
}
validate_remote_vapi_direct_tool_exact() {
  response_file="$1"
  tool_id="$2"
  intent_file="$3"
  jq -e --arg tool_id "$tool_id" \
    --argjson desired "$(jq .desired "$intent_file")" '
    def absent_or_identifier($name):
      (has($name) | not) or .[$name] == null or
      (.[$name] | type == "string" and test("^[A-Za-z0-9_-]{1,128}$"));
    def absent_or_timestamp($name):
      (has($name) | not) or .[$name] == null or
      (.[$name] | type == "string" and
       test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"));
    type == "object" and .id == $tool_id and
    ((keys - ["id","orgId","createdAt","updatedAt","latestVersion","type","function",
      "server","parameters"]) | length == 0) and
    absent_or_identifier("orgId") and absent_or_timestamp("createdAt") and
    absent_or_timestamp("updatedAt") and absent_or_identifier("latestVersion") and
    .type == $desired.type and
    .function == $desired.function and .server == $desired.server and
    .parameters == $desired.parameters' \
    "$response_file" >/dev/null
}
validate_remote_vapi_direct_assistant_exact() {
  response_file="$1"
  assistant_id="$2"
  intent_file="$3"
  jq -e --arg assistant_id "$assistant_id" \
    --arg org "$(jq -r .organization_id "$intent_file")" \
    --argjson desired "$(jq .desired "$intent_file")" '
    def absent_or_timestamp($name):
      (has($name) | not) or .[$name] == null or
      (.[$name] | type == "string" and
       test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"));
    type == "object" and .id == $assistant_id and
    ((keys - ["id","orgId","createdAt","updatedAt","name",
      "firstMessageMode","model","voice","transcriber","artifactPlan",
      "maxDurationSeconds","metadata","server","serverMessages",
      "serverUrl","hooks","credentialIds"]) | length == 0) and
    ((has("orgId") | not) or .orgId == null or .orgId == "" or
     (.orgId | type == "string" and . == $org)) and
    absent_or_timestamp("createdAt") and absent_or_timestamp("updatedAt") and
    ((has("server") | not) or .server == null) and
    ((has("serverUrl") | not) or .serverUrl == null) and
    ((has("serverMessages") | not) or .serverMessages == null or
      .serverMessages == []) and
    ((has("hooks") | not) or .hooks == null or .hooks == []) and
    ((has("credentialIds") | not) or .credentialIds == null or
      .credentialIds == []) and
    .name == $desired.name and
    .firstMessageMode == $desired.firstMessageMode and
    (.voice | type == "object") and
    (((.voice | keys) - ["provider","voiceId","fallbackPlan"]) | length == 0) and
    .voice.provider == $desired.voice.provider and
    .voice.voiceId == $desired.voice.voiceId and
    ((.voice | has("fallbackPlan") | not) or
      .voice.fallbackPlan == null or .voice.fallbackPlan == {} or
      .voice.fallbackPlan == []) and
    (.transcriber | type == "object") and
    (((.transcriber | keys) - ["provider","model","language","smartFormat"]) |
      length == 0) and
    .transcriber.provider == $desired.transcriber.provider and
    .transcriber.model == $desired.transcriber.model and
    .transcriber.language == $desired.transcriber.language and
    ((.transcriber | has("smartFormat") | not) or
      .transcriber.smartFormat == true) and
    (.artifactPlan | type == "object") and
    (((.artifactPlan | keys) - ["recordingEnabled","loggingEnabled"]) |
      length == 0) and
    .artifactPlan.recordingEnabled == false and
    ((.artifactPlan | has("loggingEnabled") | not) or
      .artifactPlan.loggingEnabled == false) and
    .maxDurationSeconds == $desired.maxDurationSeconds and
    .metadata == $desired.metadata and
    (.model | type == "object") and
    (((.model | keys) - ["provider","model","temperature","messages",
      "toolIds","tools","knowledgeBase","knowledgeBaseId"]) | length == 0) and
    ((.model | has("tools") | not) or .model.tools == null or
      .model.tools == []) and
    ((.model | has("knowledgeBase") | not) or .model.knowledgeBase == null) and
    ((.model | has("knowledgeBaseId") | not) or
      .model.knowledgeBaseId == null) and
    .model.provider == $desired.model.provider and
    .model.model == $desired.model.model and
    .model.temperature == $desired.model.temperature and
    .model.messages == $desired.model.messages and
    (.model.messages | length == 1) and
    .model.toolIds == $desired.model.toolIds and
    (.model.toolIds | length == 1)' "$response_file" >/dev/null
}
load_vapi_curl_config() {
  region="$1"
  curl_config_file="$2"
  case "$region" in
    us-west-2) direct_secret_arn="$VAPI_API_KEY_SECRET_ARN_US_WEST_2" ;;
    us-east-1) direct_secret_arn="$VAPI_API_KEY_SECRET_ARN_US_EAST_1" ;;
    *) return 2 ;;
  esac
  direct_secret="$(aws secretsmanager get-secret-value --region "$region" \
    --secret-id "$direct_secret_arn" --query SecretString --output text)"
  [[ ${#direct_secret} -ge 8 && ${#direct_secret} -le 65536 ]]
  if jq -e 'type == "object"' <<<"$direct_secret" >/dev/null 2>&1; then
    direct_vapi_key="$(jq -er '
      [.private_key, .privateKey, .key] |
      map(select(type == "string")) |
      if length == 1 then .[0] else error(
        "secret must contain exactly one private key field") end' \
      <<<"$direct_secret")"
  else
    direct_vapi_key="$direct_secret"
  fi
  unset direct_secret
  [[ ${#direct_vapi_key} -ge 8 && ${#direct_vapi_key} -le 1024 ]]
  [[ "$direct_vapi_key" =~ ^[A-Za-z0-9._-]+$ ]]
  umask 077
  test ! -e "$curl_config_file"
  test ! -L "$curl_config_file"
  (
    set -o noclobber
    printf 'header = "Authorization: Bearer %s"\n' "$direct_vapi_key" \
      >"$curl_config_file"
  )
  chmod 600 "$curl_config_file"
  sensitive_files+=("$curl_config_file")
  unset direct_vapi_key
}
write_recovered_direct_tool_ownership() {
  region="$1"
  bucket="$2"
  journal_key="$3"
  tool_id="$4"
  intent_file="$5"
  canonical="$(jq -cnS --arg tool_id "$tool_id" \
    --argjson intent "$(jq . "$intent_file")" '
    {execution_id: $intent.execution_id, region: $intent.region,
     resource_type: "tool", tool_id: $tool_id,
     endpoint_url: $intent.endpoint_url, credential_id: $intent.credential_id,
     desired_sha256: $intent.desired_sha256,
     intent_sha256: $intent.intent_sha256}')"
  ownership_sha256="$(printf '%s' "$canonical" |
    sha256sum | awk '{print $1}')"
  created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  jq -cnS --arg tool_id "$tool_id" --arg created_at "$created_at" \
    --arg ownership_sha256 "$ownership_sha256" \
    --argjson intent "$(jq . "$intent_file")" '
    {schema_version: 1, producer: "bridgefu-vapi-direct-tool-ownership@1",
     execution_id: $intent.execution_id, region: $intent.region,
     resource_type: "tool", tool_id: $tool_id,
     endpoint_url: $intent.endpoint_url, credential_id: $intent.credential_id,
     desired_sha256: $intent.desired_sha256,
     intent_sha256: $intent.intent_sha256,
     ownership_sha256: $ownership_sha256, created_at: $created_at,
     redacted: true}' >vapi-direct-tool-recovered.json
  aws s3api put-object --region "$region" --bucket "$bucket" \
    --key "$journal_key" --body vapi-direct-tool-recovered.json \
    --content-type application/json --server-side-encryption AES256 >/dev/null
}
write_recovered_direct_assistant_ownership() {
  region="$1"
  bucket="$2"
  journal_key="$3"
  assistant_id="$4"
  intent_file="$5"
  canonical="$(jq -cnS --arg assistant_id "$assistant_id" \
    --argjson intent "$(jq . "$intent_file")" '
    {execution_id: $intent.execution_id, region: $intent.region,
     resource_type: "assistant", assistant_id: $assistant_id,
     owned_name: $intent.owned_name, owner_marker: $intent.owner_marker,
     tool_id: $intent.tool_id, organization_id: $intent.organization_id,
     model_name: $intent.model_name, voice_id: $intent.voice_id,
     prompt_sha256: $intent.prompt_sha256,
     desired_sha256: $intent.desired_sha256,
     intent_sha256: $intent.intent_sha256}')"
  ownership_sha256="$(printf '%s' "$canonical" |
    sha256sum | awk '{print $1}')"
  created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  jq -cnS --arg assistant_id "$assistant_id" --arg created_at "$created_at" \
    --arg ownership_sha256 "$ownership_sha256" \
    --argjson intent "$(jq . "$intent_file")" '
    {schema_version: 1,
     producer: "bridgefu-vapi-direct-assistant-ownership@1",
     execution_id: $intent.execution_id, region: $intent.region,
     resource_type: "assistant", assistant_id: $assistant_id,
     owned_name: $intent.owned_name, owner_marker: $intent.owner_marker,
     tool_id: $intent.tool_id, organization_id: $intent.organization_id,
     model_name: $intent.model_name, voice_id: $intent.voice_id,
     prompt_sha256: $intent.prompt_sha256,
     desired_sha256: $intent.desired_sha256,
     intent_sha256: $intent.intent_sha256,
     ownership_sha256: $ownership_sha256, created_at: $created_at,
     redacted: true}' >vapi-direct-assistant-recovered.json
  aws s3api put-object --region "$region" --bucket "$bucket" \
    --key "$journal_key" --body vapi-direct-assistant-recovered.json \
    --content-type application/json --server-side-encryption AES256 >/dev/null
}
prepare_exact_direct_vapi_recovery() {
  direct_region="$1"
  direct_bucket="$2"
  direct_execution_id="$3"
  direct_stack_name="$4"
  direct_prefix="qualification/$direct_execution_id/ownership"
  direct_tool_intent_key="$direct_prefix/vapi-direct-tool-intent.json"
  direct_tool_request_key="$direct_prefix/vapi-direct-tool-request.json"
  direct_tool_journal_key="$direct_prefix/vapi-direct-tool.json"
  direct_assistant_intent_key="$direct_prefix/vapi-direct-assistant-intent.json"
  direct_assistant_request_key="$direct_prefix/vapi-direct-assistant-request.json"
  direct_assistant_journal_key="$direct_prefix/vapi-direct-assistant.json"
  direct_recovery_present=false
  direct_tool_intent_present=false
  direct_tool_request_present=false
  direct_tool_journal_present=false
  direct_assistant_intent_present=false
  direct_assistant_request_present=false
  direct_assistant_journal_present=false
  direct_recovery_tool_id=""
  direct_recovery_assistant_id=""
  for direct_record in \
    tool-intent:"$direct_tool_intent_key":vapi-direct-tool-intent.json:32768 \
    tool-request:"$direct_tool_request_key":vapi-direct-tool-request.json:8192 \
    tool:"$direct_tool_journal_key":vapi-direct-tool.json:8192 \
    assistant-intent:"$direct_assistant_intent_key":vapi-direct-assistant-intent.json:32768 \
    assistant-request:"$direct_assistant_request_key":vapi-direct-assistant-request.json:8192 \
    assistant:"$direct_assistant_journal_key":vapi-direct-assistant.json:8192; do
    direct_kind="${direct_record%%:*}"
    direct_remainder="${direct_record#*:}"
    direct_key="${direct_remainder%%:*}"
    direct_remainder="${direct_remainder#*:}"
    direct_file="${direct_remainder%%:*}"
    direct_limit="${direct_remainder##*:}"
    run_strict load_latest_s3_object_exact "$direct_region" "$direct_bucket" \
      "$direct_key" "$direct_file" "$direct_limit"
    case "$strict_status" in
      0)
        direct_recovery_present=true
        case "$direct_kind" in
          tool-intent) direct_tool_intent_present=true ;;
          tool-request) direct_tool_request_present=true ;;
          tool) direct_tool_journal_present=true ;;
          assistant-intent) direct_assistant_intent_present=true ;;
          assistant-request) direct_assistant_request_present=true ;;
          assistant) direct_assistant_journal_present=true ;;
          *) return 2 ;;
        esac
        ;;
      3) ;;
      *) return "$strict_status" ;;
    esac
  done
  if [[ "$direct_recovery_present" = false ]]; then
    return 0
  fi
  test "$direct_tool_intent_present" = true
  if [[ "$direct_tool_request_present" = true ||
        "$direct_tool_journal_present" = true ]]; then
    test "$direct_tool_intent_present" = true
  fi
  if [[ "$direct_assistant_request_present" = true ||
        "$direct_assistant_journal_present" = true ]]; then
    test "$direct_assistant_intent_present" = true
  fi
  validate_vapi_direct_tool_intent_exact vapi-direct-tool-intent.json \
    "$direct_execution_id" "$direct_region"
  if [[ "$direct_tool_request_present" = true ]]; then
    validate_vapi_direct_request_exact vapi-direct-tool-request.json \
      vapi-direct-tool-intent.json tool
  fi
  if [[ "$direct_tool_journal_present" = true ]]; then
    test "$direct_tool_request_present" = true
  fi
  if [[ "$direct_tool_journal_present" = true ]]; then
    validate_vapi_direct_tool_ownership_exact vapi-direct-tool.json \
      vapi-direct-tool-intent.json
  fi
  if [[ "$direct_assistant_intent_present" = true ]]; then
    validate_vapi_direct_assistant_intent_exact \
      vapi-direct-assistant-intent.json "$direct_execution_id" "$direct_region"
  fi
  if [[ "$direct_assistant_request_present" = true ]]; then
    validate_vapi_direct_request_exact vapi-direct-assistant-request.json \
      vapi-direct-assistant-intent.json assistant
  fi
  if [[ "$direct_assistant_journal_present" = true ]]; then
    test "$direct_assistant_request_present" = true
    validate_vapi_direct_assistant_ownership_exact \
      vapi-direct-assistant.json vapi-direct-assistant-intent.json
  fi
  if [[ "$direct_tool_request_present" = false ]]; then
    test "$direct_tool_journal_present" = false
    test "$direct_assistant_intent_present" = false
    test "$direct_assistant_request_present" = false
    test "$direct_assistant_journal_present" = false
    return 0
  fi
  run_strict describe_stack_exact "$direct_region" "$direct_stack_name" \
    vapi-direct-stack.json
  test "$strict_status" = 0
  direct_stack_endpoint="$(stack_output_exact vapi-direct-stack.json DirectHandoffUrl)"
  direct_stack_credential="$(stack_output_exact vapi-direct-stack.json VapiWebhookCredentialId)"
  direct_stack_model="$(stack_output_exact vapi-direct-stack.json VapiModel)"
  direct_stack_voice="$(stack_output_exact vapi-direct-stack.json VapiVoiceId)"
  direct_stack_product_assistant="$(stack_output_exact \
    vapi-direct-stack.json VapiAssistantId)"
  direct_product_binding_arn="$(stack_output_exact \
    vapi-direct-stack.json ProductVapiIdentityBindingArn)"
  direct_identity_binding_arn="$(stack_output_exact \
    vapi-direct-stack.json DirectVapiIdentityBindingArn)"
  test "$direct_stack_endpoint" = \
    "$(jq -r .endpoint_url vapi-direct-tool-intent.json)"
  test "$direct_stack_credential" = \
    "$(jq -r .credential_id vapi-direct-tool-intent.json)"
  direct_vapi_curl_config="vapi-direct-$direct_region-curl.config"
  load_vapi_curl_config "$direct_region" "$direct_vapi_curl_config"
  umask 077
  if [[ "$direct_tool_journal_present" = false ]]; then
    direct_owned_tool=""
    for direct_attempt in $(seq 1 30); do
      direct_status="$(curl --config "$direct_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 524288 \
        --output vapi-direct-tool-list.json --write-out '%{http_code}' \
        'https://api.vapi.ai/tool?limit=100')"
      test "$direct_status" = 200
      jq -e 'type == "array" and length < 100 and
        all(.[]; type == "object")' vapi-direct-tool-list.json >/dev/null
      jq -c --arg endpoint "$direct_stack_endpoint" \
        --arg credential "$direct_stack_credential" '
        [.[] | select(
          .server.url == $endpoint or
          (.server.credentialId == $credential and
           .function.name == "bridgefu_direct_handoff"))]' \
        vapi-direct-tool-list.json \
        >vapi-direct-tool-related.json
      direct_related_count="$(jq 'length' vapi-direct-tool-related.json)"
      test "$direct_related_count" -le 1
      if [[ "$direct_related_count" = 1 ]]; then
        jq -c '.[0]' vapi-direct-tool-related.json >vapi-direct-tool-match.json
        direct_owned_tool="$(jq -er '.id |
          select(type == "string" and test("^[A-Za-z0-9_-]{1,128}$"))' \
          vapi-direct-tool-match.json)"
        direct_status="$(curl --config "$direct_vapi_curl_config" \
          --silent --proto '=https' --tlsv1.2 \
          --connect-timeout 5 --max-time 20 --max-filesize 524288 \
          --output vapi-direct-tool-match-exact.json --write-out '%{http_code}' \
          "https://api.vapi.ai/tool/$direct_owned_tool")"
        test "$direct_status" = 200
        validate_remote_vapi_direct_tool_exact \
          vapi-direct-tool-match-exact.json \
          "$direct_owned_tool" vapi-direct-tool-intent.json
        break
      fi
      [[ "$direct_attempt" = 30 ]] && break
      sleep 2
    done
    if [[ -z "$direct_owned_tool" ]]; then
      test "$direct_assistant_intent_present" = false
      echo 'Direct Vapi tool intent exists but absence cannot be proven safe.' >&2
      return 2
    fi
    write_recovered_direct_tool_ownership "$direct_region" "$direct_bucket" \
      "$direct_tool_journal_key" "$direct_owned_tool" \
      vapi-direct-tool-intent.json
    load_latest_s3_object_exact "$direct_region" "$direct_bucket" \
      "$direct_tool_journal_key" vapi-direct-tool.json 8192
    direct_tool_journal_present=true
    validate_vapi_direct_tool_ownership_exact vapi-direct-tool.json \
      vapi-direct-tool-intent.json
  fi
  direct_recovery_tool_id="$(jq -r .tool_id vapi-direct-tool.json)"
  if [[ "$direct_assistant_intent_present" = false ]]; then
    test "$direct_assistant_request_present" = false
    test "$direct_assistant_journal_present" = false
    return 0
  fi
  test "$(jq -r .tool_id vapi-direct-assistant-intent.json)" = \
    "$direct_recovery_tool_id"
  test "$(jq -r .model_name vapi-direct-assistant-intent.json)" = \
    "$direct_stack_model"
  test "$(jq -r .voice_id vapi-direct-assistant-intent.json)" = \
    "$direct_stack_voice"
  if [[ "$direct_assistant_request_present" = false ]]; then
    test "$direct_assistant_journal_present" = false
    return 0
  fi
  direct_product_binding="$(aws secretsmanager get-secret-value \
    --region "$direct_region" --secret-id "$direct_product_binding_arn" \
    --query SecretString --output text)"
  jq -e --arg assistant "$direct_stack_product_assistant" \
    --arg org "$(jq -r .organization_id vapi-direct-assistant-intent.json)" '
    (keys | sort) == ["assistant_id","organization_id","status"] and
    .status == "bound" and .assistant_id == $assistant and
    .organization_id == $org' <<<"$direct_product_binding" >/dev/null
  unset direct_product_binding
  if [[ "$direct_assistant_journal_present" = false ]]; then
    direct_owned_assistant=""
    direct_name="$(jq -r .owned_name vapi-direct-assistant-intent.json)"
    for direct_attempt in $(seq 1 30); do
      direct_status="$(curl --config "$direct_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 524288 \
        --output vapi-direct-assistant-list.json --write-out '%{http_code}' \
        'https://api.vapi.ai/assistant?limit=100')"
      test "$direct_status" = 200
      jq -e 'type == "array" and length < 100 and
        all(.[]; type == "object")' vapi-direct-assistant-list.json >/dev/null
      jq -c --arg name "$direct_name" --arg execution "$direct_execution_id" \
        --arg owner "bridgefu-direct-web-qualification@1" \
        --arg tool "$direct_recovery_tool_id" '
        [.[] | select(.name == $name or
          .metadata.bridgefu_qualification == $execution or
          (.metadata.bridgefu_owner == $owner and
           ((.model.toolIds // null) as $tool_ids |
            (($tool_ids | type) == "array" and
             ($tool_ids | index($tool)) != null))))]' \
        vapi-direct-assistant-list.json >vapi-direct-assistant-related.json
      direct_related_count="$(jq 'length' vapi-direct-assistant-related.json)"
      test "$direct_related_count" -le 1
      if [[ "$direct_related_count" = 1 ]]; then
        direct_owned_assistant="$(jq -er '.[0].id |
          select(type == "string" and test("^[A-Za-z0-9_-]{1,128}$"))' \
          vapi-direct-assistant-related.json)"
        direct_status="$(curl --config "$direct_vapi_curl_config" \
          --silent --proto '=https' --tlsv1.2 \
          --connect-timeout 5 --max-time 20 --max-filesize 524288 \
          --output vapi-direct-assistant-match.json --write-out '%{http_code}' \
          "https://api.vapi.ai/assistant/$direct_owned_assistant")"
        test "$direct_status" = 200
        validate_remote_vapi_direct_assistant_exact \
          vapi-direct-assistant-match.json "$direct_owned_assistant" \
          vapi-direct-assistant-intent.json
        break
      fi
      [[ "$direct_attempt" = 30 ]] && break
      sleep 2
    done
    if [[ -z "$direct_owned_assistant" ]]; then
      echo 'Direct Vapi assistant intent exists but absence cannot be proven safe.' >&2
      return 2
    fi
    write_recovered_direct_assistant_ownership "$direct_region" \
      "$direct_bucket" "$direct_assistant_journal_key" \
      "$direct_owned_assistant" vapi-direct-assistant-intent.json
    load_latest_s3_object_exact "$direct_region" "$direct_bucket" \
      "$direct_assistant_journal_key" vapi-direct-assistant.json 8192
    direct_assistant_journal_present=true
    validate_vapi_direct_assistant_ownership_exact vapi-direct-assistant.json \
      vapi-direct-assistant-intent.json
  fi
  direct_recovery_assistant_id="$(jq -r .assistant_id \
    vapi-direct-assistant.json)"
}
finish_exact_direct_vapi_recovery() {
  if [[ "${direct_recovery_present:-false}" = false ]]; then
    return 0
  fi
  if [[ -n "${direct_recovery_assistant_id:-}" ]]; then
    direct_binding="$(aws secretsmanager get-secret-value \
      --region "$direct_region" --secret-id "$direct_identity_binding_arn" \
      --query SecretString --output text)"
    direct_org="$(jq -r .organization_id vapi-direct-assistant-intent.json)"
    if jq -e '(keys | sort) == ["status"] and .status == "unbound"' \
      <<<"$direct_binding" >/dev/null; then
      :
    else
      jq -e --arg assistant "$direct_recovery_assistant_id" \
        --arg org "$direct_org" '
        (keys | sort) == ["assistant_id","organization_id","status"] and
        .status == "bound" and .assistant_id == $assistant and
        .organization_id == $org' <<<"$direct_binding" >/dev/null
      aws secretsmanager put-secret-value --region "$direct_region" \
        --secret-id "$direct_identity_binding_arn" \
        --secret-string '{"status":"unbound"}' >/dev/null
      direct_binding="$(aws secretsmanager get-secret-value \
        --region "$direct_region" --secret-id "$direct_identity_binding_arn" \
        --query SecretString --output text)"
      jq -e '(keys | sort) == ["status"] and .status == "unbound"' \
        <<<"$direct_binding" >/dev/null
    fi
    unset direct_binding
    direct_status="$(curl --config "$direct_vapi_curl_config" \
      --silent --proto '=https' --tlsv1.2 \
      --connect-timeout 5 --max-time 20 --max-filesize 524288 \
      --output vapi-direct-assistant-get.json --write-out '%{http_code}' \
      "https://api.vapi.ai/assistant/$direct_recovery_assistant_id")"
    if [[ "$direct_status" = 200 ]]; then
      validate_remote_vapi_direct_assistant_exact \
        vapi-direct-assistant-get.json "$direct_recovery_assistant_id" \
        vapi-direct-assistant-intent.json
      direct_delete_status="$(curl --config "$direct_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 524288 \
        --request DELETE \
        --output vapi-direct-assistant-delete.json --write-out '%{http_code}' \
        "https://api.vapi.ai/assistant/$direct_recovery_assistant_id")"
      [[ "$direct_delete_status" =~ ^2[0-9][0-9]$ ]]
      for direct_attempt in 1 2 3 4 5 6 7 8 9 10; do
        direct_status="$(curl --config "$direct_vapi_curl_config" \
          --silent --proto '=https' --tlsv1.2 \
          --connect-timeout 5 --max-time 20 --max-filesize 524288 \
          --output vapi-direct-assistant-verify.json --write-out '%{http_code}' \
          "https://api.vapi.ai/assistant/$direct_recovery_assistant_id")"
        [[ "$direct_status" = 404 ]] && break
        test "$direct_status" = 200
        validate_remote_vapi_direct_assistant_exact \
          vapi-direct-assistant-verify.json "$direct_recovery_assistant_id" \
          vapi-direct-assistant-intent.json
        test "$direct_attempt" -lt 10
        sleep 2
      done
    fi
    test "$direct_status" = 404
    direct_name="$(jq -r .owned_name vapi-direct-assistant-intent.json)"
    direct_status="$(curl --config "$direct_vapi_curl_config" \
      --silent --proto '=https' --tlsv1.2 \
      --connect-timeout 5 --max-time 20 --max-filesize 524288 \
      --output vapi-direct-assistant-post-delete-list.json \
      --write-out '%{http_code}' \
      'https://api.vapi.ai/assistant?limit=100')"
    test "$direct_status" = 200
    jq -e 'type == "array" and length < 100 and
      all(.[]; type == "object")' \
      vapi-direct-assistant-post-delete-list.json >/dev/null
    jq -e --arg name "$direct_name" --arg execution "$direct_execution_id" \
      --arg owner "bridgefu-direct-web-qualification@1" \
      --arg tool "$direct_recovery_tool_id" '
      [.[] | select(.name == $name or
        .metadata.bridgefu_qualification == $execution or
        (.metadata.bridgefu_owner == $owner and
         ((.model.toolIds // null) as $tool_ids |
          (($tool_ids | type) == "array" and
           ($tool_ids | index($tool)) != null))))] | length == 0' \
      vapi-direct-assistant-post-delete-list.json >/dev/null
  fi
  if [[ -n "${direct_recovery_tool_id:-}" ]]; then
    direct_status="$(curl --config "$direct_vapi_curl_config" \
      --silent --proto '=https' --tlsv1.2 \
      --connect-timeout 5 --max-time 20 --max-filesize 524288 \
      --output vapi-direct-tool-get.json --write-out '%{http_code}' \
      "https://api.vapi.ai/tool/$direct_recovery_tool_id")"
    if [[ "$direct_status" = 200 ]]; then
      validate_remote_vapi_direct_tool_exact vapi-direct-tool-get.json \
        "$direct_recovery_tool_id" vapi-direct-tool-intent.json
      direct_delete_status="$(curl --config "$direct_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 524288 \
        --request DELETE \
        --output vapi-direct-tool-delete.json --write-out '%{http_code}' \
        "https://api.vapi.ai/tool/$direct_recovery_tool_id")"
      [[ "$direct_delete_status" =~ ^2[0-9][0-9]$ ]]
      for direct_attempt in 1 2 3 4 5 6 7 8 9 10; do
        direct_status="$(curl --config "$direct_vapi_curl_config" \
          --silent --proto '=https' --tlsv1.2 \
          --connect-timeout 5 --max-time 20 --max-filesize 524288 \
          --output vapi-direct-tool-verify.json --write-out '%{http_code}' \
          "https://api.vapi.ai/tool/$direct_recovery_tool_id")"
        [[ "$direct_status" = 404 ]] && break
        test "$direct_status" = 200
        validate_remote_vapi_direct_tool_exact vapi-direct-tool-verify.json \
          "$direct_recovery_tool_id" vapi-direct-tool-intent.json
        test "$direct_attempt" -lt 10
        sleep 2
      done
    fi
    test "$direct_status" = 404
    direct_status="$(curl --config "$direct_vapi_curl_config" \
      --silent --proto '=https' --tlsv1.2 \
      --connect-timeout 5 --max-time 20 --max-filesize 524288 \
      --output vapi-direct-tool-post-delete-list.json \
      --write-out '%{http_code}' 'https://api.vapi.ai/tool?limit=100')"
    test "$direct_status" = 200
    jq -e 'type == "array" and length < 100 and
      all(.[]; type == "object")' \
      vapi-direct-tool-post-delete-list.json >/dev/null
    jq -e --arg endpoint "$direct_stack_endpoint" \
      --arg credential "$direct_stack_credential" '
      [.[] | select(
        .server.url == $endpoint or
        (.server.credentialId == $credential and
         .function.name == "bridgefu_direct_handoff"))] | length == 0' \
      vapi-direct-tool-post-delete-list.json >/dev/null
  fi
}
validate_vapi_phone_intent_journal_exact() {
  intent_file="$1"
  execution_id="$2"
  region="$3"
  jq -e --arg execution_id "$execution_id" --arg region "$region" \
    --arg name "BFQ $execution_id SIP smoke" \
    '(keys | sort) == ["assistant_id","authentication_realm",
      "authentication_username","created_at","execution_id",
      "intent_sha256","owned_name","producer","redacted","region",
      "resource_type","schema_version","sip_uri"] and
     .schema_version == 1 and
     .producer == "bridgefu-vapi-phone-intent@1" and
     .execution_id == $execution_id and
     (.execution_id | test("^bfq-[a-z0-9-]{4,20}$")) and
     .region == $region and
     ($region == "us-west-2" or $region == "us-east-1") and
     .resource_type == "phone-number" and .owned_name == $name and
     .redacted == true and
     (.assistant_id | test("^[A-Za-z0-9_-]{1,128}$")) and
     .authentication_realm == "sip.vapi.ai" and
     (.authentication_username | test("^bfq_[a-f0-9]{16}$")) and
     .sip_uri == ("sip:" + .authentication_username + "@sip.vapi.ai") and
     (.intent_sha256 | test("^[0-9a-f]{64}$")) and
     (.created_at | test(
       "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$intent_file" >/dev/null
  canonical="$(jq -cS \
    '{execution_id, region, resource_type, owned_name, assistant_id,
      sip_uri, authentication_realm, authentication_username}' \
    "$intent_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .intent_sha256 "$intent_file")"
}
validate_vapi_phone_request_journal_exact() {
  request_file="$1"
  intent_file="$2"
  jq -e --argjson intent "$(jq . "$intent_file")" '
    (keys | sort) == ["attempt_state","authorized_at","execution_id",
      "intent_sha256","producer","redacted","region","request_nonce",
      "request_sha256","resource_type","schema_version"] and
    .schema_version == 1 and
    .producer == "bridgefu-vapi-phone-request@1" and
    .execution_id == $intent.execution_id and .region == $intent.region and
    .resource_type == "phone-number" and
    .resource_type == $intent.resource_type and
    .intent_sha256 == $intent.intent_sha256 and
    .attempt_state == "authorized" and .redacted == true and
    (.request_nonce | test("^[0-9a-f]{32}$")) and
    (.request_sha256 | test("^[0-9a-f]{64}$")) and
    (.authorized_at | test(
      "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$request_file" >/dev/null
  canonical="$(jq -cS '
    {execution_id, region, resource_type, intent_sha256, request_nonce,
     attempt_state}' "$request_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = "$(jq -r .request_sha256 "$request_file")"
}
validate_vapi_phone_ownership_journal_exact() {
  journal_file="$1"
  execution_id="$2"
  region="$3"
  jq -e --arg execution_id "$execution_id" --arg region "$region" \
    --arg name "BFQ $execution_id SIP smoke" \
    '(keys | sort) == ["assistant_id","created_at","execution_id",
      "owned_name","ownership_sha256","phone_id","producer",
      "redacted","region","resource_type","schema_version"] and
     .schema_version == 1 and
     .producer == "bridgefu-vapi-phone-ownership@1" and
     .execution_id == $execution_id and .region == $region and
     .resource_type == "phone-number" and .owned_name == $name and
     .redacted == true and
     (.phone_id | test("^[A-Za-z0-9_-]{1,128}$")) and
     (.assistant_id | test("^[A-Za-z0-9_-]{1,128}$")) and
     (.ownership_sha256 | test("^[0-9a-f]{64}$")) and
     (.created_at | test(
       "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))' \
    "$journal_file" >/dev/null
  canonical="$(jq -cS \
    '{execution_id, region, resource_type, phone_id, assistant_id,
      owned_name}' "$journal_file")"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = \
    "$(jq -r .ownership_sha256 "$journal_file")"
}
validate_remote_vapi_phone_exact() {
  response_file="$1"
  phone_id="$2"
  assistant_id="$3"
  name="$4"
  require_intent="$5"
  sip_uri="$6"
  authentication_realm="$7"
  authentication_username="$8"
  jq -e --arg phone_id "$phone_id" --arg assistant_id "$assistant_id" \
    --arg name "$name" --argjson require_intent "$require_intent" \
    --arg sip_uri "$sip_uri" \
    --arg authentication_realm "$authentication_realm" \
    --arg authentication_username "$authentication_username" \
    'type == "object" and .id == $phone_id and
     .provider == "vapi" and .assistantId == $assistant_id and
     .name == $name and
     (($require_intent | not) or
      (.sipUri == $sip_uri and
       ((.authentication == null) or
        ((.authentication | type) == "object" and
         ((.authentication | has("realm") | not) or
          .authentication.realm == $authentication_realm) and
         ((.authentication | has("username") | not) or
          .authentication.username == $authentication_username)))))' \
    "$response_file" >/dev/null
}
cleanup_exact_vapi_phone() {
  region="$1"
  bucket="$2"
  execution_id="$3"
  stack_name="$4"
  expected_assistant_id="${5:-}"
  journal_key="qualification/$execution_id/ownership/vapi-phone.json"
  intent_key="qualification/$execution_id/ownership/vapi-phone-intent.json"
  request_key="qualification/$execution_id/ownership/vapi-phone-request.json"
  phone_journal_present=false
  intent_journal_present=false
  request_journal_present=false
  run_strict load_latest_s3_object_exact "$region" "$bucket" \
    "$journal_key" vapi-phone-journal.json 4096
  case "$strict_status" in
    0) phone_journal_present=true ;;
    3) ;;
    *) return "$strict_status" ;;
  esac
  run_strict load_latest_s3_object_exact "$region" "$bucket" \
    "$request_key" vapi-phone-request.json 4096
  case "$strict_status" in
    0) request_journal_present=true ;;
    3) ;;
    *) return "$strict_status" ;;
  esac
  run_strict load_latest_s3_object_exact "$region" "$bucket" \
    "$intent_key" vapi-phone-intent.json 4096
  case "$strict_status" in
    0)
      intent_journal_present=true
      validate_vapi_phone_intent_journal_exact \
        vapi-phone-intent.json "$execution_id" "$region"
      ;;
    3) ;;
    *) return "$strict_status" ;;
  esac
  if [[ "$phone_journal_present" = false && \
        "$intent_journal_present" = false && \
        "$request_journal_present" = false ]]; then
    return 0
  fi
  if [[ "$request_journal_present" = true ||
        "$phone_journal_present" = true ]]; then
    test "$intent_journal_present" = true
  fi
  if [[ "$request_journal_present" = true ]]; then
    validate_vapi_phone_request_journal_exact vapi-phone-request.json \
      vapi-phone-intent.json
  fi
  if [[ "$phone_journal_present" = true ]]; then
    test "$request_journal_present" = true
  fi
  if [[ "$request_journal_present" = false ]]; then
    test "$phone_journal_present" = false
    return 0
  fi
  run_strict describe_stack_exact "$region" "$stack_name" \
    vapi-phone-stack.json
  test "$strict_status" = 0
  stack_assistant="$(jq -er '
    [.Stacks[0].Outputs[]? |
     select(.OutputKey == "VapiAssistantId") | .OutputValue] |
    select(length == 1) | .[0] |
    select(type == "string" and test("^[A-Za-z0-9_-]{1,128}$"))' \
    vapi-phone-stack.json)"
  phone_assistant="$stack_assistant"
  if [[ -n "$expected_assistant_id" ]]; then
    [[ "$expected_assistant_id" =~ ^[A-Za-z0-9_-]{1,128}$ ]]
    phone_assistant="$expected_assistant_id"
  fi
  if [[ "$intent_journal_present" = true ]]; then
    test "$phone_assistant" = \
      "$(jq -r .assistant_id vapi-phone-intent.json)"
  fi
  if [[ "$phone_journal_present" = true ]]; then
    validate_vapi_phone_ownership_journal_exact \
      vapi-phone-journal.json "$execution_id" "$region"
    test "$phone_assistant" = \
      "$(jq -r .assistant_id vapi-phone-journal.json)"
  fi
  phone_vapi_curl_config="vapi-phone-$region-curl.config"
  load_vapi_curl_config "$region" "$phone_vapi_curl_config"
  umask 077
  if [[ "$phone_journal_present" = false ]]; then
    test "$intent_journal_present" = true
    owned_name="$(jq -r .owned_name vapi-phone-intent.json)"
    sip_uri="$(jq -r .sip_uri vapi-phone-intent.json)"
    authentication_realm="$(jq -r \
      .authentication_realm vapi-phone-intent.json)"
    authentication_username="$(jq -r \
      .authentication_username vapi-phone-intent.json)"
    reconciled_phone=false
    for attempt in $(seq 1 30); do
      list_status="$(curl --config "$phone_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 262144 \
        --output vapi-phone-list-response.json \
        --write-out '%{http_code}' \
        'https://api.vapi.ai/phone-number?limit=100')"
      test "$list_status" = 200
      jq -e 'type == "array" and length < 100 and
        all(.[]; type == "object")' \
        vapi-phone-list-response.json >/dev/null
      jq -c --arg name "$owned_name" --arg sip_uri "$sip_uri" \
        --arg authentication_username "$authentication_username" \
        '[.[] | select(
          .name == $name or .sipUri == $sip_uri or
          ((.authentication | type) == "object" and
           .authentication.username == $authentication_username))]' \
        vapi-phone-list-response.json >vapi-phone-related.json
      related_count="$(jq 'length' vapi-phone-related.json)"
      test "$related_count" -le 1
      if [[ "$related_count" = 1 ]]; then
        jq -c '.[0]' vapi-phone-related.json \
          >vapi-phone-reconciled.json
        phone_id="$(jq -er '.id |
          select(type == "string" and
          test("^[A-Za-z0-9_-]{1,128}$"))' \
          vapi-phone-reconciled.json)"
        validate_remote_vapi_phone_exact \
          vapi-phone-reconciled.json "$phone_id" "$phone_assistant" \
          "$owned_name" true "$sip_uri" "$authentication_realm" \
          "$authentication_username"
        reconciled_phone=true
        break
      fi
      if [[ "$attempt" = 30 ]]; then
        echo 'Vapi phone request exists but absence cannot be proven safe.' >&2
        return 2
      fi
      sleep 2
    done
    test "$reconciled_phone" = true
    canonical="$(jq -cnS --arg execution_id "$execution_id" \
      --arg region "$region" --arg phone_id "$phone_id" \
      --arg assistant_id "$phone_assistant" --arg owned_name "$owned_name" \
      '{execution_id: $execution_id, region: $region,
        resource_type: "phone-number", phone_id: $phone_id,
        assistant_id: $assistant_id, owned_name: $owned_name}')"
    ownership_sha256="$(printf '%s' "$canonical" |
      sha256sum | awk '{print $1}')"
    created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    jq -cnS --arg execution_id "$execution_id" --arg region "$region" \
      --arg phone_id "$phone_id" --arg assistant_id "$phone_assistant" \
      --arg owned_name "$owned_name" \
      --arg ownership_sha256 "$ownership_sha256" \
      --arg created_at "$created_at" \
      '{schema_version: 1,
        producer: "bridgefu-vapi-phone-ownership@1",
        execution_id: $execution_id, region: $region,
        resource_type: "phone-number", phone_id: $phone_id,
        assistant_id: $assistant_id, owned_name: $owned_name,
        ownership_sha256: $ownership_sha256,
        created_at: $created_at, redacted: true}' \
      >vapi-phone-recovered-journal.json
    aws s3api put-object --region "$region" --bucket "$bucket" \
      --key "$journal_key" --body vapi-phone-recovered-journal.json \
      --content-type application/json --server-side-encryption AES256 \
      >/dev/null
    run_strict load_latest_s3_object_exact "$region" "$bucket" \
      "$journal_key" vapi-phone-journal.json 4096
    test "$strict_status" = 0
    phone_journal_present=true
  fi
  test "$phone_journal_present" = true
  validate_vapi_phone_ownership_journal_exact \
    vapi-phone-journal.json "$execution_id" "$region"
  test "$phone_assistant" = \
    "$(jq -r .assistant_id vapi-phone-journal.json)"
  phone_id="$(jq -r .phone_id vapi-phone-journal.json)"
  phone_url="https://api.vapi.ai/phone-number/$phone_id"
  require_intent=false
  sip_uri=""
  authentication_realm=""
  authentication_username=""
  if [[ "$intent_journal_present" = true ]]; then
    require_intent=true
    sip_uri="$(jq -r .sip_uri vapi-phone-intent.json)"
    authentication_realm="$(jq -r \
      .authentication_realm vapi-phone-intent.json)"
    authentication_username="$(jq -r \
      .authentication_username vapi-phone-intent.json)"
  fi
  status="$(curl --config "$phone_vapi_curl_config" \
    --silent --proto '=https' --tlsv1.2 \
    --connect-timeout 5 --max-time 20 --max-filesize 262144 \
    --output vapi-phone-response.json --write-out '%{http_code}' \
    "$phone_url")"
  if [[ "$status" = 200 ]]; then
    validate_remote_vapi_phone_exact vapi-phone-response.json \
      "$phone_id" "$phone_assistant" "BFQ $execution_id SIP smoke" \
      "$require_intent" "$sip_uri" "$authentication_realm" \
      "$authentication_username"
    delete_status="$(curl --config "$phone_vapi_curl_config" \
      --silent --proto '=https' \
      --tlsv1.2 --connect-timeout 5 --max-time 20 --max-filesize 262144 \
      --request DELETE \
      --output vapi-phone-delete-response.json --write-out '%{http_code}' \
      "$phone_url")"
    [[ "$delete_status" =~ ^2[0-9][0-9]$ ]]
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl --config "$phone_vapi_curl_config" \
        --silent --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 20 --max-filesize 262144 \
        --output vapi-phone-verify-response.json \
        --write-out '%{http_code}' "$phone_url")"
      [[ "$status" = 404 ]] && break
      test "$status" = 200
      validate_remote_vapi_phone_exact vapi-phone-verify-response.json \
        "$phone_id" "$phone_assistant" "BFQ $execution_id SIP smoke" \
        "$require_intent" "$sip_uri" "$authentication_realm" \
        "$authentication_username"
      test "$attempt" -lt 10
      sleep 2
    done
  fi
  test "$status" = 404
}
load_exact_acm_validation_journal() {
  region="$1"
  bucket="$2"
  execution_id="$3"
  journal_key="qualification/$execution_id/ownership/acm-validation-records.json"
  journal_listing="$(aws s3api list-object-versions --region "$region" \
    --bucket "$bucket" --prefix "$journal_key")"
  journal_version="$(jq -er --arg key "$journal_key" \
    'if ([.DeleteMarkers[]? |
          select(.Key == $key and .IsLatest == true)] | length) > 0
     then ""
     elif ([.Versions[]? |
            select(.Key == $key and .IsLatest == true)] | length) <= 1
     then ([.Versions[]? |
       select(.Key == $key and .IsLatest == true)][0].VersionId // "")
     else error("ambiguous ACM ownership journal") end' \
    <<<"$journal_listing")"
  if [[ -z "$journal_version" ]]; then
    return 1
  fi
  journal_head="$(aws s3api head-object --region "$region" \
    --bucket "$bucket" --key "$journal_key" \
    --version-id "$journal_version")"
  jq -e '(.ContentLength > 0 and .ContentLength <= 32768) and
    (.ServerSideEncryption == "AES256" or
     .ServerSideEncryption == "aws:kms")' \
    <<<"$journal_head" >/dev/null
  aws s3api get-object --region "$region" --bucket "$bucket" \
    --key "$journal_key" --version-id "$journal_version" \
    acm-validation-journal.json >/dev/null
  jq -e --arg execution_id "$execution_id" --arg region "$region" \
    --arg zone "$PUBLIC_HOSTED_ZONE_ID" --arg account "$account_id" \
    '(keys | sort) == ["certificate_arn","created_at","execution_id",
      "ownership_sha256","producer","public_hosted_zone_id","record_sets",
      "redacted","region","schema_version"] and
     .schema_version == 1 and
     .producer == "bridgefu-acm-validation-ownership@1" and
     .execution_id == $execution_id and .region == $region and
     .public_hosted_zone_id == $zone and .redacted == true and
     (.certificate_arn | startswith(
       "arn:aws:acm:" + $region + ":" + $account + ":certificate/")) and
     (.certificate_arn |
       test("^arn:aws:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f-]{36}$")) and
     (.ownership_sha256 | test("^[0-9a-f]{64}$")) and
     (.created_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) and
     (.record_sets | type == "array" and length >= 1 and length <= 8) and
     ([.record_sets[] |
       (keys | sort) == ["name","resource_records","ttl","type"] and
       .type == "CNAME" and
       (.name | type == "string" and length >= 3 and length <= 255) and
       (.ttl | type == "number" and floor == . and . >= 1 and . <= 86400) and
       (.resource_records | type == "array" and length >= 1 and length <= 8) and
       ([.resource_records[] |
         type == "string" and length >= 3 and length <= 1024] | all) and
       (.resource_records == (.resource_records | sort | unique))] | all) and
     (.record_sets == (.record_sets | sort_by(.name, .type))) and
     ([.record_sets[] | [.name, .type] | join("\u0000")] |
       length == (unique | length))' acm-validation-journal.json >/dev/null
  canonical="$(jq -cS \
    '{execution_id, region, public_hosted_zone_id, certificate_arn,
      record_sets}' acm-validation-journal.json)"
  computed_hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  test "$computed_hash" = \
    "$(jq -r .ownership_sha256 acm-validation-journal.json)"
  hosted_zone="$(aws route53 get-hosted-zone \
    --id "$PUBLIC_HOSTED_ZONE_ID")"
  zone_name="$(jq -er '.HostedZone.Name |
    select(type == "string" and endswith("."))' <<<"$hosted_zone")"
  jq -e --arg suffix "$zone_name" --arg execution_id "$execution_id" \
    '[.record_sets[].name |
      endswith($suffix) and contains($execution_id)] | all' \
    acm-validation-journal.json >/dev/null
}
discover_and_journal_exact_stack_acm_records() {
  region="$1"
  bucket="$2"
  execution_id="$3"
  stack_name="$4"
  journal_key="qualification/$execution_id/ownership/acm-validation-records.json"
  discovered_certificates='[]'
  pending_stacks="$(jq -nc --arg stack "$stack_name" '[$stack]')"
  visited_stacks='[]'
  for depth in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    : "$depth"
    [[ "$(jq 'length' <<<"$pending_stacks")" = 0 ]] && break
    stack="$(jq -r '.[0]' <<<"$pending_stacks")"
    pending_stacks="$(jq -c '.[1:]' <<<"$pending_stacks")"
    if jq -e --arg stack "$stack" 'index($stack) != null' \
      <<<"$visited_stacks" >/dev/null; then
      continue
    fi
    visited_stacks="$(jq -c --arg stack "$stack" '. + [$stack]' \
      <<<"$visited_stacks")"
    resources="$(aws cloudformation list-stack-resources \
      --region "$region" --stack-name "$stack")"
    while IFS=$'\t' read -r resource_type physical_id; do
      case "$resource_type" in
        AWS::CloudFormation::Stack)
          [[ -z "$physical_id" ]] && continue
          [[ "$physical_id" =~ ^arn:aws:cloudformation:$region:$account_id:stack/bridgefu-bfq-[A-Za-z0-9-]+/[0-9a-f-]{36}$ ]]
          pending_stacks="$(jq -c --arg stack "$physical_id" \
            '. + [$stack]' <<<"$pending_stacks")"
          ;;
        AWS::CertificateManager::Certificate)
          [[ -z "$physical_id" ]] && continue
          [[ "$physical_id" =~ ^arn:aws:acm:$region:$account_id:certificate/[0-9a-f-]{36}$ ]]
          discovered_certificates="$(jq -c --arg arn "$physical_id" \
            '. + [$arn]' <<<"$discovered_certificates")"
          ;;
      esac
    done < <(jq -r '.StackResourceSummaries[] |
      [.ResourceType, .PhysicalResourceId] | @tsv' <<<"$resources")
    test "$(jq 'length' <<<"$visited_stacks")" -le 16
    test "$(jq 'length' <<<"$pending_stacks")" -le 16
  done
  test "$(jq 'length' <<<"$pending_stacks")" = 0
  certificate_count="$(jq 'length' <<<"$discovered_certificates")"
  test "$certificate_count" -le 1
  if [[ "$certificate_count" = 0 ]]; then
    return 3
  fi
  certificate_arn="$(jq -r '.[0]' <<<"$discovered_certificates")"
  certificate_tags="$(aws acm list-tags-for-certificate \
    --region "$region" --certificate-arn "$certificate_arn")"
  exact_tag() {
    key="$1"
    expected="$2"
    tag_values="$(jq -cer --arg key "$key" '
      (.Tags // []) |
      if type == "array" then
        [.[] | select(.Key == $key) | .Value]
      else error("invalid ACM tag response") end' \
      <<<"$certificate_tags")"
    tag_count="$(jq 'length' <<<"$tag_values")"
    if [[ "$tag_count" = 0 ]]; then
      return 4
    fi
    test "$tag_count" = 1
    test "$(jq -r '.[0]' <<<"$tag_values")" = "$expected"
  }
  complete_domain_validation_options() {
    option_count="$(jq -er '
      (.Certificate.DomainValidationOptions // []) |
      if type == "array" then length
      else error("invalid ACM validation options") end' \
      <<<"$certificate")"
    test "$option_count" -le 2
    if [[ "$option_count" -lt 2 ]]; then
      return 4
    fi
    resource_record_count="$(jq -er '
      [.Certificate.DomainValidationOptions[] |
       select(.ResourceRecord != null)] | length' <<<"$certificate")"
    test "$resource_record_count" -le 2
    if [[ "$resource_record_count" -lt 2 ]]; then
      return 4
    fi
  }
  exact_tag Project bridgefu-vapi-awsconnect
  exact_tag ManagedBy bridgefu-cloudformation
  exact_tag BridgefuExecutionId "$execution_id"
  exact_tag BridgefuRecipe vapi-amazon-connect-screen-pop@1
  certificate="$(aws acm describe-certificate --region "$region" \
    --certificate-arn "$certificate_arn")"
  complete_domain_validation_options
  record_sets="$(jq -cer '
    [.Certificate.DomainValidationOptions[] |
     .ResourceRecord |
     select(. != null) |
     {name: .Name, type: .Type, ttl: 300,
      resource_records: [.Value]}] |
    group_by([.name, .type]) |
    map({name: .[0].name, type: .[0].type, ttl: .[0].ttl,
      resource_records: ([.[].resource_records[]] | sort | unique)}) |
    sort_by(.name, .type) |
    select(length >= 1 and length <= 8) |
    select([.[].type == "CNAME"] | all)' <<<"$certificate")"
  hosted_zone="$(aws route53 get-hosted-zone \
    --id "$PUBLIC_HOSTED_ZONE_ID")"
  zone_name="$(jq -er '.HostedZone.Name |
    select(type == "string" and endswith("."))' <<<"$hosted_zone")"
  jq -e --arg suffix "$zone_name" --arg execution_id "$execution_id" \
    '[.[].name | endswith($suffix) and contains($execution_id)] | all' \
    <<<"$record_sets" >/dev/null
  while read -r name; do
    owned="$(jq -cer --arg name "$name" \
      '.[] | select(.name == $name)' <<<"$record_sets")"
    listing="$(aws route53 list-resource-record-sets \
      --hosted-zone-id "$PUBLIC_HOSTED_ZONE_ID" \
      --start-record-name "$name" --start-record-type CNAME \
      --max-items 1)"
    current="$(jq -c --arg name "$name" \
      '.ResourceRecordSets[0] |
       select(.Name == $name and .Type == "CNAME") |
       {name: .Name, type: .Type, ttl: .TTL,
        resource_records: ([.ResourceRecords[].Value] | sort | unique)}' \
      <<<"$listing")"
    if [[ -z "$current" ]]; then
      continue
    fi
    test "$(jq -cS '{name, type, resource_records}' <<<"$current")" = \
      "$(jq -cS '{name, type, resource_records}' <<<"$owned")"
    record_sets="$(jq -c --arg name "$name" --argjson current "$current" \
      'map(if .name == $name then $current else . end)' \
      <<<"$record_sets")"
  done < <(jq -r '.[].name' <<<"$record_sets")
  canonical="$(jq -ncS --arg execution_id "$execution_id" \
    --arg region "$region" --arg zone "$PUBLIC_HOSTED_ZONE_ID" \
    --arg certificate_arn "$certificate_arn" \
    --argjson record_sets "$record_sets" \
    '{execution_id: $execution_id, region: $region,
      public_hosted_zone_id: $zone, certificate_arn: $certificate_arn,
      record_sets: $record_sets}')"
  ownership_sha256="$(printf '%s' "$canonical" | sha256sum |
    awk '{print $1}')"
  jq -n --argjson schema_version 1 \
    --arg producer bridgefu-acm-validation-ownership@1 \
    --arg execution_id "$execution_id" --arg region "$region" \
    --arg public_hosted_zone_id "$PUBLIC_HOSTED_ZONE_ID" \
    --arg certificate_arn "$certificate_arn" \
    --argjson record_sets "$record_sets" \
    --arg ownership_sha256 "$ownership_sha256" \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema_version: $schema_version, producer: $producer,
      execution_id: $execution_id, region: $region,
      public_hosted_zone_id: $public_hosted_zone_id,
      certificate_arn: $certificate_arn, record_sets: $record_sets,
      ownership_sha256: $ownership_sha256, created_at: $created_at,
      redacted: true}' > acm-validation-journal.json
  aws s3api put-object --region "$region" --bucket "$bucket" \
    --key "$journal_key" --body acm-validation-journal.json \
    --metadata "ownership-sha256=$ownership_sha256" >/dev/null
  load_exact_acm_validation_journal "$region" "$bucket" "$execution_id"
}
cleanup_exact_acm_validation_records() {
  changes='[]'
  while IFS= read -r encoded; do
    owned="$(printf '%s' "$encoded" | base64 --decode)"
    name="$(jq -r .name <<<"$owned")"
    listing="$(aws route53 list-resource-record-sets \
      --hosted-zone-id "$PUBLIC_HOSTED_ZONE_ID" \
      --start-record-name "$name" --start-record-type CNAME \
      --max-items 1)"
    current="$(jq -cS --arg name "$name" \
      '.ResourceRecordSets[0]? |
       select(.Name == $name and .Type == "CNAME") |
       {name: .Name, type: .Type, ttl: .TTL,
        resource_records: ([.ResourceRecords[].Value] | sort | unique)}' \
      <<<"$listing")"
    [[ -z "$current" ]] && continue
    test "$current" = "$(jq -cS . <<<"$owned")"
    aws_record="$(jq -c \
      '{Name: .name, Type: .type, TTL: .ttl,
        ResourceRecords: [.resource_records[] | {Value: .}]}' <<<"$owned")"
    changes="$(jq -c --argjson record "$aws_record" \
      '. + [{Action: "DELETE", ResourceRecordSet: $record}]' \
      <<<"$changes")"
  done < <(jq -r '.record_sets[] | @base64' \
    acm-validation-journal.json)
  if [[ "$(jq 'length' <<<"$changes")" -gt 0 ]]; then
    jq -n --argjson changes "$changes" \
      '{Comment: "Delete exact Bridgefu qualification ACM records",
        Changes: $changes}' > acm-validation-delete.json
    change_id="$(aws route53 change-resource-record-sets \
      --hosted-zone-id "$PUBLIC_HOSTED_ZONE_ID" \
      --change-batch file://acm-validation-delete.json \
      --query ChangeInfo.Id --output text)"
    [[ "$change_id" =~ ^/change/[A-Z0-9]+$ ]]
    aws route53 wait resource-record-sets-changed --id "$change_id"
  fi
  while read -r name; do
    listing="$(aws route53 list-resource-record-sets \
      --hosted-zone-id "$PUBLIC_HOSTED_ZONE_ID" \
      --start-record-name "$name" --start-record-type CNAME \
      --max-items 1)"
    jq -e --arg name "$name" \
      '[.ResourceRecordSets[]? |
        select(.Name == $name and .Type == "CNAME")] | length == 0' \
      <<<"$listing" >/dev/null
  done < <(jq -r '.record_sets[].name' acm-validation-journal.json)
}
for pair in us-west-2:w us-east-1:e; do
  region="${pair%%:*}"
  short_region="${pair##*:}"
  execution_id="bfq-${short_region}-${SOURCE_RUN_ID}-${SOURCE_RUN_ATTEMPT}"
  stack_name="bridgefu-$execution_id"
  bucket="bridgefu-vapi-awsconnect-$account_id-$region"
  prepare_exact_direct_vapi_recovery "$region" "$bucket" "$execution_id" \
    "$stack_name"
  cleanup_exact_vapi_phone "$region" "$bucket" "$execution_id" \
    "$stack_name" "${direct_recovery_assistant_id:-}"
  finish_exact_direct_vapi_recovery
  acm_journal_present=false
  run_strict load_exact_acm_validation_journal "$region" "$bucket" \
    "$execution_id"
  case "$strict_status" in
    0) acm_journal_present=true ;;
    1) ;;
    *) exit "$strict_status" ;;
  esac
  run_strict describe_stack_exact "$region" "$stack_name" \
    "stack-$short_region.json"
  case "$strict_status" in
    0) stack_present=true ;;
    3) stack_present=false ;;
    *) exit "$strict_status" ;;
  esac
  if [[ "$stack_present" = true ]]; then
    if [[ "$acm_journal_present" = false ]]; then
      for attempt in $(seq 1 180); do
        run_strict discover_and_journal_exact_stack_acm_records \
          "$region" "$bucket" "$execution_id" "$stack_name"
        if [[ "$strict_status" = 0 ]]; then
          acm_journal_present=true
          break
        fi
        case "$strict_status" in
          3|4) ;;
          *) exit "$strict_status" ;;
        esac
        run_strict describe_stack_exact "$region" "$stack_name" \
          "stack-$short_region.json"
        test "$strict_status" = 0
        stack_status="$(jq -er '.Stacks[0].StackStatus |
          select(type == "string")' "stack-$short_region.json")"
        case "$stack_status" in
          CREATE_IN_PROGRESS|REVIEW_IN_PROGRESS)
            test "$attempt" -lt 180
            sleep 10
            ;;
          CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|DELETE_FAILED)
            test "$strict_status" = 3
            break
            ;;
          *)
            echo 'Zero-certificate stack status is not an authorized cleanup state.' >&2
            exit 1
            ;;
        esac
      done
    fi
    aws cloudformation delete-stack --region "$region" \
      --stack-name "$stack_name"
    aws cloudformation wait stack-delete-complete --region "$region" \
      --stack-name "$stack_name"
  fi
  if [[ "$acm_journal_present" = true ]]; then
    cleanup_exact_acm_validation_records
  fi
  delete_prefix_versions "$region" "$bucket" \
    "qualification/$execution_id/"
done
