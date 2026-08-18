"""Fail-closed review of an exact nested CloudFormation CREATE change set.

The release controller supplies a catalog that was already sealed, downloaded,
hashed, and remotely validated.  This module proves that CloudFormation planned
that exact ten-template catalog before the controller executes the root change
set.  Exact AWS identities are returned only in memory; retained proof is a
bounded collection of counts and SHA-256 digests.

CloudFormation does not return ``ChangeSetType`` from ``DescribeChangeSet``.
Consequently, callers must bind the literal ``CREATE`` used in their
``CreateChangeSet`` request.  The returned root ``StackId`` and its
``REVIEW_IN_PROGRESS`` status independently prove that this is a new-stack
review rather than an update to an existing stack.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import yaml


class DeploymentReviewError(RuntimeError):
    """The proposed CloudFormation deployment cannot be proven exact."""


PRODUCER = "bridgefu-cloudformation-deployment-review@1"
CATALOG_SIZE = 10
MAX_TEMPLATE_BYTES = 1_048_576
MAX_TEMPLATE_NODES = 50_000
MAX_TEMPLATE_DEPTH = 64
MAX_CHANGE_RECORDS = 2_000
MAX_HIERARCHY_DEPTH = 8

_CHANGE_SET_ARN = re.compile(
    r"^arn:aws:cloudformation:(us-(?:east|west)-[1-9][0-9]*):([0-9]{12}):"
    r"changeSet/[^/]{1,128}/[A-Za-z0-9-]{1,128}$"
)
_STACK_ARN = re.compile(
    r"^arn:aws:cloudformation:(us-(?:east|west)-[1-9][0-9]*):([0-9]{12}):"
    r"stack/[^/]{1,128}/[A-Za-z0-9-]{1,128}$"
)
_VERSION_ID = re.compile(r"^[A-Za-z0-9._+/=-]{1,1024}$")
_S3_HOST = re.compile(
    r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.us-east-1\.amazonaws\.com$"
)

_CFN_TAGS = {
    "And": "Fn::And",
    "Base64": "Fn::Base64",
    "Cidr": "Fn::Cidr",
    "Condition": "Condition",
    "Contains": "Fn::Contains",
    "Equals": "Fn::Equals",
    "FindInMap": "Fn::FindInMap",
    "ForEach": "Fn::ForEach",
    "GetAtt": "Fn::GetAtt",
    "GetAZs": "Fn::GetAZs",
    "If": "Fn::If",
    "ImportValue": "Fn::ImportValue",
    "Join": "Fn::Join",
    "Length": "Fn::Length",
    "Not": "Fn::Not",
    "Or": "Fn::Or",
    "Ref": "Ref",
    "Select": "Fn::Select",
    "Split": "Fn::Split",
    "Sub": "Fn::Sub",
    "ToJsonString": "Fn::ToJsonString",
    "Transform": "Fn::Transform",
}


@dataclass(frozen=True)
class SealedTemplate:
    """One exact versioned URL and its already sealed semantic template."""

    url: str
    parsed_template: Mapping[str, Any]


@dataclass(frozen=True)
class DeploymentReview:
    """Successful review; exact identities remain only in this in-memory value."""

    root_change_set_arn: str
    root_stack_id: str
    proof: Mapping[str, Any]
    change_set_arns: tuple[str, ...] = ()
    stack_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RootInvocation:
    """Exact non-template inputs supplied to the root CreateChangeSet call."""

    change_set_name: str
    stack_name: str
    parameters: tuple[tuple[str, str], ...]
    role_arn: str
    capabilities: tuple[str, ...]
    tags: tuple[tuple[str, str], ...]
    on_stack_failure: str
    include_nested_stacks: bool = True
    notification_arns: tuple[str, ...] = ()
    import_existing_resources: bool = False


class _CloudFormationLoader(yaml.SafeLoader):
    """Safe YAML loader with CloudFormation's short-form intrinsic functions."""


def _construct_cfn_tag(
    loader: _CloudFormationLoader, tag_suffix: str, node: yaml.Node
) -> Mapping[str, Any]:
    key = _CFN_TAGS.get(tag_suffix)
    if key is None:
        raise DeploymentReviewError("template contains an unsupported YAML tag")
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
        if tag_suffix == "GetAtt":
            parts = value.split(".", 1)
            if len(parts) != 2 or not all(parts):
                raise DeploymentReviewError("template contains an invalid GetAtt")
            value = parts
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:  # pragma: no cover - PyYAML exposes only the three node types above.
        raise DeploymentReviewError("template contains an invalid YAML node")
    return {key: value}


_CloudFormationLoader.add_multi_constructor("!", _construct_cfn_tag)


def _normalize_template(value: Any) -> Any:
    """Return a bounded JSON-compatible representation for semantic comparison."""
    nodes = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_TEMPLATE_NODES or depth > MAX_TEMPLATE_DEPTH:
            raise DeploymentReviewError("template semantic structure exceeds bounds")
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, nested in item.items():
                if not isinstance(key, str) or key in result:
                    raise DeploymentReviewError(
                        "template contains an invalid mapping key"
                    )
                result[key] = visit(nested, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [visit(nested, depth + 1) for nested in item]
        if item is None or isinstance(item, (str, bool, int)):
            return item
        if isinstance(item, float) and math.isfinite(item):
            return item
        raise DeploymentReviewError("template contains a non-JSON semantic value")

    normalized = visit(value, 0)
    if not isinstance(normalized, dict):
        raise DeploymentReviewError("CloudFormation template must be a mapping")
    return normalized


def parse_template_body(value: str | Mapping[str, Any]) -> dict[str, Any]:
    """Parse a JSON/YAML CloudFormation body into canonical semantic data."""
    if isinstance(value, str):
        if not value or len(value.encode("utf-8")) > MAX_TEMPLATE_BYTES:
            raise DeploymentReviewError("template body size is invalid")
        try:
            parsed = yaml.load(value, Loader=_CloudFormationLoader)  # noqa: S506
        except DeploymentReviewError:
            raise
        except yaml.YAMLError as error:
            raise DeploymentReviewError(
                "template body is not valid YAML or JSON"
            ) from error
    elif isinstance(value, Mapping):
        parsed = value
    else:
        raise DeploymentReviewError("template body has an invalid type")
    return _normalize_template(parsed)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _bounded_pairs(
    values: Any, *, label: str, key_pattern: str, maximum: int
) -> list[dict[str, str]]:
    if not isinstance(values, tuple) or not 1 <= len(values) <= maximum:
        raise DeploymentReviewError(f"root {label} contract is invalid")
    normalized: dict[str, str] = {}
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise DeploymentReviewError(f"root {label} contract is invalid")
        key, value = item
        if (
            not isinstance(key, str)
            or re.fullmatch(key_pattern, key) is None
            or not isinstance(value, str)
            or not 1 <= len(value.encode("utf-8")) <= 4_096
            or re.search(r"[\x00-\x1f\x7f]", value)
            or key in normalized
        ):
            raise DeploymentReviewError(f"root {label} contract is invalid")
        normalized[key] = value
    return [{"key": key, "value": normalized[key]} for key in sorted(normalized)]


def _root_invocation_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, RootInvocation):
        raise DeploymentReviewError("root invocation contract is invalid")
    if (
        re.fullmatch(r"[A-Za-z][-A-Za-z0-9]{0,127}", value.change_set_name) is None
        or re.fullmatch(r"[A-Za-z][-A-Za-z0-9]{0,127}", value.stack_name) is None
        or re.fullmatch(
            r"arn:aws[-a-z0-9]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}",
            value.role_arn,
        )
        is None
        or value.on_stack_failure not in {"DO_NOTHING", "DELETE", "ROLLBACK"}
        or value.include_nested_stacks is not True
        or value.import_existing_resources is not False
        or not isinstance(value.notification_arns, tuple)
        or value.notification_arns
        or not isinstance(value.capabilities, tuple)
        or any(not isinstance(item, str) for item in value.capabilities)
        or len(value.capabilities) != len(set(value.capabilities))
        or set(value.capabilities) != {"CAPABILITY_NAMED_IAM"}
    ):
        raise DeploymentReviewError("root invocation contract is invalid")
    return {
        "change_set_name": value.change_set_name,
        "stack_name": value.stack_name,
        "parameters": _bounded_pairs(
            value.parameters,
            label="parameter",
            key_pattern=r"[A-Za-z0-9]{1,255}",
            maximum=200,
        ),
        "role_arn": value.role_arn,
        "capabilities": sorted(value.capabilities),
        "tags": _bounded_pairs(
            value.tags,
            label="tag",
            key_pattern=r"[A-Za-z0-9+\-=._:/@ ]{1,128}",
            maximum=50,
        ),
        "on_stack_failure": value.on_stack_failure,
        "include_nested_stacks": True,
        "notification_arns": [],
        "import_existing_resources": False,
    }


def _actual_pairs(
    values: Any,
    *,
    label: str,
    key_field: str,
    value_field: str,
    optional_fields: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    if not isinstance(values, list) or len(values) > 200:
        raise DeploymentReviewError(f"root change-set {label} are invalid")
    normalized: dict[str, str] = {}
    required = {key_field, value_field}
    for item in values:
        if (
            not isinstance(item, Mapping)
            or not required <= set(item)
            or not set(item) <= required | optional_fields
        ):
            raise DeploymentReviewError(f"root change-set {label} are invalid")
        key = item.get(key_field)
        nested = item.get(value_field)
        if not isinstance(key, str) or not isinstance(nested, str) or key in normalized:
            raise DeploymentReviewError(f"root change-set {label} are invalid")
        normalized[key] = nested
    return [{"key": key, "value": normalized[key]} for key in sorted(normalized)]


def _verify_root_invocation(
    description: Mapping[str, Any],
    stack: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> None:
    parameters = _actual_pairs(
        description.get("Parameters"),
        label="parameters",
        key_field="ParameterKey",
        value_field="ParameterValue",
        optional_fields=frozenset({"ResolvedValue"}),
    )
    tags = _actual_pairs(
        description.get("Tags"),
        label="tags",
        key_field="Key",
        value_field="Value",
    )
    capabilities = description.get("Capabilities")
    notification_arns = description.get("NotificationARNs", [])
    rollback = description.get("RollbackConfiguration", {})
    rollback_is_empty = rollback in ({}, None) or rollback == {
        "RollbackTriggers": [],
        "MonitoringTimeInMinutes": 0,
    }
    if (
        description.get("ChangeSetName") != expected["change_set_name"]
        or description.get("StackName") != expected["stack_name"]
        or parameters != expected["parameters"]
        # DescribeChangeSet does not expose RoleARN; the exact associated
        # REVIEW_IN_PROGRESS stack does.
        or stack.get("RoleARN") != expected["role_arn"]
        or not isinstance(capabilities, list)
        or any(not isinstance(item, str) for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or sorted(capabilities) != expected["capabilities"]
        or tags != expected["tags"]
        or description.get("OnStackFailure") != expected["on_stack_failure"]
        or description.get("IncludeNestedStacks") != expected["include_nested_stacks"]
        or notification_arns != expected["notification_arns"]
        # AWS currently serializes an omitted false ImportExistingResources
        # request as JSON null in DescribeChangeSet.  Bind the only two
        # semantically false service-model shapes and continue rejecting true
        # or any other value.
        or (
            description.get("ImportExistingResources") is not None
            and description.get("ImportExistingResources") is not False
        )
        or expected["import_existing_resources"] is not False
        or not rollback_is_empty
        or description.get("Description") not in (None, "")
    ):
        raise DeploymentReviewError("root change-set invocation differs from request")


def _template_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise DeploymentReviewError("sealed template URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    try:
        query = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError as error:
        raise DeploymentReviewError("sealed template URL is invalid") from error
    if (
        parsed.scheme != "https"
        or _S3_HOST.fullmatch(parsed.netloc) is None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or len(query) != 1
        or query[0][0] != "versionId"
        or _VERSION_ID.fullmatch(query[0][1]) is None
    ):
        raise DeploymentReviewError("sealed template URL is invalid")
    # Reject alternate encodings or query ordering.  The reviewer compares the
    # literal TemplateURL from the proposed template with this exact string.
    if urllib.parse.urlunsplit(parsed) != value:
        raise DeploymentReviewError("sealed template URL is invalid")
    return value


def _change_set_identity(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise DeploymentReviewError("change-set identity is invalid")
    match = _CHANGE_SET_ARN.fullmatch(value)
    if match is None:
        raise DeploymentReviewError("change-set identity is invalid")
    return match.group(1), match.group(2)


def _stack_identity(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise DeploymentReviewError("stack identity is invalid")
    match = _STACK_ARN.fullmatch(value)
    if match is None:
        raise DeploymentReviewError("stack identity is invalid")
    return match.group(1), match.group(2)


def _aws_json(aws: Any, arguments: list[str]) -> Mapping[str, Any]:
    value = aws.json(arguments, timeout=180)
    if not isinstance(value, Mapping):
        raise DeploymentReviewError("AWS returned invalid deployment review data")
    return value


def _describe_change_set(aws: Any, change_set_arn: str) -> Mapping[str, Any]:
    result = _aws_json(
        aws,
        [
            "cloudformation",
            "describe-change-set",
            "--change-set-name",
            change_set_arn,
        ],
    )
    if result.get("NextToken") not in (None, ""):
        raise DeploymentReviewError("change-set review exceeds pagination bounds")
    changes = result.get("Changes")
    if not isinstance(changes, list) or len(changes) > MAX_CHANGE_RECORDS:
        raise DeploymentReviewError("change-set resource inventory is invalid")
    return result


def _get_original_template(aws: Any, change_set_arn: str) -> dict[str, Any]:
    result = _aws_json(
        aws,
        [
            "cloudformation",
            "get-template",
            "--change-set-name",
            change_set_arn,
            "--template-stage",
            "Original",
        ],
    )
    stages = result.get("StagesAvailable")
    if (
        set(result) != {"TemplateBody", "StagesAvailable"}
        or not isinstance(stages, list)
        or not 1 <= len(stages) <= 2
        or len(stages) != len(set(stages))
        or "Original" not in stages
        or not set(stages) <= {"Original", "Processed"}
    ):
        raise DeploymentReviewError("GetTemplate returned an invalid response")
    return parse_template_body(result["TemplateBody"])


def _describe_review_stack(
    aws: Any,
    stack_id: str,
    *,
    expected_parent_stack_id: str | None,
    root_stack_id: str,
) -> Mapping[str, Any]:
    result = _aws_json(
        aws,
        ["cloudformation", "describe-stacks", "--stack-name", stack_id],
    )
    stacks = result.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1:
        raise DeploymentReviewError("CREATE review stack identity is ambiguous")
    stack = stacks[0]
    if not isinstance(stack, Mapping):
        raise DeploymentReviewError("CREATE review stack data is invalid")
    if (
        stack.get("StackId") != stack_id
        or stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
    ):
        raise DeploymentReviewError("stack is not an exact CREATE review stack")
    if expected_parent_stack_id is None:
        if stack.get("ParentId") not in (None, "") or stack.get("RootId") not in (
            None,
            "",
        ):
            raise DeploymentReviewError("root CREATE review stack linkage is invalid")
    elif (
        stack.get("ParentId") != expected_parent_stack_id
        or stack.get("RootId") != root_stack_id
    ):
        raise DeploymentReviewError("nested CREATE review stack linkage is invalid")
    return stack


def _nested_template_urls(template: Mapping[str, Any]) -> dict[str, str]:
    resources = template.get("Resources")
    if not isinstance(resources, Mapping):
        raise DeploymentReviewError("template resource inventory is invalid")
    nested: dict[str, str] = {}
    for logical_id, resource in resources.items():
        if not isinstance(logical_id, str) or not isinstance(resource, Mapping):
            raise DeploymentReviewError("template resource inventory is invalid")
        if resource.get("Type") != "AWS::CloudFormation::Stack":
            continue
        properties = resource.get("Properties")
        template_url = (
            properties.get("TemplateURL") if isinstance(properties, Mapping) else None
        )
        if not isinstance(template_url, str):
            raise DeploymentReviewError("nested-stack TemplateURL must be literal")
        nested[logical_id] = template_url
    return nested


def _nested_change_sets(
    description: Mapping[str, Any], nested_urls: Mapping[str, str]
) -> dict[str, tuple[str, str | None]]:
    changes = description.get("Changes")
    if not isinstance(changes, list):
        raise DeploymentReviewError("change-set resource inventory is invalid")
    selected: dict[str, tuple[str, str | None]] = {}
    for item in changes:
        if not isinstance(item, Mapping) or item.get("Type") != "Resource":
            raise DeploymentReviewError("change-set resource inventory is invalid")
        change = item.get("ResourceChange")
        if not isinstance(change, Mapping):
            raise DeploymentReviewError("change-set resource inventory is invalid")
        if change.get("Action") != "Add":
            raise DeploymentReviewError("CREATE change set contains a non-Add action")
        logical_id = change.get("LogicalResourceId")
        resource_type = change.get("ResourceType")
        if not isinstance(logical_id, str) or not isinstance(resource_type, str):
            raise DeploymentReviewError("change-set resource identity is invalid")
        if logical_id not in nested_urls:
            if resource_type == "AWS::CloudFormation::Stack" or change.get(
                "ChangeSetId"
            ) not in (None, ""):
                raise DeploymentReviewError(
                    "change set contains an orphan nested-stack edge"
                )
            continue
        if resource_type != "AWS::CloudFormation::Stack" or logical_id in selected:
            raise DeploymentReviewError("nested-stack resource change is ambiguous")
        child = change.get("ChangeSetId")
        _change_set_identity(child)
        physical = change.get("PhysicalResourceId")
        if physical is not None and not isinstance(physical, str):
            raise DeploymentReviewError("nested-stack physical identity is invalid")
        selected[logical_id] = (child, physical)
    if set(selected) != set(nested_urls):
        raise DeploymentReviewError("nested stack is missing its child ChangeSetId")
    child_ids = [child_id for child_id, _ in selected.values()]
    if len(child_ids) != len(set(child_ids)):
        raise DeploymentReviewError("nested child ChangeSetId is duplicated")
    return selected


def review_create_change_set(
    *,
    aws: Any,
    root_change_set_arn: str,
    root_stack_id: str,
    root_template_url: str,
    sealed_catalog: Sequence[SealedTemplate],
    expected_change_set_type: str,
    expected_region: str,
    expected_account_id: str,
    expected_root_invocation: RootInvocation,
) -> DeploymentReview:
    """Review a ten-template CREATE hierarchy before any execution mutation.

    ``aws`` is injectable and needs only a ``json(arguments, timeout=...)``
    method, matching the qualification controller's AWS adapter.
    """
    if expected_change_set_type != "CREATE":
        raise DeploymentReviewError("deployment review is restricted to CREATE")
    if (
        expected_region not in {"us-west-2", "us-east-1"}
        or re.fullmatch(r"[0-9]{12}", expected_account_id) is None
    ):
        raise DeploymentReviewError("expected AWS deployment coordinates are invalid")
    root_change_identity = _change_set_identity(root_change_set_arn)
    root_stack_identity = _stack_identity(root_stack_id)
    expected_identity = (expected_region, expected_account_id)
    if (
        root_change_identity != expected_identity
        or root_stack_identity != expected_identity
    ):
        raise DeploymentReviewError("root change-set and stack identities differ")
    root_template_url = _template_url(root_template_url)
    root_invocation = _root_invocation_contract(expected_root_invocation)

    if not isinstance(sealed_catalog, Sequence) or len(sealed_catalog) != CATALOG_SIZE:
        raise DeploymentReviewError("sealed catalog must contain exactly ten templates")
    catalog: dict[str, dict[str, Any]] = {}
    for record in sealed_catalog:
        if not isinstance(record, SealedTemplate):
            raise DeploymentReviewError("sealed catalog record is invalid")
        url = _template_url(record.url)
        if url in catalog:
            raise DeploymentReviewError("sealed catalog contains a duplicate template")
        catalog[url] = _normalize_template(record.parsed_template)
    if root_template_url not in catalog:
        raise DeploymentReviewError("root template is missing from sealed catalog")

    root_stack_description = _describe_review_stack(
        aws,
        root_stack_id,
        expected_parent_stack_id=None,
        root_stack_id=root_stack_id,
    )

    queue: list[tuple[str, str, str, str | None, int]] = [
        (root_change_set_arn, root_stack_id, root_template_url, None, 0)
    ]
    traversed_urls: set[str] = set()
    traversed_change_sets: set[str] = set()
    traversed_stacks: set[str] = set()
    hierarchy: list[dict[str, Any]] = []

    while queue:
        change_set_arn, stack_id, template_url, parent_change_set_arn, depth = (
            queue.pop(0)
        )
        if depth > MAX_HIERARCHY_DEPTH:
            raise DeploymentReviewError("nested change-set hierarchy exceeds bounds")
        if (
            template_url in traversed_urls
            or change_set_arn in traversed_change_sets
            or stack_id in traversed_stacks
        ):
            raise DeploymentReviewError("nested change-set hierarchy is duplicated")
        if template_url not in catalog:
            raise DeploymentReviewError("change set references an unsealed template")
        change_identity = _change_set_identity(change_set_arn)
        stack_identity = _stack_identity(stack_id)
        if (
            change_identity != root_change_identity
            or stack_identity != root_stack_identity
        ):
            raise DeploymentReviewError("nested AWS identity differs from root")

        description = _describe_change_set(aws, change_set_arn)
        if (
            description.get("ChangeSetId") != change_set_arn
            or description.get("StackId") != stack_id
            or description.get("Status") != "CREATE_COMPLETE"
            or description.get("IncludeNestedStacks") is not True
        ):
            raise DeploymentReviewError("change-set identity or status is invalid")
        if parent_change_set_arn is None:
            if (
                description.get("ExecutionStatus") != "AVAILABLE"
                or description.get("ParentChangeSetId") not in (None, "")
                or description.get("RootChangeSetId") not in (None, "")
            ):
                raise DeploymentReviewError("root change-set linkage is invalid")
            _verify_root_invocation(
                description, root_stack_description, root_invocation
            )
        elif (
            description.get("ExecutionStatus") != "UNAVAILABLE"
            or description.get("ParentChangeSetId") != parent_change_set_arn
            or description.get("RootChangeSetId") != root_change_set_arn
        ):
            raise DeploymentReviewError("nested change-set linkage is invalid")

        proposed = _get_original_template(aws, change_set_arn)
        if proposed != catalog[template_url]:
            raise DeploymentReviewError(
                "CloudFormation template differs from sealed catalog"
            )
        nested_urls = _nested_template_urls(proposed)
        nested_changes = _nested_change_sets(description, nested_urls)

        traversed_urls.add(template_url)
        traversed_change_sets.add(change_set_arn)
        traversed_stacks.add(stack_id)
        hierarchy.append(
            {
                "change_set": change_set_arn,
                "stack": stack_id,
                "template_url": template_url,
                "parent": parent_change_set_arn,
                "depth": depth,
            }
        )

        for logical_id in sorted(nested_urls):
            child_url = nested_urls[logical_id]
            if child_url not in catalog:
                raise DeploymentReviewError(
                    "nested stack references an unsealed template"
                )
            child_change_set_arn, physical_stack_id = nested_changes[logical_id]
            child_description = _describe_change_set(aws, child_change_set_arn)
            child_stack_id = child_description.get("StackId")
            _stack_identity(child_stack_id)
            if (
                physical_stack_id not in (None, "")
                and physical_stack_id != child_stack_id
            ):
                raise DeploymentReviewError("nested stack physical linkage is invalid")
            _describe_review_stack(
                aws,
                child_stack_id,
                expected_parent_stack_id=stack_id,
                root_stack_id=root_stack_id,
            )
            # The queued pass describes the child again by the same full ARN.
            # This deliberate re-read closes the mutation window between the
            # parent edge review and the child's own template review.
            queue.append(
                (
                    child_change_set_arn,
                    child_stack_id,
                    child_url,
                    change_set_arn,
                    depth + 1,
                )
            )

    if traversed_urls != set(catalog) or len(hierarchy) != CATALOG_SIZE:
        raise DeploymentReviewError("sealed template catalog is missing or orphaned")

    catalog_digest = _canonical_sha256(
        [{"url": url, "template": catalog[url]} for url in sorted(catalog)]
    )
    hierarchy_digest = _canonical_sha256(
        sorted(hierarchy, key=lambda item: item["template_url"])
    )
    proof = {
        "producer": PRODUCER,
        "version": 1,
        "result": "pass",
        "change_set_type": "CREATE",
        "template_count": CATALOG_SIZE,
        "nested_change_set_count": CATALOG_SIZE - 1,
        "max_depth": max(item["depth"] for item in hierarchy),
        "catalog_sha256": catalog_digest,
        "hierarchy_sha256": hierarchy_digest,
        "root_invocation_sha256": _canonical_sha256(root_invocation),
        "root_change_set_fingerprint": _fingerprint(root_change_set_arn),
        "root_stack_fingerprint": _fingerprint(root_stack_id),
    }
    if len(json.dumps(proof, separators=(",", ":"))) > 1_024:
        raise DeploymentReviewError("deployment review proof exceeds bounds")
    return DeploymentReview(
        root_change_set_arn=root_change_set_arn,
        root_stack_id=root_stack_id,
        proof=proof,
        change_set_arns=tuple(sorted(traversed_change_sets)),
        stack_ids=tuple(sorted(traversed_stacks)),
    )
