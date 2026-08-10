"""CloudFormation validation and Connect rendering for one deployment."""

from __future__ import annotations

import html
import json
import os
import re
import urllib.error
import urllib.request

from screen_pop import parse_fields, schema_hash

FLOW_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z0-9-]+)?):connect:(?P<region>[a-z0-9-]+):"
    r"(?P<account>[0-9]{12}):instance/(?P<instance>[A-Za-z0-9-]+)/"
    r"contact-flow/(?P<flow>[A-Za-z0-9-]+)$"
)
INSTANCE_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z0-9-]+)?):connect:(?P<region>[a-z0-9-]+):"
    r"(?P<account>[0-9]{12}):instance/(?P<instance>[A-Za-z0-9-]+)$"
)


class ConfigurationError(Exception):
    """Bounded error safe to return to CloudFormation."""


def _send(event, status, physical_id, data, reason):
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason[:512],
            "PhysicalResourceId": physical_id,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": False,
            "Data": data,
        },
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    with urllib.request.urlopen(request, timeout=6) as response:
        response.read(1024)


def _routing(value, fields, instance_arn, region, account, connect):
    if value in (None, "", "{}"):
        return "", "transfer-to-customer-flow", "", ""
    try:
        routing = json.loads(value)
    except json.JSONDecodeError:
        raise ConfigurationError("routing_json_invalid") from None
    if not isinstance(routing, dict) or set(routing) != {"fieldKey", "routes"}:
        raise ConfigurationError("routing_shape_invalid")
    key = routing["fieldKey"]
    field = next((item for item in fields if item.key == key), None)
    if field is None or field.field_type != "choice":
        raise ConfigurationError("routing_field_must_be_choice")
    routes = routing["routes"]
    if not isinstance(routes, list) or not 1 <= len(routes) <= 20:
        raise ConfigurationError("routing_routes_invalid")
    seen = set()
    conditions = []
    actions = []
    for index, route in enumerate(routes, 1):
        if not isinstance(route, dict) or set(route) != {"value", "contactFlowArn"}:
            raise ConfigurationError("routing_route_invalid")
        choice = route["value"]
        if choice not in field.choices or choice in seen:
            raise ConfigurationError("routing_value_invalid")
        seen.add(choice)
        match = FLOW_ARN.fullmatch(route["contactFlowArn"])
        if (
            match is None
            or match["region"] != region
            or match["account"] != account
            or not route["contactFlowArn"].startswith(instance_arn + "/")
        ):
            raise ConfigurationError("routing_flow_scope_invalid")
        described = connect.describe_contact_flow(
            InstanceId=match["instance"], ContactFlowId=match["flow"]
        )["ContactFlow"]
        if described.get("State") != "ACTIVE":
            raise ConfigurationError("routing_flow_not_published")
        action_id = f"transfer-to-route-{index}"
        conditions.append(
            {
                "NextAction": action_id,
                "Condition": {"Operator": "Equals", "Operands": [choice]},
            }
        )
        actions.append(
            {
                "Identifier": action_id,
                "Type": "TransferToFlow",
                "Parameters": {"ContactFlowId": route["contactFlowArn"]},
                "Transitions": {
                    "NextAction": "disconnect",
                    "Errors": [
                        {
                            "NextAction": "transfer-to-customer-flow",
                            "ErrorType": "NoMatchingError",
                        }
                    ],
                },
            }
        )
    decision = {
        "Identifier": "choose-reviewed-route",
        "Type": "Compare",
        "Parameters": {"ComparisonValue": "$.Attributes.bridgefu_routing_value"},
        "Transitions": {
            "NextAction": "transfer-to-customer-flow",
            "Conditions": conditions,
            "Errors": [
                {
                    "NextAction": "transfer-to-customer-flow",
                    "ErrorType": "NoMatchingCondition",
                }
            ],
        },
    }
    decision_json = "," + json.dumps(decision, separators=(",", ":"))
    actions_json = "," + ",".join(
        json.dumps(item, separators=(",", ":")) for item in actions
    )
    if len(decision_json) > 4096 or len(actions_json) > 4096:
        raise ConfigurationError("routing_render_too_large")
    return key, "choose-reviewed-route", decision_json, actions_json


def render(properties, *, boto3_module=None):
    try:
        fields = parse_fields(properties["ScreenPopFieldsJson"])
    except Exception:
        raise ConfigurationError("screen_pop_fields_invalid") from None
    instance_match = INSTANCE_ARN.fullmatch(properties["ConnectInstanceArn"])
    flow_match = FLOW_ARN.fullmatch(properties["TargetContactFlowArn"])
    if instance_match is None or flow_match is None:
        raise ConfigurationError("connect_arn_invalid")
    region = os.environ.get("AWS_REGION", "")
    account = properties["AccountId"]
    if (
        instance_match["region"] != region
        or flow_match["region"] != region
        or instance_match["account"] != account
        or flow_match["account"] != account
        or instance_match["instance"] != flow_match["instance"]
    ):
        raise ConfigurationError("connect_arn_scope_invalid")

    if boto3_module is None:
        import boto3 as boto3_module

    connect = boto3_module.client("connect")
    route53 = boto3_module.client("route53")
    instance = connect.describe_instance(InstanceId=instance_match["instance"])[
        "Instance"
    ]
    if instance.get("InstanceStatus") != "ACTIVE":
        raise ConfigurationError("connect_instance_not_active")
    flow = connect.describe_contact_flow(
        InstanceId=flow_match["instance"], ContactFlowId=flow_match["flow"]
    )["ContactFlow"]
    if flow.get("State") != "ACTIVE":
        raise ConfigurationError("target_flow_not_published")
    zone = route53.get_hosted_zone(Id=properties["PublicHostedZoneId"])["HostedZone"]
    if zone.get("Config", {}).get("PrivateZone") is not False:
        raise ConfigurationError("hosted_zone_not_public")
    zone_name = zone["Name"].rstrip(".").lower()
    hostname = properties["SipHostname"].rstrip(".").lower()
    if hostname == zone_name or not hostname.endswith("." + zone_name):
        raise ConfigurationError("sip_hostname_outside_zone")

    routing_key, next_action, decision_action, transfer_actions = _routing(
        properties.get("RoutingJson"),
        fields,
        properties["ConnectInstanceArn"],
        region,
        account,
        connect,
    )
    rows = "".join(
        "<p><strong>$.Attributes.screen_pop_label_"
        f"{index}:</strong> $.Attributes.screen_pop_value_{index}</p>"
        for index, _field in enumerate(fields, 1)
    )
    if len(rows) > 4096:
        raise ConfigurationError("agent_guide_too_large")
    return {
        "AgentGuideTemplateString": rows,
        "RoutingFieldKey": routing_key,
        "RoutingNextAction": next_action,
        "RoutingDecisionActionJson": decision_action,
        "RoutingTransferActionsJson": transfer_actions,
        "SchemaHash": schema_hash(fields),
        "FieldCount": str(len(fields)),
        "HostedZoneName": html.escape(zone_name),
    }


def lambda_handler(event, _context):
    physical_id = event.get("PhysicalResourceId", "bridgefu-configuration-v1")
    try:
        if event.get("RequestType") == "Delete":
            _send(event, "SUCCESS", physical_id, {}, "configuration released")
            return
        data = render(event["ResourceProperties"])
        _send(event, "SUCCESS", physical_id, data, "configuration validated")
    except ConfigurationError as error:
        _send(event, "FAILED", physical_id, {}, str(error))
    except (KeyError, TypeError, urllib.error.URLError):
        _send(event, "FAILED", physical_id, {}, "configuration_validation_failed")
    except Exception:
        _send(event, "FAILED", physical_id, {}, "configuration_internal_error")
