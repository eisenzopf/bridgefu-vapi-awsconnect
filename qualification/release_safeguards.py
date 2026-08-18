"""Fail-closed preflight, telemetry, and teardown safeguards.

This module deliberately retains only bounded summaries.  Exact AWS resource
identities remain in process memory while the qualification controller owns
them; retained evidence contains counts and cryptographic digests, never a
general account inventory.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any


class SafeguardError(RuntimeError):
    """A release safeguard could not establish its required proof."""


PREFLIGHT_PRODUCER = "bridgefu-qualification-preflight@1"
TELEMETRY_PRODUCER = "bridgefu-cloudwatch-capacity-observation@1"
ZERO_PROOF_PRODUCER = "bridgefu-zero-resource-proof@1"
MAX_INVENTORY_RESOURCES = 8_000
MAX_TAGGED_RESOURCES = 2_000
MAX_CLOUDWATCH_DATAPOINTS = 512
CAPACITY_RESERVE = 1
VPC_QUOTA_CODE = "L-F678F1CE"
INTERNET_GATEWAY_QUOTA_CODE = "L-A4707A72"
EIP_QUOTA_CODE = "L-0263D0A3"
CONNECT_INSTANCE_QUOTA_CODE = "L-AA17A6B9"
STANDARD_VCPU_QUOTA_CODE = "L-1216C47A"
RUNTIME_DEPLOYMENT_PRODUCER = "bridgefu-runtime-deployment@1"

ZERO_RESOURCE_CATEGORIES = (
    "cloudformation_stacks",
    "ec2_instances",
    "ec2_volumes",
    "ec2_network_interfaces",
    "ec2_vpcs",
    "ec2_security_groups",
    "ec2_elastic_ips",
    "ec2_vpc_endpoints",
    "dynamodb_tables",
    "lambda_functions",
    "api_gateway_apis",
    "acm_certificates",
    "cloudwatch_log_groups",
    "cloudwatch_alarms",
    "cloudwatch_dashboards",
    "secrets",
    "connect_resources",
    "route53_private_zones",
    "route53_public_records",
    "s3_object_versions",
    "vapi_resources",
    "iam_resources",
    "sns_resources",
    "backup_resources",
    "execution_tagged_resources",
    "other_stack_resources",
)

RESOURCE_TYPE_CATEGORY = {
    "AWS::CloudFormation::Stack": "cloudformation_stacks",
    "AWS::EC2::Instance": "ec2_instances",
    "AWS::EC2::Volume": "ec2_volumes",
    "AWS::EC2::NetworkInterface": "ec2_network_interfaces",
    "AWS::EC2::VPC": "ec2_vpcs",
    "AWS::EC2::SecurityGroup": "ec2_security_groups",
    "AWS::EC2::EIP": "ec2_elastic_ips",
    "AWS::EC2::VPCEndpoint": "ec2_vpc_endpoints",
    "AWS::DynamoDB::Table": "dynamodb_tables",
    "AWS::Lambda::Function": "lambda_functions",
    "AWS::ApiGatewayV2::Api": "api_gateway_apis",
    "AWS::CertificateManager::Certificate": "acm_certificates",
    "AWS::Logs::LogGroup": "cloudwatch_log_groups",
    "AWS::CloudWatch::Alarm": "cloudwatch_alarms",
    "AWS::CloudWatch::Dashboard": "cloudwatch_dashboards",
    "AWS::SecretsManager::Secret": "secrets",
    "AWS::Route53::HostedZone": "route53_private_zones",
    "AWS::Route53::RecordSet": "route53_public_records",
    "AWS::IAM::Role": "iam_resources",
    "AWS::IAM::ManagedPolicy": "iam_resources",
    "AWS::IAM::Policy": "iam_resources",
    "AWS::IAM::InstanceProfile": "iam_resources",
    "AWS::SNS::Topic": "sns_resources",
    "AWS::SNS::Subscription": "sns_resources",
    "AWS::Backup::BackupVault": "backup_resources",
    "AWS::Backup::BackupPlan": "backup_resources",
    "AWS::Backup::BackupSelection": "backup_resources",
    "AWS::Connect::Instance": "connect_resources",
    "AWS::Connect::ContactFlow": "connect_resources",
    "AWS::Connect::HoursOfOperation": "connect_resources",
    "AWS::Connect::IntegrationAssociation": "connect_resources",
    "AWS::Connect::Queue": "connect_resources",
    "AWS::Connect::RoutingProfile": "connect_resources",
    "AWS::Connect::SecurityProfile": "connect_resources",
    "AWS::Connect::User": "connect_resources",
    "AWS::ApiGatewayV2::Integration": "api_gateway_apis",
    "AWS::ApiGatewayV2::Route": "api_gateway_apis",
    "AWS::ApiGatewayV2::Stage": "api_gateway_apis",
    "AWS::Lambda::Permission": "lambda_functions",
    "AWS::Logs::MetricFilter": "cloudwatch_log_groups",
    "AWS::EC2::EIPAssociation": "ec2_elastic_ips",
    "AWS::EC2::InternetGateway": "ec2_vpcs",
    "AWS::EC2::NatGateway": "ec2_vpcs",
    "AWS::EC2::Route": "ec2_vpcs",
    "AWS::EC2::RouteTable": "ec2_vpcs",
    "AWS::EC2::SecurityGroupEgress": "ec2_security_groups",
    "AWS::EC2::SecurityGroupIngress": "ec2_security_groups",
    "AWS::EC2::Subnet": "ec2_vpcs",
    "AWS::EC2::SubnetRouteTableAssociation": "ec2_vpcs",
    "AWS::EC2::VPCGatewayAttachment": "ec2_vpcs",
    "Custom::BridgefuVapiResources": "vapi_resources",
    "Custom::BridgefuConfiguration": "other_stack_resources",
}

PARENT_BOUND_RESOURCE_TYPES = {
    "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::Stage",
    "AWS::Backup::BackupSelection",
    "AWS::Connect::ContactFlow",
    "AWS::Connect::HoursOfOperation",
    "AWS::Connect::IntegrationAssociation",
    "AWS::Connect::Queue",
    "AWS::Connect::RoutingProfile",
    "AWS::Connect::SecurityProfile",
    "AWS::Connect::User",
    "AWS::EC2::EIPAssociation",
    "AWS::EC2::Route",
    "AWS::EC2::SecurityGroupEgress",
    "AWS::EC2::SecurityGroupIngress",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::VPCGatewayAttachment",
    "AWS::IAM::Policy",
    "AWS::Lambda::Permission",
    "AWS::Logs::MetricFilter",
    "AWS::SNS::Subscription",
    "Custom::BridgefuConfiguration",
}

DIRECT_VERIFIED_RESOURCE_TYPES = {
    "AWS::ApiGatewayV2::Api",
    "AWS::Backup::BackupPlan",
    "AWS::Backup::BackupVault",
    "AWS::CertificateManager::Certificate",
    "AWS::CloudFormation::Stack",
    "AWS::CloudWatch::Alarm",
    "AWS::CloudWatch::Dashboard",
    "AWS::Connect::Instance",
    "AWS::DynamoDB::Table",
    "AWS::EC2::EIP",
    "AWS::EC2::Instance",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::NatGateway",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Subnet",
    "AWS::EC2::VPC",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::Volume",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Logs::LogGroup",
    "AWS::Route53::HostedZone",
    "AWS::Route53::RecordSet",
    "AWS::SNS::Topic",
    "AWS::SecretsManager::Secret",
    "Custom::BridgefuVapiResources",
}


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _dns_name(value: Any) -> str:
    if not isinstance(value, str):
        raise SafeguardError("DNS name is invalid")
    normalized = value.rstrip(".").lower() + "."
    if (
        len(normalized) > 254
        or re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+", normalized)
        is None
    ):
        raise SafeguardError("DNS name is invalid")
    return normalized


def public_ns_records(name: str) -> list[str]:
    """Resolve the public NS RRset with a bounded, DNS-specific dependency."""
    try:
        import dns.resolver  # type: ignore[import-not-found]

        answer = dns.resolver.resolve(name.rstrip("."), "NS", lifetime=10.0)
    except Exception as error:  # dnspython exposes resolver-specific subclasses.
        raise SafeguardError("public DNS delegation lookup failed") from error
    values = sorted({_dns_name(str(item)) for item in answer})
    if not 2 <= len(values) <= 8:
        raise SafeguardError("public DNS delegation result is invalid")
    return values


def exact_route53_records(
    aws: Any, hosted_zone_id: str, name: str
) -> list[dict[str, Any]]:
    normalized = _dns_name(name)
    response = aws.json(
        [
            "route53",
            "list-resource-record-sets",
            "--hosted-zone-id",
            hosted_zone_id,
            "--start-record-name",
            normalized,
            "--max-items",
            "1",
        ],
        timeout=120,
    )
    values = (
        response.get("ResourceRecordSets") if isinstance(response, Mapping) else None
    )
    if not isinstance(values, list) or len(values) > 1:
        raise SafeguardError("Route53 record inventory is invalid")
    exact: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping):
            raise SafeguardError("Route53 record inventory is invalid")
        raw_name = value.get("Name")
        if not isinstance(raw_name, str) or len(raw_name) > 1024:
            raise SafeguardError("Route53 record inventory is invalid")
        # Route53 returns the first name at or after StartRecordName. That may
        # legitimately be an unrelated ACM validation label (leading `_`) or
        # an escaped wildcard (`\\052`). Compare it with the already-validated
        # target before applying the stricter host-name parser.
        if raw_name.rstrip(".").lower() + "." != normalized:
            continue
        candidate = _dns_name(raw_name)
        record_type = value.get("Type")
        if not isinstance(record_type, str) or not re.fullmatch(
            r"[A-Z0-9]{1,16}", record_type
        ):
            raise SafeguardError("Route53 record type is invalid")
        exact.append({"name": candidate, "type": record_type})
    return exact


def _service_quota(aws: Any, service: str, code: str) -> int:
    response = aws.json(
        [
            "service-quotas",
            "get-service-quota",
            "--service-code",
            service,
            "--quota-code",
            code,
        ],
        timeout=120,
    )
    quota = response.get("Quota") if isinstance(response, Mapping) else None
    value = quota.get("Value") if isinstance(quota, Mapping) else None
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value <= 0
        or int(value) != value
    ):
        raise SafeguardError("AWS service quota is invalid")
    return int(value)


def _bounded_list(
    document: Any, key: str, label: str, maximum: int = 5_000
) -> list[Any]:
    values = document.get(key) if isinstance(document, Mapping) else None
    pagination = (
        [
            document.get(token)
            for token in ("NextToken", "nextToken", "PaginationToken", "Marker")
        ]
        if isinstance(document, Mapping)
        else []
    )
    if (
        not isinstance(values, list)
        or len(values) > maximum
        or any(token not in (None, "") for token in pagination)
    ):
        raise SafeguardError(f"{label} inventory is invalid")
    return values


def _capacity_check(used: int, required: int, limit: int) -> bool:
    return all(
        type(value) is int and value >= 0 for value in (used, required, limit)
    ) and (limit - used - required >= CAPACITY_RESERVE)


def validate_preflight(
    aws: Any,
    *,
    execution_id: str,
    expected_account_id: str,
    region: str,
    cloudformation_role_arn: str,
    vapi_secret_arn: str,
    hosted_zone_id: str,
    hosted_zone_name: str,
    sip_hostname: str,
    runtime_image_id: str,
    release: str,
    instance_type: str,
    resolve_ns: Callable[[str], list[str]] = public_ns_records,
) -> dict[str, Any]:
    """Prove identity, DNS, AMI/offering, and quota capacity before mutation."""
    identity = aws.json(["sts", "get-caller-identity"], timeout=60)
    if (
        not isinstance(identity, Mapping)
        or identity.get("Account") != expected_account_id
    ):
        raise SafeguardError("active AWS account does not match the protected account")
    role_match = re.fullmatch(
        r"arn:aws[-a-z0-9]*:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}",
        cloudformation_role_arn,
    )
    secret_match = re.fullmatch(
        r"arn:aws[-a-z0-9]*:secretsmanager:([-a-z0-9]+):([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]+",
        vapi_secret_arn,
    )
    if role_match is None or role_match.group(1) != expected_account_id:
        raise SafeguardError("CloudFormation service role account is not exact")
    if (
        secret_match is None
        or secret_match.group(1) != region
        or secret_match.group(2) != expected_account_id
    ):
        raise SafeguardError("Vapi secret account or region is not exact")
    role_name = cloudformation_role_arn.rsplit("/", 1)[-1]
    role = aws.json(["iam", "get-role", "--role-name", role_name], timeout=120)
    role_value = role.get("Role") if isinstance(role, Mapping) else None
    if (
        not isinstance(role_value, Mapping)
        or role_value.get("Arn") != cloudformation_role_arn
    ):
        raise SafeguardError("CloudFormation service role identity is not exact")
    secret = aws.json(
        ["secretsmanager", "describe-secret", "--secret-id", vapi_secret_arn],
        timeout=120,
    )
    if (
        not isinstance(secret, Mapping)
        or secret.get("ARN") != vapi_secret_arn
        or secret.get("DeletedDate") is not None
    ):
        raise SafeguardError("Vapi secret identity is not exact")

    zone = aws.json(["route53", "get-hosted-zone", "--id", hosted_zone_id], timeout=120)
    hosted = zone.get("HostedZone") if isinstance(zone, Mapping) else None
    delegation = zone.get("DelegationSet") if isinstance(zone, Mapping) else None
    zone_id = hosted.get("Id") if isinstance(hosted, Mapping) else None
    zone_config = hosted.get("Config") if isinstance(hosted, Mapping) else None
    expected_zone_name = _dns_name(hosted_zone_name)
    if (
        not isinstance(hosted, Mapping)
        or not isinstance(zone_id, str)
        or zone_id.rsplit("/", 1)[-1] != hosted_zone_id
        or _dns_name(hosted.get("Name")) != expected_zone_name
        or not isinstance(zone_config, Mapping)
        or zone_config.get("PrivateZone") is not False
    ):
        raise SafeguardError("qualification hosted zone is not the exact public zone")
    name_servers = (
        delegation.get("NameServers") if isinstance(delegation, Mapping) else None
    )
    if not isinstance(name_servers, list) or not 2 <= len(name_servers) <= 8:
        raise SafeguardError("Route53 delegation set is invalid")
    expected_delegation = sorted({_dns_name(item) for item in name_servers})
    if len(expected_delegation) != len(name_servers):
        raise SafeguardError("Route53 delegation set is ambiguous")
    observed_delegation = sorted(
        {_dns_name(item) for item in resolve_ns(hosted_zone_name)}
    )
    if observed_delegation != expected_delegation:
        raise SafeguardError("public parent DNS delegation is not exact")
    normalized_hostname = _dns_name(sip_hostname)
    if not normalized_hostname.endswith("." + expected_zone_name):
        raise SafeguardError("qualification SIP hostname is outside the hosted zone")
    for record_name in (normalized_hostname, "control." + normalized_hostname):
        if exact_route53_records(aws, hosted_zone_id, record_name):
            raise SafeguardError("qualification DNS record name is not vacant")

    images = aws.json(
        ["ec2", "describe-images", "--image-ids", runtime_image_id], timeout=120
    )
    image_values = _bounded_list(images, "Images", "AMI", 2)
    if len(image_values) != 1 or not isinstance(image_values[0], Mapping):
        raise SafeguardError("candidate AMI identity is not exact")
    image = image_values[0]
    tags = {
        item.get("Key"): item.get("Value")
        for item in image.get("Tags", [])
        if isinstance(item, Mapping)
        and isinstance(item.get("Key"), str)
        and isinstance(item.get("Value"), str)
    }
    if (
        image.get("ImageId") != runtime_image_id
        or image.get("OwnerId") != expected_account_id
        or image.get("State") != "available"
        or image.get("Architecture") != "arm64"
        or image.get("RootDeviceType") != "ebs"
        or tags.get("ManagedBy") != "bridgefu-vapi-awsconnect"
        or tags.get("BridgefuRelease") != release
    ):
        raise SafeguardError("candidate AMI ownership or runtime contract is invalid")

    instance_types = aws.json(
        ["ec2", "describe-instance-types", "--instance-types", instance_type],
        timeout=120,
    )
    type_values = _bounded_list(instance_types, "InstanceTypes", "instance type", 2)
    if len(type_values) != 1 or not isinstance(type_values[0], Mapping):
        raise SafeguardError("runtime instance type description is invalid")
    selected_type = type_values[0]
    vcpu = selected_type.get("VCpuInfo")
    memory = selected_type.get("MemoryInfo")
    architectures = selected_type.get("ProcessorInfo", {}).get("SupportedArchitectures")
    selected_vcpus = vcpu.get("DefaultVCpus") if isinstance(vcpu, Mapping) else None
    memory_mib = memory.get("SizeInMiB") if isinstance(memory, Mapping) else None
    if (
        type(selected_vcpus) is not int
        or selected_vcpus < 1
        or type(memory_mib) is not int
        or memory_mib < 1
        or not isinstance(architectures, list)
        or "arm64" not in architectures
    ):
        raise SafeguardError("runtime instance type is not a valid ARM64 host")

    zones = _bounded_list(
        aws.json(
            [
                "ec2",
                "describe-availability-zones",
                "--filters",
                "Name=state,Values=available",
            ],
            timeout=120,
        ),
        "AvailabilityZones",
        "availability-zone",
        100,
    )
    zone_names = sorted(
        item.get("ZoneName")
        for item in zones
        if isinstance(item, Mapping)
        and item.get("ZoneType", "availability-zone") == "availability-zone"
        and isinstance(item.get("ZoneName"), str)
    )
    if len(zone_names) < 2 or len(zone_names) != len(set(zone_names)):
        raise SafeguardError("two exact availability zones are not available")
    selected_zones = zone_names[:2]

    offerings = aws.json(
        [
            "ec2",
            "describe-instance-type-offerings",
            "--location-type",
            "availability-zone",
            "--filters",
            f"Name=instance-type,Values={instance_type}",
            f"Name=location,Values={','.join(selected_zones)}",
        ],
        timeout=120,
    )
    offering_values = _bounded_list(
        offerings, "InstanceTypeOfferings", "instance offering", 10
    )
    offered_zones: set[str] = set()
    for item in offering_values:
        if (
            not isinstance(item, Mapping)
            or item.get("InstanceType") != instance_type
            or item.get("LocationType") != "availability-zone"
            or item.get("Location") not in selected_zones
        ):
            raise SafeguardError("runtime instance offering inventory is invalid")
        offered_zones.add(str(item["Location"]))
    if offered_zones != set(selected_zones):
        raise SafeguardError(
            "runtime instance type is not offered in every selected availability zone"
        )

    vpcs = _bounded_list(aws.json(["ec2", "describe-vpcs"]), "Vpcs", "VPC")
    gateways = _bounded_list(
        aws.json(["ec2", "describe-internet-gateways"]),
        "InternetGateways",
        "internet gateway",
    )
    addresses = _bounded_list(
        aws.json(["ec2", "describe-addresses"]), "Addresses", "EIP"
    )
    connects = _bounded_list(
        aws.json(["connect", "list-instances"]), "InstanceSummaryList", "Connect"
    )
    vpc_limit = _service_quota(aws, "vpc", VPC_QUOTA_CODE)
    internet_gateway_limit = _service_quota(aws, "vpc", INTERNET_GATEWAY_QUOTA_CODE)
    eip_limit = _service_quota(aws, "ec2", EIP_QUOTA_CODE)
    connect_limit = _service_quota(aws, "connect", CONNECT_INSTANCE_QUOTA_CODE)
    vcpu_limit = _service_quota(aws, "ec2", STANDARD_VCPU_QUOTA_CODE)

    active = _bounded_list(
        aws.json(
            [
                "ec2",
                "describe-instances",
                "--filters",
                "Name=instance-state-name,Values=pending,running,stopping",
            ],
            timeout=120,
        ),
        "Reservations",
        "active EC2",
    )
    active_types: list[str] = []
    for reservation in active:
        instances = (
            reservation.get("Instances") if isinstance(reservation, Mapping) else None
        )
        if not isinstance(instances, list) or len(instances) > 1_000:
            raise SafeguardError("active EC2 inventory is invalid")
        for item in instances:
            value = item.get("InstanceType") if isinstance(item, Mapping) else None
            if not isinstance(value, str) or len(value) > 64:
                raise SafeguardError("active EC2 instance type is invalid")
            active_types.append(value)
    unique_types = sorted(set(active_types))
    vcpus_by_type: dict[str, int] = {}
    for offset in range(0, len(unique_types), 100):
        batch = unique_types[offset : offset + 100]
        if not batch:
            continue
        descriptions = _bounded_list(
            aws.json(["ec2", "describe-instance-types", "--instance-types", *batch]),
            "InstanceTypes",
            "active EC2 instance type",
            100,
        )
        for item in descriptions:
            name = item.get("InstanceType") if isinstance(item, Mapping) else None
            info = item.get("VCpuInfo") if isinstance(item, Mapping) else None
            value = info.get("DefaultVCpus") if isinstance(info, Mapping) else None
            if name not in batch or type(value) is not int or value < 1:
                raise SafeguardError("active EC2 vCPU inventory is invalid")
            vcpus_by_type[str(name)] = value
    if set(vcpus_by_type) != set(unique_types):
        raise SafeguardError("active EC2 vCPU inventory is incomplete")
    active_vcpus = sum(vcpus_by_type[item] for item in active_types)

    capacity_checks = {
        "vpcs": _capacity_check(len(vpcs), 1, vpc_limit),
        "internet_gateways": _capacity_check(len(gateways), 1, internet_gateway_limit),
        # The qualification root disables both optional NAT gateways.  The
        # exact customer template therefore creates only Runtime.GatewayEip.
        "elastic_ips": _capacity_check(len(addresses), 1, eip_limit),
        "connect_instances": _capacity_check(len(connects), 1, connect_limit),
        "standard_vcpus": _capacity_check(active_vcpus, selected_vcpus, vcpu_limit),
    }
    blocked = sorted(name for name, passed in capacity_checks.items() if not passed)
    if blocked:
        raise SafeguardError(
            "AWS capacity reserve is insufficient for: " + ", ".join(blocked)
        )

    return {
        "schema_version": 1,
        "producer": PREFLIGHT_PRODUCER,
        "execution_id": execution_id,
        "region": region,
        "runtime_image_fingerprint": hashlib.sha256(
            runtime_image_id.encode("ascii")
        ).hexdigest()[:12],
        "runtime_image_sha256": hashlib.sha256(
            runtime_image_id.encode("ascii")
        ).hexdigest(),
        "instance_type": instance_type,
        "vcpus": selected_vcpus,
        "memory_mib": memory_mib,
        "checks": {
            "active_account_exact": True,
            "cloudformation_role_account_exact": True,
            "vapi_secret_account_region_exact": True,
            "public_hosted_zone_exact": True,
            "public_delegation_exact": True,
            "dns_names_vacant": True,
            "candidate_ami_exact": True,
            "instance_offering_available": True,
            **capacity_checks,
        },
        "passed": True,
        "redacted": True,
    }


def validate_deployed_runtime(
    aws: Any,
    *,
    execution_id: str,
    region: str,
    expected_account_id: str,
    instance_id: str,
    runtime_image_id: str,
    instance_type: str,
    expected_recipe: str,
) -> dict[str, Any]:
    """Prove that the live runtime is the exact preflighted candidate host."""
    if (
        region not in {"us-west-2", "us-east-1"}
        or re.fullmatch(r"[0-9]{12}", expected_account_id) is None
        or re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id) is None
        or re.fullmatch(r"ami-[0-9a-f]{8,17}", runtime_image_id) is None
        or re.fullmatch(r"[a-z0-9.]{3,32}", instance_type) is None
        or not isinstance(expected_recipe, str)
        or not expected_recipe
    ):
        raise SafeguardError("deployed runtime expectation is invalid")
    response = aws.json(
        ["ec2", "describe-instances", "--instance-ids", instance_id], timeout=120
    )
    reservations = _bounded_list(response, "Reservations", "deployed runtime", 2)
    instances: list[Mapping[str, Any]] = []
    for reservation in reservations:
        values = (
            reservation.get("Instances") if isinstance(reservation, Mapping) else None
        )
        if not isinstance(values, list) or len(values) > 2:
            raise SafeguardError("deployed runtime inventory is invalid")
        if any(not isinstance(value, Mapping) for value in values):
            raise SafeguardError("deployed runtime inventory is invalid")
        instances.extend(values)
    if len(instances) != 1:
        raise SafeguardError("deployed runtime identity is not exact")
    instance = instances[0]
    tags = instance.get("Tags")
    if not isinstance(tags, list) or len(tags) > 64:
        raise SafeguardError("deployed runtime tags are invalid")
    normalized_tags: dict[str, str] = {}
    for item in tags:
        key = item.get("Key") if isinstance(item, Mapping) else None
        value = item.get("Value") if isinstance(item, Mapping) else None
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or key in normalized_tags
        ):
            raise SafeguardError("deployed runtime tags are invalid")
        normalized_tags[key] = value
    state = instance.get("State")
    placement = instance.get("Placement")
    availability_zone = (
        placement.get("AvailabilityZone") if isinstance(placement, Mapping) else None
    )
    expected_tags = {
        "Project": "bridgefu-vapi-awsconnect",
        "ManagedBy": "bridgefu-cloudformation",
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": expected_recipe,
    }
    if (
        instance.get("InstanceId") != instance_id
        or instance.get("ImageId") != runtime_image_id
        or instance.get("InstanceType") != instance_type
        or instance.get("Architecture") != "arm64"
        or not isinstance(state, Mapping)
        or state.get("Name") != "running"
        or not isinstance(availability_zone, str)
        or not availability_zone.startswith(region)
        or any(
            normalized_tags.get(key) != value for key, value in expected_tags.items()
        )
    ):
        raise SafeguardError("deployed runtime differs from the candidate contract")
    return {
        "schema_version": 1,
        "producer": RUNTIME_DEPLOYMENT_PRODUCER,
        "execution_id": execution_id,
        "region": region,
        "runtime_image_sha256": hashlib.sha256(
            runtime_image_id.encode("ascii")
        ).hexdigest(),
        "instance_id_fingerprint": hashlib.sha256(
            instance_id.encode("ascii")
        ).hexdigest()[:16],
        "instance_type": instance_type,
        "architecture": "arm64",
        "availability_zone": availability_zone,
        "checks": {
            "instance_id_exact": True,
            "candidate_ami_exact": True,
            "instance_type_exact": True,
            "architecture_arm64": True,
            "running": True,
            "ownership_tags_exact": True,
        },
        "passed": True,
        "redacted": True,
    }


def stack_ownership_inventory(
    aws: Any, root_stack: str, maximum_stacks: int = 16
) -> dict[str, Any]:
    """Capture exact stack IDs and physical resources before stack deletion."""
    queue = [root_stack]
    seen: set[str] = set()
    stack_ids: set[str] = set()
    stack_logical_ids: dict[str, str] = {}
    resources: dict[str, set[str]] = {name: set() for name in ZERO_RESOURCE_CATEGORIES}
    resources_by_type: dict[str, set[str]] = {}
    resource_types: dict[str, int] = {}
    while queue:
        stack = queue.pop(0)
        if stack in seen or len(seen) >= maximum_stacks:
            raise SafeguardError("qualification nested-stack ownership is invalid")
        seen.add(stack)
        description = aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", stack], timeout=120
        )
        stacks = description.get("Stacks") if isinstance(description, Mapping) else None
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or not isinstance(stacks[0], Mapping)
        ):
            raise SafeguardError("qualification stack ownership is unavailable")
        stack_id = stacks[0].get("StackId")
        if not isinstance(stack_id, str) or not stack_id.startswith("arn:"):
            raise SafeguardError("qualification stack ID is invalid")
        stack_ids.add(stack_id)
        response = aws.json(
            ["cloudformation", "list-stack-resources", "--stack-name", stack_id],
            timeout=120,
        )
        values = _bounded_list(
            response, "StackResourceSummaries", "stack resource", 500
        )
        for item in values:
            if not isinstance(item, Mapping):
                raise SafeguardError("qualification stack resource is invalid")
            resource_type = item.get("ResourceType")
            physical_id = item.get("PhysicalResourceId")
            if not isinstance(resource_type, str) or len(resource_type) > 128:
                raise SafeguardError("qualification stack resource type is invalid")
            if resource_type not in RESOURCE_TYPE_CATEGORY:
                raise SafeguardError(
                    "qualification contains an unmodeled resource type"
                )
            resource_types[resource_type] = resource_types.get(resource_type, 0) + 1
            if physical_id is None:
                continue
            if (
                not isinstance(physical_id, str)
                or not 1 <= len(physical_id) <= 2_048
                or re.search(r"[\x00-\x1f\x7f]", physical_id)
            ):
                raise SafeguardError("qualification physical resource ID is invalid")
            category = RESOURCE_TYPE_CATEGORY.get(
                resource_type, "other_stack_resources"
            )
            resources[category].add(physical_id)
            resources_by_type.setdefault(resource_type, set()).add(physical_id)
            if resource_type == "AWS::CloudFormation::Stack":
                if not physical_id.startswith("arn:"):
                    raise SafeguardError("qualification nested stack ID is invalid")
                logical_id = item.get("LogicalResourceId")
                if (
                    not isinstance(logical_id, str)
                    or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,254}", logical_id)
                    or physical_id in stack_logical_ids
                ):
                    raise SafeguardError(
                        "qualification nested stack logical identity is invalid"
                    )
                stack_logical_ids[physical_id] = logical_id
                queue.append(physical_id)
            if sum(resource_types.values()) > MAX_INVENTORY_RESOURCES:
                raise SafeguardError("qualification stack resource bound was exceeded")
    instance_ids = sorted(resources_by_type.get("AWS::EC2::Instance", set()))
    for offset in range(0, len(instance_ids), 100):
        batch = instance_ids[offset : offset + 100]
        response = aws.json(
            ["ec2", "describe-instances", "--instance-ids", *batch], timeout=120
        )
        reservations = _bounded_list(response, "Reservations", "runtime instance", 100)
        observed: set[str] = set()
        for reservation in reservations:
            instances = (
                reservation.get("Instances")
                if isinstance(reservation, Mapping)
                else None
            )
            if not isinstance(instances, list) or len(instances) > 100:
                raise SafeguardError("runtime instance attachment inventory is invalid")
            for instance in instances:
                if not isinstance(instance, Mapping):
                    raise SafeguardError("runtime instance attachment is invalid")
                instance_id = instance.get("InstanceId")
                if instance_id not in batch:
                    raise SafeguardError("runtime instance attachment identity changed")
                observed.add(str(instance_id))
                for block in instance.get("BlockDeviceMappings", []):
                    ebs = block.get("Ebs") if isinstance(block, Mapping) else None
                    volume_id = (
                        ebs.get("VolumeId") if isinstance(ebs, Mapping) else None
                    )
                    if isinstance(volume_id, str):
                        resources["ec2_volumes"].add(volume_id)
                        resources_by_type.setdefault("AWS::EC2::Volume", set()).add(
                            volume_id
                        )
                for interface in instance.get("NetworkInterfaces", []):
                    eni = (
                        interface.get("NetworkInterfaceId")
                        if isinstance(interface, Mapping)
                        else None
                    )
                    if isinstance(eni, str):
                        resources["ec2_network_interfaces"].add(eni)
                        resources_by_type.setdefault(
                            "AWS::EC2::NetworkInterface", set()
                        ).add(eni)
                for group in instance.get("SecurityGroups", []):
                    group_id = (
                        group.get("GroupId") if isinstance(group, Mapping) else None
                    )
                    if isinstance(group_id, str):
                        resources["ec2_security_groups"].add(group_id)
                        resources_by_type.setdefault(
                            "AWS::EC2::SecurityGroup", set()
                        ).add(group_id)
                vpc_id = instance.get("VpcId")
                if isinstance(vpc_id, str):
                    resources["ec2_vpcs"].add(vpc_id)
                    resources_by_type.setdefault("AWS::EC2::VPC", set()).add(vpc_id)
        if observed != set(batch):
            raise SafeguardError("runtime instance attachment inventory is incomplete")
    resources["cloudformation_stacks"].update(stack_ids)
    normalized = {key: sorted(value) for key, value in resources.items()}
    normalized_by_type = {
        key: sorted(value) for key, value in sorted(resources_by_type.items())
    }
    return {
        "stack_ids": sorted(stack_ids),
        "stack_logical_ids": dict(sorted(stack_logical_ids.items())),
        "resources": normalized,
        "resources_by_type": normalized_by_type,
        "resource_count": sum(len(value) for value in normalized.values()),
        "ownership_sha256": _canonical_sha256(
            {
                "stack_ids": sorted(stack_ids),
                "stack_logical_ids": dict(sorted(stack_logical_ids.items())),
                "resources": normalized,
                "resources_by_type": normalized_by_type,
            }
        ),
    }


def _parse_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise SafeguardError(f"{label} timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SafeguardError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise SafeguardError(f"{label} timestamp is invalid")
    return parsed.astimezone(dt.UTC)


def _metric_points(
    aws: Any,
    *,
    name: str,
    instance_id: str,
    start: dt.datetime,
    end: dt.datetime,
) -> list[dict[str, Any]]:
    response = aws.json(
        [
            "cloudwatch",
            "get-metric-statistics",
            "--namespace",
            "Bridgefu/Runtime",
            "--metric-name",
            name,
            "--dimensions",
            f"Name=InstanceId,Value={instance_id}",
            "--start-time",
            (start - dt.timedelta(seconds=10)).isoformat(),
            "--end-time",
            (end + dt.timedelta(seconds=10)).isoformat(),
            "--period",
            "10",
            "--statistics",
            "Minimum",
            "Maximum",
        ],
        timeout=120,
    )
    points = response.get("Datapoints") if isinstance(response, Mapping) else None
    if not isinstance(points, list) or len(points) > MAX_CLOUDWATCH_DATAPOINTS:
        raise SafeguardError("CloudWatch capacity datapoints are invalid")
    normalized: list[dict[str, Any]] = []
    for point in points:
        if not isinstance(point, Mapping):
            raise SafeguardError("CloudWatch capacity datapoint is invalid")
        timestamp = _parse_timestamp(point.get("Timestamp"), "CloudWatch metric")
        minimum = point.get("Minimum")
        maximum = point.get("Maximum")
        if (
            not isinstance(minimum, (int, float))
            or isinstance(minimum, bool)
            or not math.isfinite(float(minimum))
            or not isinstance(maximum, (int, float))
            or isinstance(maximum, bool)
            or not math.isfinite(float(maximum))
        ):
            raise SafeguardError("CloudWatch capacity datapoint value is invalid")
        normalized.append(
            {
                "timestamp": timestamp,
                "minimum": float(minimum),
                "maximum": float(maximum),
            }
        )
    return sorted(normalized, key=lambda item: item["timestamp"])


def collect_active_call_telemetry(
    aws: Any,
    *,
    execution_id: str,
    instance_id: str,
    instance_type: str,
    vcpus: int,
    memory_mib: int,
    runtime_log_group: str,
    window_started_at: str,
    window_ended_at: str,
    deadline_seconds: int = 180,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    start = _parse_timestamp(window_started_at, "active-call start")
    end = _parse_timestamp(window_ended_at, "active-call end")
    duration = (end - start).total_seconds()
    if not 10 <= duration <= 600:
        raise SafeguardError("active-call telemetry window is outside its bounds")
    required_samples = max(2, math.ceil(duration / 10) - 1)
    deadline = monotonic() + deadline_seconds
    idle: list[dict[str, Any]] = []
    memory: list[dict[str, Any]] = []
    while True:
        idle = _metric_points(
            aws, name="cpu_usage_idle", instance_id=instance_id, start=start, end=end
        )
        memory = _metric_points(
            aws, name="mem_used_percent", instance_id=instance_id, start=start, end=end
        )
        coverage = (
            len(idle) >= required_samples
            and len(memory) >= required_samples
            and idle[0]["timestamp"] <= start + dt.timedelta(seconds=10)
            and memory[0]["timestamp"] <= start + dt.timedelta(seconds=10)
            and idle[-1]["timestamp"] >= end - dt.timedelta(seconds=10)
            and memory[-1]["timestamp"] >= end - dt.timedelta(seconds=10)
        )
        if coverage:
            break
        if monotonic() >= deadline:
            raise SafeguardError("CloudWatch active-call samples did not converge")
        sleep(10)
    starts = aws.json(
        [
            "logs",
            "filter-log-events",
            "--log-group-name",
            runtime_log_group,
            "--start-time",
            str(int(start.timestamp() * 1_000)),
            "--end-time",
            str(int(end.timestamp() * 1_000) + 1),
            "--filter-pattern",
            '"starting bridgefu process"',
        ],
        timeout=120,
    )
    events = starts.get("events") if isinstance(starts, Mapping) else None
    next_token = starts.get("nextToken") if isinstance(starts, Mapping) else None
    if (
        not isinstance(events, list)
        or len(events) > 100
        or next_token not in (None, "")
    ):
        raise SafeguardError("Bridgefu startup-event inventory is invalid")
    host_cpu_peak = 100.0 - min(point["minimum"] for point in idle)
    host_memory_peak = max(point["maximum"] for point in memory)
    if not 0 <= host_cpu_peak <= 100 or not 0 <= host_memory_peak <= 100:
        raise SafeguardError("host utilization datapoints are invalid")
    cpu_passed = host_cpu_peak < 60.0
    memory_passed = host_memory_peak < 60.0
    restart_passed = len(events) == 0
    value = {
        "schema_version": 1,
        "producer": TELEMETRY_PRODUCER,
        "execution_id": execution_id,
        "instance_type": instance_type,
        "vcpus": vcpus,
        "memory_mib": memory_mib,
        "window_duration_seconds": round(duration, 3),
        "minimum_required_samples": required_samples,
        "cpu_sample_count": len(idle),
        "memory_sample_count": len(memory),
        "host_cpu_peak_percent": round(host_cpu_peak, 3),
        "host_memory_peak_percent": round(host_memory_peak, 3),
        "bridgefu_start_events_during_smoke": len(events),
        "cpu_strictly_under_60_percent": cpu_passed,
        "memory_strictly_under_60_percent": memory_passed,
        "bridgefu_restart_free": restart_passed,
        "compile_excluded": True,
        "passed": cpu_passed and memory_passed and restart_passed,
        "redacted": True,
    }
    if value["passed"] is not True:
        raise SafeguardError("active-call capacity or restart gate failed")
    return value


def empty_resource_counts() -> dict[str, int]:
    return {name: 0 for name in ZERO_RESOURCE_CATEGORIES}


def normalize_zero_observation(
    counts: Mapping[str, Any], *, observed_at: str
) -> dict[str, Any]:
    if set(counts) != set(ZERO_RESOURCE_CATEGORIES):
        raise SafeguardError("zero-resource inventory categories are not exact")
    normalized: dict[str, int] = {}
    for name in ZERO_RESOURCE_CATEGORIES:
        value = counts[name]
        if type(value) is not int or not 0 <= value <= MAX_INVENTORY_RESOURCES:
            raise SafeguardError("zero-resource inventory count is invalid")
        normalized[name] = value
    _parse_timestamp(observed_at, "zero-resource observation")
    return {"observed_at": observed_at, "resource_counts": normalized, "redacted": True}


def observation_is_empty(value: Mapping[str, Any]) -> bool:
    counts = value.get("resource_counts")
    return (
        set(value) == {"observed_at", "resource_counts", "redacted"}
        and value.get("redacted") is True
        and isinstance(value.get("observed_at"), str)
        and isinstance(counts, Mapping)
        and set(counts) == set(ZERO_RESOURCE_CATEGORIES)
        and all(type(item) is int and item == 0 for item in counts.values())
    )


def stable_zero_resource_proof(
    observe: Callable[[], dict[str, Any]],
    *,
    execution_id: str,
    ownership_sha256: str,
    owned_resource_count: int,
    timeout_seconds: int = 900,
    minimum_span_seconds: int = 60,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", ownership_sha256):
        raise SafeguardError("resource ownership digest is invalid")
    if (
        type(owned_resource_count) is not int
        or not 0 <= owned_resource_count <= MAX_INVENTORY_RESOURCES
    ):
        raise SafeguardError("owned resource count is invalid")
    started = monotonic()
    stable: list[dict[str, Any]] = []
    stable_started: float | None = None
    projection: Mapping[str, Any] | None = None
    while monotonic() - started <= timeout_seconds:
        observation = observe()
        if not isinstance(observation, Mapping) or not observation_is_empty(
            observation
        ):
            stable = []
            stable_started = None
            projection = None
        else:
            current_projection = observation.get("resource_counts")
            if current_projection != projection:
                stable = []
                stable_started = monotonic()
                projection = current_projection
            stable.append(dict(observation))
            if (
                len(stable) >= 3
                and stable_started is not None
                and monotonic() - stable_started >= minimum_span_seconds
            ):
                observations = stable[-3:]
                timestamps = [
                    _parse_timestamp(item["observed_at"], "zero-resource observation")
                    for item in observations
                ]
                if (
                    timestamps != sorted(timestamps)
                    or (timestamps[-1] - timestamps[0]).total_seconds()
                    < minimum_span_seconds
                ):
                    raise SafeguardError(
                        "zero-resource observations do not span one minute"
                    )
                return {
                    "schema_version": 1,
                    "producer": ZERO_PROOF_PRODUCER,
                    "execution_id": execution_id,
                    "ownership_sha256": ownership_sha256,
                    "owned_resource_count": owned_resource_count,
                    "required_observations": 3,
                    "minimum_span_seconds": minimum_span_seconds,
                    "observations": observations,
                    "proven_at": dt.datetime.now(dt.UTC)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                    "passed": True,
                    "redacted": True,
                }
        remaining = timeout_seconds - (monotonic() - started)
        if remaining <= 0:
            break
        sleep(min(30 if stable else 5, remaining))
    raise SafeguardError("three stable zero-resource observations did not converge")


def tagged_resource_arns(aws: Any, execution_id: str) -> list[str]:
    arns: list[str] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        command = [
            "resourcegroupstaggingapi",
            "get-resources",
            "--tag-filters",
            f"Key=BridgefuExecutionId,Values={execution_id}",
            "--resources-per-page",
            "100",
            "--no-paginate",
        ]
        if token is not None:
            command.extend(["--pagination-token", token])
        response = aws.json(command, timeout=120)
        values = (
            response.get("ResourceTagMappingList")
            if isinstance(response, Mapping)
            else None
        )
        pagination = (
            response.get("PaginationToken") if isinstance(response, Mapping) else None
        )
        if not isinstance(values, list) or len(values) > 100:
            raise SafeguardError("execution-tagged resource inventory is invalid")
        for item in values:
            arn = item.get("ResourceARN") if isinstance(item, Mapping) else None
            if (
                not isinstance(arn, str)
                or not arn.startswith("arn:")
                or len(arn) > 2_048
            ):
                raise SafeguardError("execution-tagged resource identity is invalid")
            arns.append(arn)
        if len(arns) > MAX_TAGGED_RESOURCES:
            raise SafeguardError("execution-tagged resource inventory is invalid")
        if pagination in (None, ""):
            break
        if (
            not isinstance(pagination, str)
            or not 1 <= len(pagination) <= 2_048
            or re.search(r"[\x00-\x1f\x7f]", pagination)
            or pagination in seen_tokens
        ):
            raise SafeguardError("execution-tagged resource inventory is invalid")
        seen_tokens.add(pagination)
        token = pagination
    if len(arns) != len(set(arns)):
        raise SafeguardError("execution-tagged resource inventory is ambiguous")
    return sorted(arns)
