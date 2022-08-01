from ipaddress import ip_address

from panther_base_helpers import deep_get, pattern_match_list
from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject

# pylint: disable=too-many-return-statements,invalid-name,unused-argument,global-at-module-level,global-variable-undefined

# Monitor for GetObject events from S3.
# Also check ListBucket to reveal object enumeration.
_S3_EVENT_LIST = (
    "ListBucket*",
    "GetObject*",
)

# Some AWS IP addresses listed as "malicious" are stale
# This enables allowing specific roles where this may occur
_ALLOWED_ROLES = (
    "*PantherAuditRole-*",
    "*PantherLogProcessingRole-*",
)


def rule(event):
    # Filter: Non-S3 events
    if event.get("eventSource") != "s3.amazonaws.com":
        return False
    # Filter: Errors
    if event.get("errorCode"):
        return False
    # Filter: Internal AWS
    if deep_get(event, "userIdentity", "type") in ("AWSAccount", "AWSService"):
        return False
    # Filter: Non "Get" events
    if not pattern_match_list(event.get("eventName"), _S3_EVENT_LIST):
        return False

    # Validate the IP is actually an IP (sometimes it's a string)
    try:
        ip_address(event.get("sourceIPAddress"))
    except ValueError:
        return False

    # Create GreyNoise Objects
    global NOISE
    NOISE = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP is in RIOT dataset we can assume safe, do not alert
    if riot.is_riot("sourceIPAddress"):
        return False

    # Check that the IP is classified as 'malicious'
    if NOISE.classification("sourceIPAddress") == "malicious":

        # Filter: Roles that generate FP's if used from AWS IP Space
        if pattern_match_list(deep_get(event, "userIdentity", "arn"), _ALLOWED_ROLES):
            # Only Greynoise advanced provides AS organization info
            if NOISE.subscription_level() == 'advanced':
                if NOISE.organization == 'Amazon.com, Inc.':
                    return False
            # return false if the role is seen and we are not able to valide the AS organization
            else:
                return False
        return True

    return False


def title(event):
    # Group by ip-arn combinations
    ip = deep_get(event, "sourceIPAddress")
    arn = deep_get(event, "userIdentity", "arn")
    return f"GreyNoise malicious S3 events detected by {ip} from {arn}"


def alert_context(event):
    return NOISE.context("sourceIPAddress")
