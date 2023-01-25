from fnmatch import fnmatch

from panther_base_helpers import deep_get

EC2_CRUD_ACTIONS = {
    "AssociateIamInstanceProfile",
    "AssociateInstanceEventWindow",
    "BundleInstance",
    "CancelSpotInstanceRequests",
    "ConfirmProductInstance",
    "CreateInstanceEventWindow",
    "CreateInstanceExportTask",
    "DeleteInstanceEventWindow",
    "DeregisterInstanceEventNotificationAttributes",
    "DisassociateIamInstanceProfile",
    "DisassociateInstanceEventWindow",
    "ImportInstance",
    "ModifyInstanceAttribute",
    "ModifyInstanceCapacityReservationAttributes",
    "ModifyInstanceCreditSpecification",
    "ModifyInstanceEventStartTime",
    "ModifyInstanceEventWindow",
    "ModifyInstanceMaintenanceOptions",
    "ModifyInstanceMetadataOptions",
    "ModifyInstancePlacement",
    "MonitorInstances",
    "RegisterInstanceEventNotificationAttributes",
    "ReportInstanceStatus",
    "RequestSpotInstances",
    "ResetInstanceAttribute",
    "RunInstances",
    "RunScheduledInstances",
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
    "UnmonitorInstances",
}

ALLOWED_ARNS = {"*ExampleArn*"}


def rule(event):
    # Disqualify any eventSource that is not ec2
    if event.get("eventSource", "") != "ec2.amazonaws.com":
        return False
    # Disqualify AWS Service-Service operations, which can appear in a variety of forms
    if (
        # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
        #  events with ec2.amazonaws.com as the source name where users of the
        #  web-console will have their sourceIPAddress recorded as "AWS Internal"
        #  though their userIdentity will be more normal.
        #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
        event.get("sourceIPAddress", "").endswith(".amazonaws.com")
        or deep_get(event, "userIdentity", "type", default="") == "AWSService"
        or deep_get("userIdentity", "invokedBy", default="") == "AWS Internal"
        or deep_get("userIdentity", "invokedBy", default="").endswith(".amazonaws.com")
    ):
        return False
    # Dry run operations get logged as SES Internal in the sourceIPAddress
    #  but not in the invokedBy field
    if event.get("errorCode", "") == "Client.DryRunOperation":
        return False
    # Disqualify any eventNames that do not Include instance
    # and events that have readOnly set to false
    if event.get("eventName", "") in EC2_CRUD_ACTIONS:
        useridentity_arn = deep_get(event, "userIdentity", "arn", default="<arn_not_found>")
        for allowed_arn in ALLOWED_ARNS:
            if fnmatch(useridentity_arn, allowed_arn):
                return False
        return True
    return False


def title(event):
    items = deep_get(event, "requestParameters", "instancesSet", "items", default=[{}])
    actor = deep_get(event, "usersIdentity", "arn", default="<arn_not_found>")
    return (
        f"AWS: [{actor}] "
        f"performed [{event.get('eventName', '<event_not_found>')}] "
        f"on Instance [{items[0].get('instanceId', '<instance_id_not_found>')}] "
        f"in AWS Account [{event.get('recipientAccountId', '<account_id_not_found>')}]"
    )


def alert_context(event):
    items = deep_get(event, "requestParameters", "instancesSet", "items")
    return {
        "awsRegion": event.get("awsRegion"),
        "eventName": event.get("eventName"),
        "recipientAccountId": event.get("recipientAccountId"),
        "instanceId": items[0].get("instanceId"),
    }
