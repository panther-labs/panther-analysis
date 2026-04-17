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


def rule(event):
    # Disqualify any eventSource that is not ec2
    if event.get("eventSource", "") != "ec2.amazonaws.com":
        return False
    if event.get("readOnly"):
        return False
    # Disqualify AWS Service-Service operations, which can appear in a variety of forms
    if (
        # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
        #  events with ec2.amazonaws.com as the source name where users of the
        #  web-console will have their sourceIPAddress recorded as "AWS Internal"
        #  though their userIdentity will be more normal.
        #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
        event.get("sourceIPAddress", "").endswith(".amazonaws.com")
        or event.deep_get("userIdentity", "type", default="") == "AWSService"
        or event.deep_get("userIdentity", "invokedBy", default="") == "AWS Internal"
        or event.deep_get("userIdentity", "invokedBy", default="").endswith(".amazonaws.com")
    ):
        return False
    # Dry run operations get logged as SES Internal in the sourceIPAddress
    #  but not in the invokedBy field
    if event.get("errorCode", "") == "Client.DryRunOperation":
        return False
    # Disqualify any eventNames that do not Include instance
    # and events that have readOnly set to false
    if event.get("eventName", "") in EC2_CRUD_ACTIONS:
        return True
    return False


def title(event):
    items = event.deep_get(
        "requestParameters", "instancesSet", "items", default=[{"instanceId": "none"}]
    )
    return (
        f"AWS Event [{event.get('eventName')}] Instance ID "
        f"[{items[0].get('instanceId')}] AWS Account ID [{event.get('recipientAccountId')}]"
    )


def dedup(event):
    items = event.deep_get(
        "requestParameters",
        "instancesSet",
        "items",
        default=[{"instanceId": "INSTANCE_ID_NOT_FOUND"}],
    )
    return items[0].get("instanceId", "INSTANCE_ID_NOT_FOUND")


def alert_context(event):
    items = event.deep_get(
        "requestParameters", "instancesSet", "items", default=[{"instanceId": "none"}]
    )
    return {
        "awsRegion": event.get("awsRegion"),
        "eventName": event.get("eventName"),
        "recipientAccountId": event.get("recipientAccountId"),
        "instanceId": items[0].get("instanceId"),
    }
