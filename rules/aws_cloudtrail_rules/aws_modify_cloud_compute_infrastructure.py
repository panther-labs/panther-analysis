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
    if event.udm("event_source", default="") != "ec2.amazonaws.com":
        return False
    # Disqualify AWS Service-Service operations, which can appear in a variety of forms
    if (
        # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
        #  events with ec2.amazonaws.com as the source name where users of the
        #  web-console will have their sourceIPAddress recorded as "AWS Internal"
        #  though their userIdentity will be more normal.
        #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
        event.udm("source_ip_address", default="").endswith(".amazonaws.com")
        or event.udm("user_type", default="") == "AWSService"
        or event.udm("invoked_by", default="") == "AWS Internal"
        or event.udm("invoked_by", default="").endswith(".amazonaws.com")
    ):
        return False
    # Dry run operations get logged as SES Internal in the sourceIPAddress
    #  but not in the invokedBy field
    if event.udm("error_code", default="") == "Client.DryRunOperation":
        return False
    # Disqualify any eventNames that do not Include instance
    # and events that have readOnly set to false
    if event.udm("event_name", default="") in EC2_CRUD_ACTIONS:
        return True
    return False


def title(event):
    return (
        f"AWS Event [{event.udm('event_name')}] "
        f"AWS Account ID [{event.udm('recipient_account_id')}]"
    )


def alert_context(event):
    items = event.udm("request_items")
    return {
        "awsRegion": event.udm("cloud_region"),
        "eventName": event.udm("event_name"),
        "recipientAccountId": event.udm("recipient_account_id"),
        "instanceId": items[0].get("instanceId"),
    }
