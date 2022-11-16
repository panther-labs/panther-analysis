from panther_base_helpers import aws_rule_context

def rule(event):
    # Return True to match the log event and trigger an alert.
    event_names = ['CreateTrafficMirrorFilter','CreateTrafficMirrorFilterRule','CreateTrafficMirrorSession', 'CreateTrafficMirrorTarget', 'DeleteTrafficMirrorFilter', 'DeleteTrafficMirrorFilterRule', 'DeleteTrafficMirrorSession', 'DeleteTrafficMirrorTarget', 'DescribeTrafficMirrorFilters', 'DescribeTrafficMirrorSessions', 'DescribeTrafficMirrorTargets', 'ModifyTrafficMirrorFilterNetworkServices', 'ModifyTrafficMirrorFilterRule', 'ModifyTrafficMirrorSession']
    if 'ec2' in event.get('eventSource') and event.get('eventName') in event_names:
        # continue on with analysis 
        return True
    else:
        return False

def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as deduplication string.
    return f"{event.get('userIdentity',{}).get('type','no-type')} ec2 activity found for {event.get('eventName')} in account {event.get('recipientAccountId')} in region {event.get('awsRegion')}."

def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # Dedupe based on user identity, to not include multiple events from the same identity.
    return f"{event.get('userIdentity',{}).get('arn','no-user-identity-provided')}"

def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
    return aws_rule_context(event)
