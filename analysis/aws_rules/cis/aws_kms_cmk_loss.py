# API calls that are indicative of KMS CMK Deletion
KMS_LOSS_EVENTS = {
    'DisableKey',
    'ScheduleKeyDeletion',
}


def rule(event):
    return event['eventName'] in KMS_LOSS_EVENTS
