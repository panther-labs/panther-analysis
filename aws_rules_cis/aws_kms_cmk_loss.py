# API calls that are indicative of KMS CMK Deletion
KMS_LOSS_EVENTS = {'DisableKey', 'ScheduleKeyDeletion'}
KMS_KEY_TYPE = 'AWS::KMS::Key'


def rule(event):
    return event.get('eventName') in KMS_LOSS_EVENTS


def dedup(event):
    for resource in event['resources']:
        if resource['type'] == KMS_KEY_TYPE:
            return resource['ARN']
    return None
