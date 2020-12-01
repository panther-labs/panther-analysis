# API calls that are indicative of KMS CMK Deletion
KMS_LOSS_EVENTS = {'DisableKey', 'ScheduleKeyDeletion'}
KMS_KEY_TYPE = 'AWS::KMS::Key'


def rule(event):
    return event['eventName'] in KMS_LOSS_EVENTS


def dedup(event):
    for resource in event.get('resources', {}) or {}:
        if resource.get('type', '') == KMS_KEY_TYPE:
            return resource['ARN']
    return event.get('p_row_id')
