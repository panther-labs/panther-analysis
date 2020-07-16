from fnmatch import fnmatch
# pylint: disable=line-too-long
BUCKET_ROLE_MAPPING = {
    'panther-bootstrap-processeddata-*': [
        'arn:aws:sts::*:assumed-role/panther-cloud-security-EventProcessorFunctionRole-*/panther-aws-event-processor',
        'arn:aws:sts::*:assumed-role/panther-log-analysis-AthenaApiFunctionRole-*/panther-athena-api',
        'arn:aws:sts::*:assumed-role/panther-log-analysis-RulesEngineFunctionRole-*/panther-rules-engine',
        'arn:aws:sts::*:assumed-role/panther-snowflake-logprocessing-role-*/snowflake'
        'arn:aws:sts::*:assumed-role/panther-data-replication-role-*/s3-replication'
    ]
}
# pylint: enable=line-too-long


def _unknown_requester_access(event):
    for bucket_pattern, role_patterns in BUCKET_ROLE_MAPPING.items():
        if not fnmatch(event.get('bucket', ''), bucket_pattern):
            continue
        if not any([
                fnmatch(event.get('requester', ''), role_pattern)
                for role_pattern in role_patterns
        ]):
            return True
    return False


def rule(event):
    if event.get('errorcode'):
        return False

    return (event.get('operation') == 'REST.GET.OBJECT' and
            _unknown_requester_access(event))


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Unknown requester accessing data from S3 Bucket [{}]'.format(
        event.get('bucket'))
