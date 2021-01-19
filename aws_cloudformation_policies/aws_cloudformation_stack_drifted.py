from panther_base_helpers import deep_get

# CloudFormation stacks tagged with "STACK=(name)" will be marked as passing.
IGNORE_STACK_TAGS = {
    'panther-bootstrap-gateway', 'panther-cloud-security', 'panther-core',
    'panther-log-analysis'
}


def policy(resource):
    if deep_get(resource, 'DriftInformation', 'StackDriftStatus') != "DRIFTED":
        return True

    # Some of Panther's own stacks contain Lambda functions which will always show as "drifted."
    # Panther stacks have a fixed "Stack" tag, even though the real stack name is dynamic.
    tags = resource['Tags']
    if tags.get('Application') == 'Panther' and tags.get(
            'Stack') in IGNORE_STACK_TAGS:
        return True

    return False
