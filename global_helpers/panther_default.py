# Define common code here that all of your policies and rules can share.
#
# Example usage:
#
# import panther
# def policy(resource):
#     return panther.example_helper()
#


def example_helper():
    return True


AWS_ACCOUNTS = {
    # Add your AWS account IDs/names below:
    '123456789012': 'sample-account',
}


def lookup_aws_account_name(account_id):
    '''Lookup the AWS account name, return the ID if not found

    Args:
        account_id (str): The AWS account ID

    Returns:
        str: The name of the AWS account ID
    '''
    return AWS_ACCOUNTS.get(account_id, account_id)


def aws_event_tense(event_name):
    '''Convert an AWS CloudTrail eventName to be interpolated in alert titles

    An example is passing in StartInstance and returning 'started'.
    This would then be used in an alert title such as
    'The EC2 instance my-instance was started'.

    Args:
        event_name (str): The CloudTrail eventName

    Returns:
        str: A tensed version of the event name
    '''
    mapping = {
        'Create': 'created',
        'Delete': 'deleted',
        'Start': 'started',
        'Stop': 'stopped',
        'Update': 'updated',
    }
    for event_prefix, tensed in mapping.items():
        if event_name.startswith(event_prefix):
            return tensed
    # If the event pattern doesn't exist, return original
    return event_name
