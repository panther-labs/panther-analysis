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
