# Define common code here that all of your policies and rules can share.
#
# Example usage:
#
# import panther_default
# def policy(resource):
#     return panther.example_helper()
#


import base64
import binascii
from typing import List


def example_helper():
    return True


AWS_ACCOUNTS = {
    # Add your AWS account IDs/names below:
    "123456789012": "sample-account",
}


def lookup_aws_account_name(account_id):
    """Lookup the AWS account name, return the ID if not found

    Args:
        account_id (str): The AWS account ID

    Returns:
        str: The name of the AWS account ID
        or
        str: The AWS account ID (unnamed account)
    """
    return AWS_ACCOUNTS.get(account_id, f"{account_id} (unnamed account)")


def aws_cloudtrail_success(event):
    if event.get("errorCode", "") or event.get("errorMessage", ""):
        return False
    return True


def aws_event_tense(event_name):
    """Convert an AWS CloudTrail eventName to be interpolated in alert titles

    An example is passing in StartInstance and returning 'started'.
    This would then be used in an alert title such as
    'The EC2 instance my-instance was started'.

    Args:
        event_name (str): The CloudTrail eventName

    Returns:
        str: A tensed version of the event name
    """
    mapping = {
        "Create": "created",
        "Delete": "deleted",
        "Start": "started",
        "Stop": "stopped",
        "Update": "updated",
    }
    for event_prefix, tensed in mapping.items():
        if event_name.startswith(event_prefix):
            return tensed
    # If the event pattern doesn't exist, return original
    return event_name


# Adapted from https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
def aws_key_account_id(aws_key: str):
    """retrieve the AWS account ID associated with a given access key ID"""
    key_no_prefix = aws_key[4:]  # remove the four-character prefix
    base32_key = base64.b32decode(key_no_prefix)  # remainder of the key is base32-encoded
    decoded_key = base32_key[0:6]  # retrieve the 10-byte string

    # Convert the 10-byte string to an integer
    key_id_int = int.from_bytes(decoded_key, byteorder="big", signed=False)
    mask = int.from_bytes(binascii.unhexlify(b"7fffffffff80"), byteorder="big", signed=False)

    # Do a bitwise AND with the mask to retrieve the account ID
    # (divide the 10-byte key integer by 128 and remove the fractional part(s))
    account_id = (key_id_int & mask) >> 7
    return str(account_id)


def aws_regions() -> List[str]:
    """return a list of AWS regions"""
    return [
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ca-central-1",
        "ca-central-1",
        "eu-central-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-1",
        "eu-west-2",
        "eu-west-2",
        "eu-west-3",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]

