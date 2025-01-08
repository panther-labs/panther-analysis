from typing import List

import panther_aws_helpers

# panther_default.AWS_ACCOUNTS is DEPRECATED!!!  Instead use panther_aws_helpers.AWS_ACCOUNTS
AWS_ACCOUNTS = panther_aws_helpers.AWS_ACCOUNTS


def lookup_aws_account_name(account_id):
    """Global `lookup_aws_account_name` is DEPRECATED.
    Instead, use `from panther_aws_helpers import lookup_aws_account_name`."""
    return panther_aws_helpers.lookup_aws_account_name(account_id)


def aws_cloudtrail_success(event):
    """Global `aws_cloudtrail_success` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_cloudtrail_success`."""
    return panther_aws_helpers.aws_cloudtrail_success(event)


def aws_event_tense(event_name):
    """Global `aws_event_tense` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_event_tense`."""
    return panther_aws_helpers.aws_event_tense(event_name)


def aws_key_account_id(aws_key: str):
    """Global `aws_key_account_id` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_key_account_id`."""
    return panther_aws_helpers.aws_key_account_id(aws_key)


def aws_regions() -> List[str]:
    """Global `aws_regions` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_regions`."""
    return panther_aws_helpers.aws_regions()
