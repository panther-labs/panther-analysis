import json

from panther_base_helpers import deep_get
from policyuniverse.policy import Policy

# According to AWS there should exist an explicit deny policy that contains
# "aws:SecureTransport": "false" for this check to be compliant
# https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/
# This policy returns a LOW severity alert if the bucket policy is using an implicit deny
# of secure transport or a HIGH severity if secure transport is not enforced.

IMPLICIT_DENY = False


def policy(resource):
    if resource["Policy"] is None:
        return False

    iam_policy = Policy(json.loads(resource["Policy"]))

    for statement in iam_policy.statements:
        if (
            statement.effect == "Deny"
            and deep_get(statement.statement, "Condition", "Bool", "aws:SecureTransport") == "false"
        ):
            return True

        if (
            statement.effect == "Allow"
            and deep_get(statement.statement, "Condition", "Bool", "aws:SecureTransport") == "true"
        ):
            global IMPLICIT_DENY  # pylint: disable=global-statement
            IMPLICIT_DENY = True
            return True

    return False


def severity(_):
    if IMPLICIT_DENY:
        return "LOW"
    return "HIGH"
