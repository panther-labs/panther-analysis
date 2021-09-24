import json

from panther_base_helpers import deep_get
from policyuniverse.policy import Policy

# According to AWS there should exist an explicit deny policy that contains
# "aws:SecureTransport": "false" for this check to be compliant
# https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/
# This policy returns a LOW severity alert if the bucket policy is using an implicit deny
# of secure transport or a HIGH severity if secure transport is not enforced.

IMPLICIT_DENY = True


def policy(resource):
    if resource["Policy"] is None:
        return False

    explicit_deny = False
    global IMPLICIT_DENY  # pylint: disable=global-statement
    # Reset global to prevent it getting stepped on by reuse in the Lambda invocation
    IMPLICIT_DENY = True

    iam_policy = Policy(json.loads(resource["Policy"]))

    for statement in iam_policy.statements:
        if (
            statement.effect == "Deny"
            and deep_get(statement.statement, "Condition", "Bool", "aws:SecureTransport") != "true"
        ):
            explicit_deny = True
            break

        if (
            statement.effect == "Allow"
            and deep_get(statement.statement, "Condition", "Bool", "aws:SecureTransport") != "true"
        ):
            IMPLICIT_DENY = False

    return explicit_deny


def severity(_):
    if IMPLICIT_DENY:
        return "LOW"
    return "HIGH"


def title(resource):
    if IMPLICIT_DENY:
        return f"{resource.get('name')} lacks an explicit deny policy for Secure Transport"
    return f"{resource.get('name')} does not enforce Secure Transport"
