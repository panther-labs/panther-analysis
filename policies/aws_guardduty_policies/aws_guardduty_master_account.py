from panther_base_helpers import deep_get

# Set the MASTER_ACCOUNT_ID variable to a string
# of the AWS Master Account receiving GuardDuty logs.
MASTER_ACCOUNT_ID = None


def policy(resource):
    if MASTER_ACCOUNT_ID is None:
        return True

    if resource["Master"] is None:
        return False

    return MASTER_ACCOUNT_ID == deep_get(resource, "Master", "AccountId")
