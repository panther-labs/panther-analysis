import json
from datetime import timedelta

import panther_event_type_helpers as event_type
from panther_oss_helpers import put_string_set, resolve_timestamp_string

# Days an account is considered new
TTL = timedelta(days=3)


def parse_new_account_id(event):
    if event.get("serviceEventDetails"):
        details = json.loads(event.get("serviceEventDetails"))
        return str(details.get("createAccountStatus").get("accountId"))
    return "<UNKNOWN ACCOUNT ID>"


def rule(event):
    if event.udm("event_type") != event_type.ACCOUNT_CREATED:
        return False
    account_id = parse_new_account_id(event)
    event_time = resolve_timestamp_string(event.get("p_event_time"))
    expiry_time = event_time + TTL
    account_event_id = f"new_aws_account_{event.get('p_row_id')}"

    if account_id:
        put_string_set(
            "new_account - " + account_id, [account_event_id], expiry_time.strftime("%s")
        )

    return True


def title(event):
    return f"A new AWS account has been created. Account ID - [{parse_new_account_id(event)}]"
