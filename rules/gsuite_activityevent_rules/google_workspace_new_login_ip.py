import json
from datetime import datetime, timedelta

from panther_base_helpers import deep_get
from panther_oss_helpers import get_string_set, put_string_set

ALERT_CONTEXT_DICTIONARY = {}

# Store the record in Dynamo for each user, for this amount of days
# If the user does not log in within this period,
#   the record will expire, and the next login will alert
DYNAMO_CACHE_DAYS = 30


def rule(event):
    # see: https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login
    is_login_event = event.get("type") == "login" and event.get("name") == "login_success"
    if not is_login_event:
        return False

    ip_address = get_ip_address(event)
    user_identifier = get_user_identifier(event)

    if not ip_address or not user_identifier:
        # We can only alert if there was an IP and a user_identifier (email)
        #   associated with the login
        return False

    event_key = get_dynamo_key(user_identifier)

    # name|user_identifier : set(ip_address)
    user_ip_history_raw = load_from_dynamo(event_key)
    user_ip_history = list(user_ip_history_raw)  # cannot append to a set() or serialize it to json

    ALERT_CONTEXT_DICTIONARY["previous_ips"] = user_ip_history.copy()

    # If no previous login record exists,
    #   store the current login and exit to prevent a false positive
    if not user_ip_history:
        user_ip_history.append(ip_address)
        save_to_dynamo(event_key, user_ip_history)
        return False

    # This IP has not logged in before - alert, and then store the IP to prevent subsequent alerts
    if ip_address not in user_ip_history:
        ALERT_CONTEXT_DICTIONARY["current_ip"] = ip_address

        user_ip_history.append(ip_address)
        save_to_dynamo(event_key, user_ip_history)

        return True

    return False


def title(event):
    user_identifier = get_user_identifier(event)
    ip_address = get_ip_address(event)
    return f"New Google Workspace login IP for user '{user_identifier}' from '{ip_address}'"


def alert_context():
    return ALERT_CONTEXT_DICTIONARY


##### End Panther Override Functions #####


def get_dynamo_key(user_identifier):
    # The key to store the data in Dynamo.
    # '__name__' results in it being unique to this detection,
    #   and 'user_identifier' results in 1 record per user

    # If you want to do some debugging,
    #   add characters to the end of this string to cause temporary cache invalidation.
    # Don't forget to remove it when done, though!

    return f"{__name__}|{user_identifier}"


def get_user_identifier(event):
    return deep_get(event, "actor", "email")


def get_ip_address(event):
    return event.get("ipAddress")


def load_from_dynamo(event_key):
    dynamo_result_raw = get_string_set(event_key)

    result = None
    if isinstance(dynamo_result_raw, str):
        # mocking returns all mocked objects in a string
        # so we must convert the unit test object into the type dynamo sends (a set)
        if dynamo_result_raw:
            result = json.loads(dynamo_result_raw)
        else:
            result = set()
    else:
        result = dynamo_result_raw

    if not isinstance(result, set):
        raise Exception(
            f"Expected dynamo result to be a set, was '{type(result)}',",
            f" value: '{result}', raw value: '{dynamo_result_raw}'",
        )

    return result


def save_to_dynamo(event_key, dynamo_data):
    # For this specific record,
    #   extend the expiration in Dynamo to 'DYNAMO_CACHE_DAYS' days from now
    new_key_expiration = str((datetime.now() + timedelta(days=DYNAMO_CACHE_DAYS)).timestamp())

    put_string_set(event_key, dynamo_data, new_key_expiration)
