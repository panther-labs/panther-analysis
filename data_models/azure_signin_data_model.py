import panther_event_type_helpers as event_type
from panther_azuresignin_helpers import actor_user, is_sign_in_event
from panther_base_helpers import deep_get


def get_event_type(event):
    if not is_sign_in_event(event):
        return None

    error_code = deep_get(event, "properties", "status", "errorCode", default=0)
    if error_code == 0:
        return event_type.SUCCESSFUL_LOGIN
    return event_type.FAILED_LOGIN


def get_actor_user(event):
    return actor_user(event)
