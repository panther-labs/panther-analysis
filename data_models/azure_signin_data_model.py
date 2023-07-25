import panther_event_type_helpers as event_type
from panther_azuresignin_helpers import actor_user
from panther_base_helpers import deep_get


def get_event_type(event):
    operation = deep_get(event, "operationName", default="")
    error_code = deep_get(event, "properties", "status", "errorCode", default=0)
    if operation == "Sign-in activity":
        if error_code == 0:
            return event_type.SUCCESSFUL_LOGIN
        return event_type.FAILED_LOGIN
    return None


def get_actor_user(event):
    return actor_user(event)
