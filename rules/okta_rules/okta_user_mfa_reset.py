import panther_event_type_helpers as event_type
from panther_base_helpers import okta_alert_context


def rule(event):
    return event.udm("event_type") == event_type.MFA_RESET


def title(event):
    try:
        which_factor = event.get("outcome", {}).get("reason", "").split()[2]
    except IndexError:
        which_factor = "<FACTOR_NOT_FOUND>"
    return (
        f"Okta: User reset their MFA factor [{which_factor}] "
        f"[{event.get('target',[{}])[0].get('alternateId', '<id-not-found>')}] "
        f"by [{event.get('actor',{}).get('alternateId','<id-not-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
