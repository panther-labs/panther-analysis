from global_filter_github import filter_include_event
from panther_base_helpers import github_alert_context

def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "organization_moderators.add_user"


def title(event):
    return (
        f"GitHub.Audit: User [{event.get('actor', '<UNKNOWN_ACTOR>')}] added user "
        f"[{event.get('user', '<UNKNOWN_USER>')}] to moderators in "
        f"[{event.get('org','<UNKNOWN_ORG>')}]"
    )


def alert_context(event):
    return github_alert_context(event)
