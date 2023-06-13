from global_filter_notion import filter_include_event
from panther_base_helpers import deep_get
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    return deep_get(event, "type", default="<NO_EVENT_TYPE_FOUND>") == "page.deleted"


def title(event):
    user = deep_get(event, "actor", "person", "email", default="<NO_USER_FOUND>")
    page_id = deep_get(event, "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
    return f"Notion User [{user}] deleted multiple pages with page ids [{page_id}]."


def alert_context(event):
    return notion_alert_context(event)
