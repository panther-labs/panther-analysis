from panther_base_helpers import deep_get
from panther_box_helpers import is_box_sdk_enabled, lookup_box_file, lookup_box_folder

ALLOWED_SHARED_ACCESS = {"collaborators", "company"}
SHARE_EVENTS = {
    "CHANGE_FOLDER_PERMISSION",
    "ITEM_SHARED",
    "ITEM_SHARED_CREATE",
    "ITEM_SHARED_UPDATE",
    "SHARE",
}


def rule(event):
    # filter events
    if event.get("event_type") not in SHARE_EVENTS:
        return False
    # only try to lookup file/folder info if sdk is enabled in the env
    if is_box_sdk_enabled():
        item = get_item(event)
        if item is not None and item.get("shared_link"):
            return deep_get(item, "shared_link", "effective_access") not in ALLOWED_SHARED_ACCESS
    return False


def get_item(event):
    item_id = event.deep_get("source", "item_id", default="")
    user_id = event.deep_get("source", "owned_by", "id", default="")
    item = {}
    if event.deep_get("source", "item_type") == "folder":
        item = lookup_box_folder(user_id, item_id)
    elif event.deep_get("source", "item_type") == "file":
        item = lookup_box_file(user_id, item_id)
    return item


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] shared an item "
        f"[{event.deep_get('source', 'item_name', default='<UNKNOWN_NAME>')}] externally."
    )
