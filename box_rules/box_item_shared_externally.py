from panther_base_helpers import deep_get
from panther_box_helpers import is_box_sdk_enabled, lookup_box_file, lookup_box_folder  # pylint: disable=import-error

ALLOWED_SHARED_ACCESS = ['collaborators', 'company']
SHARE_EVENTS = [
    'CHANGE_FOLDER_PERMISSION',
    'ITEM_SHARED',
    'ITEM_SHARED_CREATE',
    'ITEM_SHARED_UPDATE',
    'SHARE',
]


def rule(event):
    # filter events
    if event.get('event_type') not in SHARE_EVENTS:
        return False
    # only try to lookup file/folder info if sdk is enabled in the env
    if is_box_sdk_enabled():
        item = get_item(event)
        if item is not None and item['shared_link']:
            return deep_get(item, 'shared_link',
                            'effective_access') not in ALLOWED_SHARED_ACCESS
    return False


def get_item(event):
    item_id = deep_get(event, 'source', 'item_id', default='')
    user_id = deep_get(event, 'source', 'owned_by', 'id', default='')
    item = {}
    if deep_get(event, 'source', 'item_type') == 'folder':
        item = lookup_box_folder(user_id, item_id)
    elif deep_get(event, 'source', 'item_type') == 'file':
        item = lookup_box_file(user_id, item_id)
    return item


def title(event):
    message = ('User [{}] shared an item [{}] externally.')
    return message.format(
        deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>'),
        deep_get(event, 'source', 'item_name', default='<UNKNOWN_NAME>'))
