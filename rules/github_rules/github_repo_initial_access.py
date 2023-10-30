from global_filter_github import filter_include_event
from panther_detection_helpers.caching import get_string_set, put_string_set

CODE_ACCESS_ACTIONS = [
    "git.clone",
    "git.push",
    "git.fetch",
]


def rule(event):
    if not filter_include_event(event):
        return False
    # if the actor field is empty, short circuit the rule
    if not event.udm("actor_user"):
        return False

    if event.get("action") in CODE_ACCESS_ACTIONS and not event.get("repository_public"):
        # Compute unique entry for this user + repo
        key = get_key(event)
        previous_access = get_string_set(key)
        if not previous_access:
            put_string_set(key, key)
            return True
    return False


def title(event):
    return (
        f"A user [{event.udm('actor_user')}] accessed a private repository "
        f"[{event.get('repo', '<UNKNOWN_REPO>')}] for the first time."
    )


def get_key(event):
    return __name__ + ":" + str(event.udm("actor_user")) + ":" + str(event.get("repo"))
