from panther_oss_helpers import get_string_set, put_string_set


def rule(event):
    if event.get("action").startswith("git."):
        # trigger on any of the git actions, http or ssh
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
