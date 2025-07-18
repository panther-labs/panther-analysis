def rule(event):
    if event.deep_get("action", default="") in [
        "business_secret_scanning_custom_pattern_push_protection.disabled",
        "business_secret_scanning_push_protection.disable",
        "business_secret_scanning_push_protection.disabled_for_new_repos",
        "org.secret_scanning_custom_pattern_push_protection_disabled",
        "org.secret_scanning_push_protection_disable",
        "org.secret_scanning_push_protection_new_repos_disable",
        "repository_secret_scanning_custom_pattern_push_protection.disabled",
    ]:
        return True
    return False
