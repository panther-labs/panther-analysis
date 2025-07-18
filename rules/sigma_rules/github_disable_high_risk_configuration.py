def rule(event):
    if event.deep_get("action", default="") in [
        "business_advanced_security.disabled_for_new_repos",
        "business_advanced_security.disabled_for_new_user_namespace_repos",
        "business_advanced_security.disabled",
        "business_advanced_security.user_namespace_repos_disabled",
        "org.advanced_security_disabled_for_new_repos",
        "org.advanced_security_disabled_on_all_repos",
        "org.advanced_security_policy_selected_member_disabled",
        "org.disable_oauth_app_restrictions",
        "org.disable_two_factor_requirement",
        "repo.advanced_security_disabled",
    ]:
        return True
    return False
