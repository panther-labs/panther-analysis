from global_filter_github import filter_include_event
from panther_base_helpers import github_alert_context

# List of actions in markdown format
# pylint: disable=line-too-long
# https://github.com/github/docs/blob/main/content/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise.md
# grep '^| `' audit-log-events-for-your-enterprise.md.txt | sed -e 's/\| //' -e 's/`//g' | awk -F\| '{if ($1 ~ /business/) {print $1}}'
# pylint: enable=line-too-long

# {GitHub Action: Alert Severity}
ADV_SEC_ACTIONS = {
    "dependabot_alerts.disable": "CRITICAL",
    "dependabot_alerts_new_repos.disable": "HIGH",
    "dependabot_security_updates.disable": "CRITICAL",
    "dependabot_security_updates_new_repos.disable": "HIGH",
    "repository_secret_scanning_push_protection.disable": "HIGH",
    "secret_scanning.disable": "CRITICAL",
    "secret_scanning_new_repos.disable": "HIGH",
    "bypass": "MEDIUM",  # Bypass secret scanner push protection for a detected secret.
    # pylint: disable=line-too-long
    # The events that begin with "business" are seemingly from enterprise logs
    # business.disable_oidc  -  OIDC single sign-on was disabled for an enterprise.
    "business.disable_oidc": "CRITICAL",
    # business.disable_saml  -  SAML single sign-on was disabled for an enterprise.
    "business.disable_saml": "CRITICAL",
    # business.disable_two_factor_requirement  -  The requirement for members to
    #    have two-factor authentication enabled to access an enterprise was disabled.
    "business.disable_two_factor_requirement": "CRITICAL",
    # business.members_can_update_protected_branches.disable  -  The ability for
    #    enterprise members to update branch protection rules was disabled.
    #    Only enterprise owners can update protected branches.
    "business.members_can_update_protected_branches.disable": "MEDIUM",
    # business.referrer_override_disable  -  An enterprise owner or site administrator
    #    disabled the referrer policy override.
    "business.referrer_override_disable": "MEDIUM",
    # business_advanced_security.disabled  -  {% data
    #    variables.product.prodname_GH_advanced_security %}
    #    was disabled for your enterprise. For more information, see "[Managing
    #    {% data variables.product.prodname_GH_advanced_security %}
    #    features for your enterprise]
    #    (/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_advanced_security.disabled": "CRITICAL",
    # business_advanced_security.disabled_for_new_repos  -  {% data
    #    variables.product.prodname_GH_advanced_security %} was disabled for
    #    new repositories in your enterprise. For more information, see
    #    "[Managing {% data variables.product.prodname_GH_advanced_security %} features
    #    for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_advanced_security.disabled_for_new_repos": "HIGH",
    # business_secret_scanning.disable  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning.disable": "CRITICAL",
    # business_secret_scanning.disabled_for_new_repos  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning.disabled_for_new_repos": "CRITICAL",
    # business_secret_scanning_custom_pattern_push_protection.disabled  -  Push protection for a custom pattern for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Defining custom patterns for {% data variables.product.prodname_secret_scanning %}](/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning#defining-a-custom-pattern-for-an-enterprise-account)."
    "business_secret_scanning_custom_pattern_push_protection.disabled": "HIGH",
    # business_secret_scanning_push_protection.disable  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection.disable": "CRITICAL",
    # business_secret_scanning_push_protection.disabled_for_new_repos  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection.disabled_for_new_repos": "HIGH",
    # business_secret_scanning_push_protection_custom_message.disable  -  The custom message triggered by an attempted push to a push-protected repository was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection_custom_message.disable": "XXXX",
    #
    # There are also correlating github _org_ level events
    "org.advanced_security_disabled_for_new_repos": "HIGH",
    "org.advanced_security_disabled_on_all_repos": "CRITICAL",
    # org.advanced_security_policy_selected_member_disabled - An enterprise owner prevented {% data variables.product.prodname_GH_advanced_security %} features from being enabled for repositories owned by the organization. {% data reusables.advanced-security.more-information-about-enforcement-policy %}
    # pylint: enable=line-too-long
    "org.advanced_security_policy_selected_member_disabled": "HIGH",
    "repo.advanced_security_disabled": "CRITICAL",
    "repo.advanced_security_policy_selected_member_disabled": "HIGH",
}


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action", "") in ADV_SEC_ACTIONS


def title(event):
    action = event.get("action", "")
    advanced_sec_text = ""
    # https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security#about-advanced-security-features
    if "advanced_security" in action or "secret_scanning" in action:
        advanced_sec_text = "Advanced "
    return f"Change detected to GitHub {advanced_sec_text}Security - {event.get('action', '')}"


def alert_context(event):
    return github_alert_context(event)


# Use the per action severity configured above
def severity(event):
    return ADV_SEC_ACTIONS.get(event.get("action", ""), "Low")


def dedup(event):
    # 1. Actor
    # 2. Action
    # We should dedup on actor - action
    actor = event.get("actor", "<NO_ACTOR>")
    action = event.get("action", "<NO_ACTION>")
    return "_".join([actor, action])
