from panther_base_helpers import pattern_match_list
from panther_github_helpers import github_alert_context

APP_TOKEN_TYPE = "GitHub App server-to-server token"

# Protected-branch writes the organisation's own automation is expected to make,
# keyed on the audit event's numeric repo_id so no repository name is published here.
EXPECTED_BOT_OVERRIDES = {
    "256069557": ["refs/heads/main"],
    "499630320": ["refs/heads/main"],
    "243627255": ["refs/heads/release-*"],
}


def is_bot_actor(event):
    return (
        event.get("actor_is_bot") is True
        or str(event.get("actor", "")).endswith("[bot]")
        or event.get("programmatic_access_type") == APP_TOKEN_TYPE
    )


def is_expected_override(event):
    patterns = EXPECTED_BOT_OVERRIDES.get(str(event.get("repo_id", "")), [])
    return pattern_match_list(event.get("branch", ""), patterns)


def rule(event):
    if event.get("action") != "protected_branch.policy_override":
        return False
    return is_bot_actor(event) and not is_expected_override(event)


def title(event):
    return (
        f"Bot [{event.get('actor', '<UNKNOWN_ACTOR>')}] overrode branch protection"
        f" on [{event.get('branch', '<UNKNOWN_BRANCH>')}]"
        f" in [{event.get('repo', '<UNKNOWN_REPO>')}]"
    )


def dedup(event):
    return f"{event.get('repo', '')}:{event.get('branch', '')}:{event.get('actor', '')}"


def alert_context(event):
    context = github_alert_context(event)
    for field in (
        "repo_id",
        "branch",
        "actor_is_bot",
        "programmatic_access_type",
        "token_id",
        "rule_suite_id",
        "before",
        "after",
        "overridden_codes",
    ):
        context[field] = event.get(field)
    return context
