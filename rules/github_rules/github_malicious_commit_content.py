from panther_github_helpers import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


def rule(event):
    # Check for push events with commits
    if not (event.get("commits") or event.get("head_commit")):
        return False

    # Check head_commit fields (single commit in push)
    if head_commit := event.get("head_commit"):
        fields_to_check = [
            head_commit.get("message"),
            head_commit.get("author", {}).get("email"),
            head_commit.get("author", {}).get("name"),
        ]
        for field in fields_to_check:
            if contains_bash_injection_pattern(field):
                return True

    # Check all commits in the push
    for commit in event.get("commits", []):
        commit_fields = [
            commit.get("message"),
            commit.get("author", {}).get("email"),
            commit.get("author", {}).get("name"),
        ]
        for field in commit_fields:
            if contains_bash_injection_pattern(field):
                return True

    return False


def title(event):
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    ref = event.get("ref", "<UNKNOWN_REF>")

    return f"Malicious pattern detected in commit content in {repo_name} on {ref}"


def alert_context(event):
    context = github_webhook_alert_context(event)

    context["malicious_commits"] = []

    # Analyze head_commit
    if head_commit := event.get("head_commit"):
        commit_analysis = _analyze_commit(head_commit)
        if commit_analysis["has_malicious_patterns"]:
            context["malicious_commits"].append(commit_analysis)

    # Analyze all commits
    for commit in event.get("commits", []):
        commit_analysis = _analyze_commit(commit)
        if commit_analysis["has_malicious_patterns"]:
            context["malicious_commits"].append(commit_analysis)

    return context


def _analyze_commit(commit):
    """Analyze a single commit for malicious patterns."""
    analysis = {
        "commit_id": commit.get("id"),
        "message": commit.get("message"),
        "author": commit.get("author", {}).get("name"),
        "author_email": commit.get("author", {}).get("email"),
        "timestamp": commit.get("timestamp"),
        "url": commit.get("url"),
        "has_malicious_patterns": False,
        "field_analysis": {},
    }

    # Check message
    if message := commit.get("message"):
        patterns = get_matched_bash_patterns(message)
        if patterns:
            analysis["has_malicious_patterns"] = True
            analysis["field_analysis"]["message"] = {
                "value": message,
                "matched_patterns": patterns,
            }

    # Check author email
    if author_email := commit.get("author", {}).get("email"):
        patterns = get_matched_bash_patterns(author_email)
        if patterns:
            analysis["has_malicious_patterns"] = True
            analysis["field_analysis"]["author_email"] = {
                "value": author_email,
                "matched_patterns": patterns,
            }

    # Check author name
    if author_name := commit.get("author", {}).get("name"):
        patterns = get_matched_bash_patterns(author_name)
        if patterns:
            analysis["has_malicious_patterns"] = True
            analysis["field_analysis"]["author_name"] = {
                "value": author_name,
                "matched_patterns": patterns,
            }

    return analysis


def reference(event):
    # Try to get the compare URL
    if compare_url := event.get("compare"):
        return compare_url

    # Try head commit URL
    if head_commit_url := event.deep_get("head_commit", "url"):
        return head_commit_url

    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"
