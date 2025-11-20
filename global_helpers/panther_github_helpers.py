import re

from panther_base_helpers import deep_get

# Bash injection patterns focused on command substitution attacks
# Based on Nx vulnerability (GHSA-cxm3-wv7p-598c): $(echo "You've been compromised")
# These patterns detect malicious content in untrusted GitHub inputs like PR titles,
# issue bodies, commit messages, etc.
BASH_INJECTION_PATTERNS = [
    # Command substitution
    r"\$\([^)]+\)",  # $(command) - requires non-empty command
    # Variable expansion with command substitution
    r"\$\{[^}]*\$\([^)]+\)[^}]*\}",  # ${var$(cmd)var}
    r"\$\{[^}]*`[^`]+`[^}]*\}",  # ${var`cmd`var}
    # Process substitution
    r"<\([^)]+\)",  # <(command)
    r">\([^)]+\)",  # >(command)
    # Direct shell invocation
    r"/bin/(?:sh|bash|dash|zsh)\s+-c\s+",  # /bin/bash -c "command"
    r"(?:bash|sh)\s+-c\s+['\"]",  # bash -c "command"
    # Encoding/obfuscation attempts
    r"\\x[0-9a-fA-F]{4,}",  # Multiple hex bytes (longer sequences)
    r"eval\s*\(\s*\$",  # eval($(...)) patterns
    r"exec\s*\(\s*\$",  # exec($(...)) patterns
    # Network exfiltration patterns
    r"(?:curl|wget)\s+[^|>]+\|\s*(?:sh|bash)",  # curl url | bash
    r"nc\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9]+",  # nc IP PORT
]

COMPILED_BASH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in BASH_INJECTION_PATTERNS
]


def contains_bash_injection_pattern(text):
    """
    Check if text contains any bash injection patterns.

    Args:
        text: String to check for bash injection patterns

    Returns:
        bool: True if any pattern matches, False otherwise
    """
    if not text:
        return False
    return any(pattern.search(text) for pattern in COMPILED_BASH_PATTERNS)


def get_matched_bash_patterns(text):
    """
    Get all matched bash injection patterns from text.

    Args:
        text: String to analyze for bash injection patterns

    Returns:
        list: List of dicts containing pattern and matches, empty list if none found
    """
    if not text:
        return []
    return [
        {
            "pattern": pattern.pattern,
            "match": pattern.findall(text),
        }
        for pattern in COMPILED_BASH_PATTERNS
        if pattern.search(text)
    ]


def github_alert_context(event):
    return {
        "action": event.get("action", ""),
        "actor": event.get("actor", ""),
        "actor_location": event.deep_get("actor_location", "country_code"),
        "org": event.get("org", ""),
        "repo": event.get("repo", ""),
        "user": event.get("user", ""),
    }


def is_cross_fork_pr(event):
    """
    Check if this is a cross-fork pull request.

    Args:
        event: GitHub webhook event

    Returns:
        bool: True if this is a cross-fork PR (head repo != base repo), False otherwise
    """
    # Check direct pull_request event
    head_repo = event.deep_get("pull_request", "head", "repo", "full_name")
    base_repo = event.deep_get("pull_request", "base", "repo", "full_name")

    if head_repo and base_repo:
        return head_repo != base_repo

    # Check workflow_run event with pull_requests array
    pull_requests = event.deep_get("workflow_run", "pull_requests", default=[])
    for pull_request in pull_requests:
        pr_head_repo = deep_get(pull_request, "head", "repo", "id")
        pr_base_repo = deep_get(pull_request, "base", "repo", "id")
        if pr_head_repo and pr_base_repo and pr_head_repo != pr_base_repo:
            return True

    # Check workflow_run event with head_repository (for workflows from forks)
    # GitHub doesn't always populate pull_requests array, but head_repository is reliable
    head_repository = event.deep_get("workflow_run", "head_repository")
    base_repository = event.deep_get("workflow_run", "repository")

    if head_repository and base_repository:
        head_repo_id = head_repository.get("id")
        base_repo_id = base_repository.get("id")
        if head_repo_id and base_repo_id and head_repo_id != base_repo_id:
            return True

    return False


def is_pull_request_event(event):
    """
    Check if this is a pull request related webhook event.

    Args:
        event: GitHub webhook event

    Returns:
        bool: True if this is a pull request event, False otherwise
    """
    pr_actions = [
        "opened",
        "synchronize",
        "reopened",
        "closed",
        "assigned",
        "unassigned",
        "labeled",
        "unlabeled",
        "edited",
        "ready_for_review",
        "converted_to_draft",
    ]
    return event.get("action") in pr_actions and event.get("pull_request") is not None


def github_webhook_alert_context(event):
    """
    Enhanced GitHub webhook alert context for GitHub.Webhook log type.
    Provides more detailed context than the basic github_alert_context.

    Args:
        event: GitHub webhook event

    Returns:
        dict: Enhanced alert context with repository, sender, pull request, and push info
    """
    context = github_alert_context(event)

    # Add repository details
    repository = event.get("repository", {})
    context["repository"] = {
        "name": repository.get("name"),
        "full_name": repository.get("full_name"),
        "private": repository.get("private"),
        "fork": repository.get("fork"),
        "default_branch": repository.get("default_branch"),
        "html_url": repository.get("html_url"),
    }

    # Add sender details
    sender = event.get("sender", {})
    if sender:
        context["sender"] = {
            "login": sender.get("login"),
            "id": sender.get("id"),
            "type": sender.get("type"),
            "html_url": sender.get("html_url"),
        }

    # Add pull request details if this is a PR event
    if is_pull_request_event(event):
        pull_request = event.get("pull_request", {})
        context["pull_request"] = {
            "number": pull_request.get("number"),
            "title": pull_request.get("title"),
            "state": pull_request.get("state"),
            "user": deep_get(pull_request, "user", "login"),
            "draft": pull_request.get("draft"),
            "html_url": pull_request.get("html_url"),
            "created_at": pull_request.get("created_at"),
            "updated_at": pull_request.get("updated_at"),
        }

        # Add fork analysis for PR events
        context["fork_analysis"] = {
            "is_cross_fork": is_cross_fork_pr(event),
            "head_repo": deep_get(pull_request, "head", "repo", "full_name"),
            "base_repo": deep_get(pull_request, "base", "repo", "full_name"),
            "head_ref": deep_get(pull_request, "head", "ref"),
            "base_ref": deep_get(pull_request, "base", "ref"),
            "head_sha": deep_get(pull_request, "head", "sha"),
            "base_sha": deep_get(pull_request, "base", "sha"),
        }

    # Add push details if this is a push event
    pusher = event.get("pusher")
    if pusher:
        context["push_details"] = {
            "pusher": pusher,
            "ref": event.get("ref"),
            "before": event.get("before"),
            "after": event.get("after"),
            "forced": event.get("forced"),
            "size": len(event.get("commits", [])),
        }

        # Add head commit details for push events
        head_commit = event.get("head_commit", {})
        if head_commit:
            context["head_commit"] = {
                "id": head_commit.get("id"),
                "message": head_commit.get("message"),
                "author": head_commit.get("author", {}).get("name"),
                "committer": head_commit.get("committer", {}).get("name"),
                "timestamp": head_commit.get("timestamp"),
                "url": head_commit.get("url"),
            }

    return context


def github_reference_url(event):
    """
    Generate a reference URL for GitHub webhook events to link back to the source.

    Args:
        event: GitHub webhook event

    Returns:
        str: URL to the PR, commit, or repository depending on event type, or None if unavailable
    """
    # For pull request events, link to the PR
    if is_pull_request_event(event):
        pr_url = deep_get(event, "pull_request", "html_url")
        if pr_url:
            return pr_url

    # For push events, link to the compare view
    compare_url = event.get("compare")
    if compare_url:
        return compare_url

    # Fallback to workflow run URL
    workflow_run_url = deep_get(event, "workflow_run", "html_url")
    if workflow_run_url:
        return workflow_run_url

    # Fallback to repository URL
    repo_url = deep_get(event, "repository", "html_url")
    if repo_url:
        return repo_url

    return None
