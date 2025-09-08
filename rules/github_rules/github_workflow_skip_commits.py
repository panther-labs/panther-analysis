import re

from panther_github_helpers import github_reference_url, github_webhook_alert_context

SKIP_PATTERNS = [
    r"\[skip ci\]",
    r"\[ci skip\]",
    r"\[no ci\]",
    r"\[skip actions\]",
    r"\[actions skip\]",
    r"skip-checks:\s*true",
]

COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SKIP_PATTERNS]


def rule(event):
    if not event.get("pusher"):
        return False

    repo = event.get("repository", {})
    if repo.get("private") or not repo.get("allow_forking"):
        return False

    messages = event.deep_walk("commits", "message")
    if not isinstance(messages, list):
        messages = [messages]

    for message in messages:
        if _has_skip_pattern(message):
            return True

    return False


def _has_skip_pattern(message):
    if not message:
        return False

    return any(pattern.search(message) for pattern in COMPILED_PATTERNS)


def title(event):
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    head_commit = event.deep_get("head_commit", default={})
    commit_sha = head_commit.get("id", "<NO_SHA>")[:8]

    return f"Cross-fork workflow skip commit detected in {repo_name} ({commit_sha})"


def alert_context(event):
    context = github_webhook_alert_context(event)

    skip_commits = []

    commits = event.get("commits", [{}])
    for commit in commits:
        commit_message = commit.get("message", "")
        if _has_skip_pattern(commit_message):
            matched_patterns = [
                SKIP_PATTERNS[i]
                for i, pattern in enumerate(COMPILED_PATTERNS)
                if pattern.search(commit_message)
            ]

            skip_commits.append(
                {
                    "id": commit.get("id"),
                    "message": commit_message,
                    "author": commit.get("author", {}).get("name"),
                    "matched_patterns": matched_patterns,
                }
            )

    context["skip_commits"] = skip_commits

    return context


def reference(event):
    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"
