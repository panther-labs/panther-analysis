import re

from panther_github_helpers import (
    github_reference_url,
    github_webhook_alert_context,
    is_cross_fork_pr,
    is_pull_request_event,
)

# Bash injection patterns focused on command substitution attacks
# Based on Nx vulnerability (GHSA-cxm3-wv7p-598c): $(echo "You've been compromised")
BASH_INJECTION_PATTERNS = [
    # Command substitution
    r"\$\([^)]+\)",  # $(command) - requires non-empty command
    r"`[^`]+`",  # `command` - requires non-empty command
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


def rule(event):
    if not is_pull_request_event(event) or event.deep_get("action") != "opened":
        return False

    if pr_title := event.deep_get("pull_request", "title"):
        return any(pattern.search(pr_title) for pattern in COMPILED_BASH_PATTERNS)
    return False


def _get_matched_patterns(text):
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


def title(event):
    pr_number = event.deep_get("pull_request", "number", default="<UNKNOWN>")
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    action = event.get("action", "<UNKNOWN_ACTION>")

    return f"Malicious pattern detected in PR #{pr_number} in {repo_name} ({action})"


def alert_context(event):
    context = github_webhook_alert_context(event)

    # Analyze patterns found in title
    title_patterns = _get_matched_patterns(event.deep_get("pull_request", "title"))
    context["title_analysis"] = {
        "contains_malicious_patterns": len(title_patterns) > 0,
        "matched_patterns": title_patterns,
    }

    return context


def reference(event):
    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"


def severity(event):
    if is_cross_fork_pr(event):
        return "DEFAULT"

    return "LOW"
