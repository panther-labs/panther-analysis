import re

from panther_github_helpers import github_alert_context

# pylint: disable=line-too-long
# Suspicious package manager and installation tool patterns
SUSPICIOUS_PATTERNS = [
    # NPM patterns
    # https://github.com/npm/cli/blob/latest/workspaces/config/lib/definitions/definitions.js#L2137
    # Format: npm/{version} node/v{version} {platform} {arch} workspaces/{boolean} [ci/{name}]
    r"npm/\d+\.\d+\.\d+\s+node/v\d+\.\d+\.\d+\s+\w+\s+\w+\s+workspaces/(?:true|false)(?:\s+ci/\w+)?",
    # Yarn patterns
    # https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/scriptUtils.ts#L187-L192
    # "yarn/{version} npm/? node/{version} {platform} {arch}"
    r"yarn/\d+\.\d+\.\d+(?:-core)?\s+npm/\?\s+node/v\d+\.\d+\.\d+\s+\w+\s+\w+",
    # Python pip patterns
    # https://github.com/pypa/pip/blob/main/src/pip/_internal/network/session.py#L204
    # "pip/24.0 {"ci":null,"cpu":"aarch64","distro":{"name":"Alpine Linux"...}}"
    r"pip/\d+\.\d+(?:\.\d+)?\s+\{.*\}",
    # Ruby Gem patterns
    # https://github.com/rubygems/rubygems/blob/master/lib/rubygems/request.rb#L276
    # Ruby, RubyGems/{version} {platform} Ruby/{version} ({date} patchlevel {number})
    r"Ruby,\s+RubyGems/\d+\.\d+\.\d+\s+[\w-]+\s+Ruby/\d+\.\d+\.\d+\s+\([^)]+\)",
    # Rust Cargo patterns
    # https://github.com/rust-lang/cargo/blob/master/src/cargo/util/network/http.rs#L76
    # Default user agent: handle.useragent(&format!("cargo/{}", version()))?;
    r"cargo/\d+\.\d+\.\d+",
]


# Compile regex patterns for performance
COMPILED_SUSPICIOUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS
]


def rule(event):
    user_agent = event.get("user_agent", "")
    action = event.get("action", "")

    # Allow legitimate dependency installation actions
    legitimate_actions = {
        "git.clone",
        "git.fetch",
        "git.pull",
        "git.checkout",
        "git.archive",
        "repo.download",
    }

    if action in legitimate_actions:
        return False

    if not user_agent or len(user_agent) < 3:
        return False

    for compiled_pattern in COMPILED_SUSPICIOUS_PATTERNS:
        match = compiled_pattern.search(user_agent)
        if match:
            return True
    return False


def title(event):
    user_agent = event.get("user_agent", "")
    action = event.get("action", "")
    detected_pattern = "unknown"
    for compiled_pattern in COMPILED_SUSPICIOUS_PATTERNS:
        match = compiled_pattern.search(user_agent)
        if match:
            detected_pattern = match.group()

    return f"GitHub Supply Chain - Package Manager Modifying Repository ({detected_pattern} - {action})"


def alert_context(event):
    context = github_alert_context(event)
    user_agent = event.get("user_agent", "")

    detected_pattern = "unknown"
    for compiled_pattern in COMPILED_SUSPICIOUS_PATTERNS:
        match = compiled_pattern.search(user_agent)
        if match:
            detected_pattern = match.group()

    context.update(
        {
            "user_agent": user_agent,
            "detected_pattern": detected_pattern,
            "user_agent_length": len(user_agent),
            "programmatic_access_type": event.get("programmatic_access_type"),
            "action": event.get("action"),
            "repo": event.get("repo"),
            "analysis_note": "Package managers should only read dependencies, not modify repositories",
        }
    )

    return context


def dedup(event):
    user_agent = event.get("user_agent", "")
    actor = event.get("actor", "<NO_ACTOR>")

    return f"{user_agent}_{actor}"
