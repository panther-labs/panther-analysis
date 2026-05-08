#!/usr/bin/env python3
"""Pre-commit hook that runs a Claude Code review on changed detection files."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def eprint(*args, **kwargs):
    """Print to stderr so output is visible when run via pre-commit."""
    print(*args, file=sys.stderr, **kwargs)

# ─── Configuration ───────────────────────────────────────────────
REVIEW_EXTENSIONS = {".py", ".yml", ".yaml", ".sql"}
EXCLUDE_PATTERNS = re.compile(r"\.env$|\.pem$|\.key$|credentials\.json|secrets\.json|\.secret")
MAX_FILES = 100
REPO_ROOT = Path(__file__).resolve().parent.parent


def run_git(*args):
    """Run a git command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        return None


def get_changed_files():
    """Get reviewable staged files."""
    output = run_git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    if not output:
        return []

    files = []
    for f in output.splitlines():
        path = Path(f)
        if path.suffix in REVIEW_EXTENSIONS and not EXCLUDE_PATTERNS.search(f):
            files.append(f)
            if len(files) >= MAX_FILES:
                break
    return files


def read_file_contents(files):
    """Read staged contents of each file (from git index, not working tree)."""
    parts = []
    for f in files:
        content = run_git("show", f":{f}")
        if content is not None:
            parts.append(f"--- FILE: {f} ---\n{content}\n--- END: {f} ---")
    return "\n\n".join(parts)


def load_style_guides():
    """Load all style guide markdown files."""
    style_dir = REPO_ROOT / "style_guides"
    if not style_dir.is_dir():
        return ""

    parts = []
    for guide in sorted(style_dir.glob("*.md")):
        content = guide.read_text(encoding="utf-8", errors="replace")
        parts.append(f"--- STYLE GUIDE: {guide.name} ---\n{content}\n--- END: {guide.name} ---")
    return "\n\n".join(parts)


def build_review_prompt(changed_files, file_contents, style_guides):
    """Build the review prompt."""
    has_queries = any(f.startswith("queries/") for f in changed_files)
    has_correlation = any(f.startswith("correlation_rules/") for f in changed_files)

    query_section = (
        """Query files detected — review these:
- Filename format: `<LogProvider>.<QueryTitle>.Query.yml`
- DisplayName format: "LogProvider QueryTitle"
- Snowflake SQL syntax correctness
- LIMIT clause present where sensible
- Time range filter (p_event_time or similar)
- Use `p_any_*` fields when possible
- Select specific fields, not `SELECT *`
- Readable and performant"""
        if has_queries
        else "No query files in this change — skip this section."
    )

    correlation_section = (
        "\n### 7. Correlation Rules\nReview against CORRELATION_RULES_STYLE_GUIDE.md provided above."
        if has_correlation
        else ""
    )

    file_list = "\n".join(changed_files)

    return f"""You are a thorough code reviewer for a Panther SIEM security detection rules repository.

Review ONLY the following changed files. Report only actual issues found — do not invent problems.

**Changed files:**
{file_list}

**File contents:**
{file_contents}

**Style guides (use these as the authoritative reference):**
{style_guides}

---

## Review Areas

### 1. Style Guide Compliance
Review adherence to the style guides provided above:
- File naming conventions
- Code formatting, imports, line length
- Comment and docstring style
- Import organization

### 2. Python Logic (.py files)
- **Event handling**: Always use `event.get()`, `event.deep_get()`, `event.deep_walk()` — never raw dict access like `event["key"]` or nested `.get().get()` chains
  - Good: `event.deep_get("userIdentity", "userName", default="<UNKNOWN_USER>")`
  - Bad: `event.get("userIdentity", {{}}).get("userName")`
- **`title()` functions**: 2-3 dynamic fields max, always with `default=<UNKNOWN_FIELD_NAME>`
- **`dedup()` functions**: Needed if title has many dynamic fields
- **`rule()`/`policy()` logic**: Correctness, edge cases, false positive potential
- **`alert_context()`**: Use safe accessors; if the same pattern appears in 3+ rules, it belongs in global_helpers
- **`severity()`**: Dynamic severity logic correctness
- **Security**: No hardcoded credentials, secrets, or API keys
- **Error handling**: Proper patterns for external calls

### 3. YAML Metadata (.yml files)
- **Description**: Concise, clear, ~3 sentences explaining what the rule detects. No verbose or repetitive language.
- **Severity**:
  - High/Critical = precise attack detection, minimal false positives
  - Medium = less precise or potential false positives
  - Low/Info = broad or informational
- **MITRE ATT&CK**: Appropriate technique/sub-technique mapping for the use case
- **Tags**: Friendly names for MITRE mapping (Tactics > Techniques > Subtechniques), plus use case refs (e.g. "Ransomware", "Exfiltration")
- **References**: URLs relevant to the use case (security research, docs, other rule repos)
- **Status**: New rules, correlation_rules, and scheduled_rules MUST have `Status: Experimental`. (Not applicable to queries.)
- **Required fields**: RuleID/PolicyID format, DisplayName clarity, LogTypes/ResourceTypes, Enabled status

### 4. Tests (in YAML files)
- At least one positive AND one negative test per rule
- Edge cases covered (empty fields, missing keys, boundary values)
- Realistic but anonymized log samples — no real production data
- Descriptive test names explaining what they validate
- Correct ExpectedResult values

### 5. Queries (only if files in queries/ path)
{query_section}

### 6. Architecture & Patterns
- Correct directory structure for detection type
- Dual-file architecture (.py + .yml) present
- Consistent with similar existing detections
- Proper imports and dependencies
{correlation_section}

## Output Format

Structure your review as:

## Review Summary
**Overall:** [PASS / ISSUES FOUND]
[1-2 sentence summary]

## Findings
[Group by file. For each issue: file path, line number if applicable, what's wrong, and how to fix it.]
[Use warning emoji for warnings and x emoji for blocking issues.]
[Skip sections with no issues — do not pad with praise.]

If everything looks good, say **PASS** with a brief confirmation — do not invent problems."""


def run_claude_with_spinner(cmd, prompt, spinner_msg="Working..."):
    """Run a Claude command with a spinner. Returns (stdout, stderr, success)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(prompt)
        prompt_file = f.name

    stop_spinner = threading.Event()

    def spinner():
        chars = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
        i = 0
        while not stop_spinner.is_set():
            eprint(f"\r   {chars[i % len(chars)]} {spinner_msg}", end="", flush=True)
            i += 1
            time.sleep(0.1)
        eprint("\r" + " " * (len(spinner_msg) + 10) + "\r", end="")

    spin_thread = threading.Thread(target=spinner, daemon=True)
    spin_thread.start()

    try:
        with open(prompt_file) as stdin_f:
            result = subprocess.run(
                cmd,
                stdin=stdin_f,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                text=True,
                cwd=REPO_ROOT,
            )
        return result.stdout.strip(), "", result.returncode == 0
    finally:
        stop_spinner.set()
        spin_thread.join()
        os.unlink(prompt_file)


def run_claude_review(prompt):
    """Run Claude in print mode for review. Returns (output, success)."""
    stdout, _stderr, success = run_claude_with_spinner(
        ["claude", "--print", "-"], prompt, "Reviewing..."
    )
    return stdout, success


def run_claude_fix(prompt):
    """Run Claude to apply fixes. Returns (output, success)."""
    stdout, stderr, success = run_claude_with_spinner(
        ["claude", "-p", "-", "--allowedTools", "Edit,Read", "--permission-mode", "acceptEdits"],
        prompt,
        "Fixing...",
    )
    return stdout, success


def check_for_issues(review_output):
    """Determine if the review found issues."""
    # Match only the verdict line: **Overall:** PASS or **Overall:** ISSUES FOUND
    # Use MULTILINE so ^ anchors to line start, preventing body text matches
    if re.search(
        r"^\*{0,2}Overall:?\*{0,2}\s*\*{0,2}ISSUES FOUND\*{0,2}",
        review_output,
        re.IGNORECASE | re.MULTILINE,
    ):
        return True
    if re.search(
        r"^\*{0,2}Overall:?\*{0,2}\s*\*{0,2}PASS\*{0,2}",
        review_output,
        re.IGNORECASE | re.MULTILINE,
    ):
        return False
    # Fallback: check for emoji markers
    if "\u26a0\ufe0f" in review_output or "\u274c" in review_output:
        return True
    # If we can't determine the verdict, assume issues (fail safe)
    return True


def prompt_user(message, valid_choices):
    """Prompt the user for input via /dev/tty."""
    try:
        with open("/dev/tty", "r") as tty:
            eprint(message, flush=True)
            answer = tty.readline().strip().lower()
            return answer if answer in valid_choices else None
    except (OSError, EOFError):
        return None


def is_interactive():
    """Check if we can prompt the user (terminal or /dev/tty available)."""
    try:
        with open("/dev/tty", "r"):
            return True
    except OSError:
        return False


def main():
    # Skip in non-interactive environments (GitHub Desktop, IDE git, CI)
    if not is_interactive():
        eprint("Skipping Claude review (non-interactive environment).")
        return 0

    # Check for claude CLI
    if not shutil.which("claude"):
        eprint("\u274c 'claude' CLI not found.")
        eprint()
        eprint("Setup:")
        eprint("  1. Install the Claude CLI: https://docs.anthropic.com/en/docs/claude-code/overview")
        eprint("  2. Run: make install-pre-commit-hooks")
        eprint()
        eprint("To skip this check: git commit --no-verify")
        return 1

    # Get changed files
    changed_files = get_changed_files()
    if not changed_files:
        eprint("\u2705 No reviewable files staged (.py, .yml, .yaml, .sql). Skipping review.")
        return 0

    # Print header
    eprint("\u2500" * 50)
    eprint(f"\U0001f50d Claude Code Review \u2014 pre-commit")
    eprint(f"   Reviewing {len(changed_files)} staged file(s)")
    eprint("\u2500" * 50)
    for f in changed_files:
        eprint(f"   {f}")
    eprint()

    # Build prompt
    file_contents = read_file_contents(changed_files)
    style_guides = load_style_guides()
    review_prompt = build_review_prompt(changed_files, file_contents, style_guides)

    # Run review
    eprint("\u23f3 Running review (this may take 30-60 seconds)...")
    eprint()

    review_output, review_success = run_claude_review(review_prompt)

    if not review_success or not review_output:
        eprint("\u26a0\ufe0f  Claude review failed.")
        eprint()
        answer = prompt_user("Commit anyway? (y/n)", {"y", "n"})
        return 0 if answer == "y" else 1

    # Display results
    eprint("\u2550" * 50)
    eprint("\U0001f4cb REVIEW RESULTS")
    eprint("\u2550" * 50)
    eprint()
    eprint(review_output)
    eprint()
    eprint("\u2550" * 50)

    # Check for issues
    if not check_for_issues(review_output):
        eprint("\u2705 No issues found. Proceeding with commit.")
        return 0

    # Offer options
    eprint()
    eprint("Options:")
    eprint("  f) Apply fixes automatically")
    eprint("  p) Commit anyway")
    eprint("  a) Abort")
    eprint()
    answer = prompt_user("Choose (f/p/a):", {"f", "p", "a"})

    if answer == "p":
        eprint("\u2705 Committing...")
        return 0
    if answer != "f":
        eprint("\u274c Commit aborted. Fix the findings and try again.")
        return 1

    # Apply fixes
    eprint()
    eprint("\u23f3 Applying fixes (this may take 30-60 seconds)...")

    fix_prompt = f"""You are fixing issues found during code review in a Panther SIEM detection rules repository.

Here are the review findings:

{review_output}

Apply ALL the suggested fixes to the actual files. Only modify what the review flagged — do not make other changes.

Files to fix:
{chr(10).join(changed_files)}"""

    fix_output, fix_success = run_claude_fix(fix_prompt)

    if not fix_success:
        eprint("\u26a0\ufe0f  Auto-fix failed. Please fix manually.")
        if fix_output:
            eprint(fix_output)
        return 1

    eprint("\u2705 Done.")
    if fix_output:
        eprint()
        eprint(fix_output)
        eprint()

    # Run formatters
    eprint()
    eprint("\u23f3 Running formatters...")
    subprocess.run(["make", "fmt"], cwd=REPO_ROOT, capture_output=True)

    # Show diff for review before staging
    eprint()
    eprint("\u2500" * 50)
    eprint("\U0001f4ca Changes applied:")
    eprint("\u2500" * 50)
    subprocess.run(
        ["git", "diff", "--", *changed_files],
        cwd=REPO_ROOT,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )
    eprint("\u2500" * 50)
    eprint()

    answer = prompt_user("Stage these changes? (y/n)", {"y", "n"})
    if answer != "y":
        eprint("\u274c Changes not staged. Review the diff and stage manually.")
        return 1

    subprocess.run(["git", "add", *changed_files], cwd=REPO_ROOT)
    eprint("\u2705 Fixes staged. Continuing with commit...")
    return 0  # Let the commit proceed with the fixed files


if __name__ == "__main__":
    sys.exit(main())
