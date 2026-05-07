#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────
REVIEW_EXTENSIONS='\.py$|\.yml$|\.yaml$|\.sql$'
EXCLUDE_PATTERNS='\.env$|\.pem$|\.key$|credentials\.json|secrets\.json|\.secret'
MAX_FILES=100

# ─── Determine changed files ────────────────────────────────────
# Compare HEAD against the remote tracking branch.
# Falls back to origin/develop, then origin/main.
remote_branch=""
for candidate in "HEAD@{upstream}" "origin/develop" "origin/main"; do
    if git rev-parse --verify "$candidate" >/dev/null 2>&1; then
        remote_branch="$candidate"
        break
    fi
done

if [[ -z "$remote_branch" ]]; then
    echo "⚠️  Could not determine remote branch to diff against. Skipping review."
    exit 0
fi

changed_files=()
while IFS= read -r line; do
    changed_files+=("$line")
done < <(
    git diff --name-only --diff-filter=ACMR "$remote_branch"...HEAD \
    | grep -E "$REVIEW_EXTENSIONS" \
    | grep -vE "$EXCLUDE_PATTERNS" \
    | head -n "$MAX_FILES"
)

if [[ ${#changed_files[@]} -eq 0 ]]; then
    echo "✅ No reviewable files changed (.py, .yml, .yaml, .sql). Skipping review."
    exit 0
fi

echo "───────────────────────────────────────────────────"
echo "🔍 Claude Code Review — pre-push"
echo "   Reviewing ${#changed_files[@]} file(s) against $remote_branch"
echo "───────────────────────────────────────────────────"
printf '   %s\n' "${changed_files[@]}"
echo ""

# ─── Build file contents block for the prompt ────────────────────
file_contents=""
for f in "${changed_files[@]}"; do
    if [[ -f "$f" ]]; then
        file_contents+="
--- FILE: $f ---
$(cat "$f")
--- END: $f ---
"
    fi
done

# ─── Load style guides ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

style_guide_contents=""
for guide in "$REPO_ROOT"/style_guides/*.md; do
    if [[ -f "$guide" ]]; then
        style_guide_contents+="
--- STYLE GUIDE: $(basename "$guide") ---
$(cat "$guide")
--- END: $(basename "$guide") ---
"
    fi
done

# ─── Detect if PR contains queries ──────────────────────────────
has_queries=false
for f in "${changed_files[@]}"; do
    if [[ "$f" == queries/* ]]; then
        has_queries=true
        break
    fi
done

# ─── Detect if PR contains correlation rules ────────────────────
has_correlation=false
for f in "${changed_files[@]}"; do
    if [[ "$f" == correlation_rules/* ]]; then
        has_correlation=true
        break
    fi
done

# ─── Run Claude Code ─────────────────────────────────────────────
review_prompt="You are a thorough code reviewer for a Panther SIEM security detection rules repository.

Review ONLY the following changed files. Report only actual issues found — do not invent problems.

**Changed files:**
$(printf '%s\n' "${changed_files[@]}")

**File contents:**
$file_contents

**Style guides (use these as the authoritative reference):**
$style_guide_contents

---

## Review Areas

### 1. Style Guide Compliance
Review adherence to the style guides provided above:
- File naming conventions
- Code formatting, imports, line length
- Comment and docstring style
- Import organization

### 2. Python Logic (.py files)
- **Event handling**: Always use \`event.get()\`, \`event.deep_get()\`, \`event.deep_walk()\` — never raw dict access like \`event[\"key\"]\` or nested \`.get().get()\` chains
  - Good: \`event.deep_get(\"userIdentity\", \"userName\", default=\"<UNKNOWN_USER>\")\`
  - Bad: \`event.get(\"userIdentity\", {}).get(\"userName\")\`
- **\`title()\` functions**: 2-3 dynamic fields max, always with \`default=<UNKNOWN_FIELD_NAME>\`
- **\`dedup()\` functions**: Needed if title has many dynamic fields
- **\`rule()\`/\`policy()\` logic**: Correctness, edge cases, false positive potential
- **\`alert_context()\`**: Use safe accessors; if the same pattern appears in 3+ rules, it belongs in global_helpers
- **\`severity()\`**: Dynamic severity logic correctness
- **Security**: No hardcoded credentials, secrets, or API keys
- **Error handling**: Proper patterns for external calls

### 3. YAML Metadata (.yml files)
- **Description**: Concise, clear, ~3 sentences explaining what the rule detects. No verbose or repetitive language.
- **Severity**:
  - High/Critical = precise attack detection, minimal false positives
  - Medium = less precise or potential false positives
  - Low/Info = broad or informational
- **MITRE ATT&CK**: Appropriate technique/sub-technique mapping for the use case
- **Tags**: Friendly names for MITRE mapping (Tactics → Techniques → Subtechniques), plus use case refs (e.g. \"Ransomware\", \"Exfiltration\")
- **References**: URLs relevant to the use case (security research, docs, other rule repos)
- **Status**: New rules, correlation_rules, and scheduled_rules MUST have \`Status: Experimental\`. (Not applicable to queries.)
- **Required fields**: RuleID/PolicyID format, DisplayName clarity, LogTypes/ResourceTypes, Enabled status

### 4. Tests (in YAML files)
- At least one positive AND one negative test per rule
- Edge cases covered (empty fields, missing keys, boundary values)
- Realistic but anonymized log samples — no real production data
- Descriptive test names explaining what they validate
- Correct ExpectedResult values

### 5. Queries (only if files in queries/ path)
$(if $has_queries; then echo "Query files detected — review these:
- Filename format: \`<LogProvider>.<QueryTitle>.Query.yml\`
- DisplayName format: \"LogProvider QueryTitle\"
- Snowflake SQL syntax correctness
- LIMIT clause present where sensible
- Time range filter (p_event_time or similar)
- Use \`p_any_*\` fields when possible
- Select specific fields, not \`SELECT *\`
- Readable and performant"; else echo "No query files in this change — skip this section."; fi)

### 6. Architecture & Patterns
- Correct directory structure for detection type
- Dual-file architecture (.py + .yml) present
- Consistent with similar existing detections
- Proper imports and dependencies

$(if $has_correlation; then echo "### 7. Correlation Rules
Review against CORRELATION_RULES_STYLE_GUIDE.md provided above."; fi)

## Output Format

Structure your review as:

## Review Summary
**Overall:** [PASS / ISSUES FOUND]
[1-2 sentence summary]

## Findings
[Group by file. For each issue: file path, line number if applicable, what's wrong, and how to fix it.]
[Use ⚠️ for warnings and ❌ for blocking issues.]
[Skip sections with no issues — do not pad with praise.]

If everything looks good, say **PASS** with a brief confirmation — do not invent problems."

if ! command -v claude &>/dev/null; then
    echo "❌ 'claude' CLI not found."
    echo ""
    echo "Setup:"
    echo "  1. Install the Claude CLI: https://docs.anthropic.com/en/docs/claude-code/overview"
    echo "  2. Run: make install-pre-commit-hooks"
    echo ""
    echo "To skip this check: git push --no-verify"
    exit 1
fi

echo "⏳ Running review (this may take 30-60 seconds)..."
echo ""

err_file=$(mktemp)
trap 'rm -f "$err_file" "${fix_log:-}" "${prompt_file:-}" "${fix_prompt_file:-}"' EXIT
prompt_file=$(mktemp)
printf '%s' "$review_prompt" > "$prompt_file"
review_output=$(claude --print - < "$prompt_file" 2>"$err_file") || {
    stderr_output=$(cat "$err_file" 2>/dev/null)
    echo "⚠️  Claude review failed."
    [[ -n "${stderr_output:-}" ]] && echo "Error: $stderr_output"
    echo ""
    echo "Push anyway? (y/n)"
    read -r answer < /dev/tty
    if [[ "$answer" =~ ^[Yy] ]]; then
        exit 0
    else
        exit 1
    fi
}

echo "═══════════════════════════════════════════════════"
echo "📋 REVIEW RESULTS"
echo "═══════════════════════════════════════════════════"
echo ""
echo "$review_output"
echo ""
echo "═══════════════════════════════════════════════════"

# ─── Check if review found issues ───────────────────────────────
has_issues=false
# Check for explicit PASS first (case-insensitive, flexible formatting)
if echo "$review_output" | grep -qiE '\*{0,2}Overall:?\*{0,2}\s*\*{0,2}PASS\*{0,2}'; then
    has_issues=false
# Check for explicit ISSUES FOUND
elif echo "$review_output" | grep -qiE '\*{0,2}Overall:?\*{0,2}\s*\*{0,2}ISSUES FOUND\*{0,2}'; then
    has_issues=true
# Fallback: check for emoji markers in findings (not in meta-commentary)
elif echo "$review_output" | grep -qE '⚠️|❌'; then
    has_issues=true
fi

if ! $has_issues; then
    echo "✅ No issues found. Proceeding with push."
    exit 0
fi

# ─── Offer to apply fixes ──────────────────────────────────────
echo ""
echo "Options:"
echo "  f) Apply fixes automatically"
echo "  p) Push anyway"
echo "  a) Abort"
echo ""
echo "Choose (f/p/a):"
read -r answer < /dev/tty

case "$answer" in
    [Ff])
        echo ""
        echo "⏳ Applying fixes (this may take 30-60 seconds)..."
        fix_prompt="You are fixing issues found during code review in a Panther SIEM detection rules repository.

Here are the review findings:

$review_output

Apply ALL the suggested fixes to the actual files. Only modify what the review flagged — do not make other changes.

Files to fix:
$(printf '%s\n' "${changed_files[@]}")"

        # Run Claude in background with a spinner
        fix_log=$(mktemp)
        fix_prompt_file=$(mktemp)
        printf '%s' "$fix_prompt" > "$fix_prompt_file"
        claude -p - --allowedTools "Edit,Read" --permission-mode acceptEdits < "$fix_prompt_file" > "$fix_log" &
        claude_pid=$!
        trap 'kill "$claude_pid" 2>/dev/null; rm -f "$err_file" "${fix_log:-}" "${prompt_file:-}" "${fix_prompt_file:-}"' EXIT
        spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        while kill -0 "$claude_pid" 2>/dev/null; do
            for (( i=0; i<${#spin}; i++ )); do
                printf "\r   ${spin:$i:1} Fixing..."
                sleep 0.1
            done
        done
        wait "$claude_pid" || {
            printf "\r"
            echo "⚠️  Auto-fix failed. Please fix manually."
            [[ -s "$fix_log" ]] && cat "$fix_log"
            rm -f "$fix_log"
            exit 1
        }
        printf "\r   ✅ Done.          \n"
        [[ -s "$fix_log" ]] && echo "" && cat "$fix_log" && echo ""
        rm -f "$fix_log"

        echo ""
        echo "⏳ Running formatters..."
        make fmt 2>&1 || true
        echo ""
        echo "───────────────────────────────────────────────────"
        echo "📊 Changes applied:"
        echo "───────────────────────────────────────────────────"
        git add "${changed_files[@]}"
        git diff --cached --stat -- "${changed_files[@]}"
        echo "───────────────────────────────────────────────────"
        echo ""
        echo "  a) Amend into last commit (git commit --amend --no-edit)"
        echo "  n) Create new commit"
        echo "  s) Leave staged, I'll handle it"
        echo ""
        echo "Choose (a/n/s):"
        read -r fix_answer < /dev/tty
        case "$fix_answer" in
            [Aa])
                git commit --amend --no-edit
                echo "✅ Amended into last commit. Push when ready."
                ;;
            [Nn])
                git commit -m "fix: apply review findings"
                echo "✅ Created new commit. Push when ready."
                ;;
            *)
                echo "✅ Changes staged. Handle it your way."
                ;;
        esac
        exit 1
        ;;
    [Pp])
        echo "✅ Pushing..."
        exit 0
        ;;
    *)
        echo "❌ Push aborted. Fix the findings and try again."
        exit 1
        ;;
esac