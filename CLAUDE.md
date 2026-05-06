# CLAUDE.md

Guidance for Claude Code working in this repository.

**The canonical agent guide is [AGENTS.md](AGENTS.md). Read it first.** It covers the rules, conventions, gotchas, and workflow for this repo and is shared across all AI coding tools (Claude Code, Cursor, etc.).

## Critical reminders (do not skip)

These are the highest-impact rules from `AGENTS.md` — re-stated here because mistakes are costly:

1. **This repo is public.** Never commit customer data, real account IDs, real emails, real IPs, secrets, or internal Panther customer context. Redact all sample logs in unit tests.
2. **All PRs target the `develop` branch**, not `main`. When using `gh pr create`, pass `--base develop` explicitly.
3. **Detections are dual-file.** Every `.py` has a matching `.yml` (with the same basename). Always commit them together. The YAML `Filename:` must exactly match the `.py` filename.
4. **Use safe field access** in detection code: `event.get("field", "")` and `event.deep_get("a", "b", default="")`. Never use `event["field"]`. `deep_get` is a method on `event` — do not import it from `panther_base_helpers`.
5. **Always include positive AND negative unit tests** in the YAML `Tests:` block, with redacted sample logs.
6. **Run the trio before pushing:** `make fmt && make lint && make test`. Don't disable lints or skip hooks to make CI green — fix the underlying issue.
7. **Test scoping:** when iterating on a single rule, use `pipenv run panther_analysis_tool test --path <dir>` or `--filter RuleID=<id>` rather than running the full suite.
8. **Correlation rules** require `pat validate` against a live Panther instance — `pat test` is not sufficient. See [`style_guides/CORRELATION_RULES_STYLE_GUIDE.md`](style_guides/CORRELATION_RULES_STYLE_GUIDE.md).

## Quick command reference

```bash
make install                                                          # setup
make fmt && make lint && make test                                    # before pushing
pipenv run panther_analysis_tool test --path rules/<dir>/             # scoped test
pipenv run panther_analysis_tool test --filter RuleID=<RuleID>        # one rule
pipenv run panther_analysis_tool validate --api-token ... --api-host  # correlation rules
```

For everything else — directory layout, metadata fields, MITRE format, naming conventions, `alert_context` reuse, deprecation flow, PR process, common gotchas — see **[AGENTS.md](AGENTS.md)** and the [`style_guides/`](style_guides/) directory.
