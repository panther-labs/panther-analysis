#!/usr/bin/env bash
# Pre-commit hook: runs Claude review first, then pre-commit (fmt + lint).
# Installed by: make install-pre-commit-hooks

# 1. Claude Code Review (with full TTY access)
python3 .scripts/claude_review.py || exit 1

# 2. Run pre-commit hooks (fmt, lint)
if command -v pre-commit > /dev/null; then
    exec pre-commit hook-impl --config=.pre-commit-config.yaml --hook-type=pre-commit --hook-dir "$(cd "$(dirname "$0")" && pwd)" -- "$@"
elif command -v pipenv > /dev/null; then
    exec pipenv run pre-commit hook-impl --config=.pre-commit-config.yaml --hook-type=pre-commit --hook-dir "$(cd "$(dirname "$0")" && pwd)" -- "$@"
else
    echo 'pre-commit not found. Run: make install' 1>&2
    exit 1
fi
