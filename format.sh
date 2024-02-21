#!/bin/sh

# Small script that removes trailing whitespace from files in the repository

OS=$(uname)
for extension in "*.py" "*.yml"; do
    case $OS in
        Darwin) find . -type f -not -path '.git' -iname $extension -print0 | xargs -0 sed -i '' -E "s/[[:space:]]*\$//";;
        Linux) find . -type f -not -path '.git' -iname $extension -print0 | xargs -0 sed -i -E "s/[[:space:]]*\$//";;
        *) echo "Unsupported OS: $OSTYPE"; exit 1;;
    esac
done
