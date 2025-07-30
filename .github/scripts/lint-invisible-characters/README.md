# Invisible Character Linter

The `lint-invisible.py` script detects invisible Unicode characters in text files that might cause issues or be used maliciously. It ignores common legitimate whitespace characters (space, tab, CR, LF).

### Usage

```bash
python3 lint-invisible.py <file1> <file2> ... [--ignore <pattern1>,<pattern2>,...]
```

#### Arguments
- `<file1> <file2> ...`: One or more files to scan
- `--ignore`: Optional comma-separated list of patterns to ignore

### Testing

To test the linter with the provided test file:

```bash
# Basic test
python3 lint-invisible.py lint-invisible-test-file.md
```

Expected output will show detected invisible characters with their Unicode code points and descriptions. The script will exit with status code 1 if any invisible characters are found.

### Scanning the Entire Repository

To scan all files in the repository, you can use the following commands based on your operating system. Run these commands from the root of the repository:

#### macOS / Linux (bash/zsh)
```bash
find . -type f -not -path '*/\.*' -exec python3 .github/scripts/lint-invisible-characters/lint-invisible.py {} +
```

#### Windows (PowerShell)
```powershell
Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notlike '*\.git\*' } | ForEach-Object { python3 .github/scripts/lint-invisible-characters/lint-invisible.py $_.FullName }
```

The commands above will:
1. Find all files in the current directory and subdirectories
2. Exclude hidden files and `.git` directory
3. Pass the files to the linter for scanning

You can add the `--ignore` flag with patterns if needed:
```bash
# macOS / Linux
find . -type f -not -path '*/\.*' -exec python3 .github/scripts/lint-invisible-characters/lint-invisible-characters.py --ignore=pattern1,pattern2 {} +

# Windows PowerShell
Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notlike '*\.git\*' } | ForEach-Object { python3 .github/scripts/lint-invisible-characters/lint-invisible-characters.py --ignore=pattern1,pattern2 $_.FullName }
```



