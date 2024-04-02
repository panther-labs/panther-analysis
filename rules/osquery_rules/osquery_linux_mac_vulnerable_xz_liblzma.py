# SELECT 'Homebrew Package' AS source, name, version,
#   CASE
#     WHEN version LIKE '5.6.0%' OR version LIKE '5.6.1%' THEN 'Potentially Vulnerable'
#     ELSE 'Most likely not vulnerable'
#   END AS status
# FROM homebrew_packages
# WHERE name = 'xz' OR name = 'liblzma';

# SELECT 'DEB Package' AS source, name, version,
#   CASE
#     WHEN version LIKE '5.6.0%' OR version LIKE '5.6.1%' THEN 'Potentially Vulnerable'
#     ELSE 'Most likely not vulnerable'
#   END AS status
# FROM deb_packages
# WHERE name = 'xz-utils' OR name = 'xz-libs' OR name = 'liblzma' OR name LIKE 'liblzma%'
# UNION
# SELECT 'RPM Package' AS source, name, version,
#   CASE
#     WHEN version LIKE '5.6.0%' OR version LIKE '5.6.1%' THEN 'Potentially Vulnerable'
#     ELSE 'Most likely not vulnerable'
#   END AS status
# FROM rpm_packages
# WHERE name = 'xz-utils' OR name = 'xz-libs' OR name = 'liblzma' OR name LIKE 'liblzma%';

VULNERABLE_PACKAGES = {"xz", "liblzma", "xz-libs", "xz-utils"}
VULNERABLE_VERSIONS = {"5.6.0", "5.6.1"}


def rule(event):
    if event.get("action") != "added":
        return False
    name = event.deep_get("columns", "name", default="")
    version = event.deep_get("columns", "version", default="")
    status = event.deep_get("columns", "status", default="")

    if name not in VULNERABLE_PACKAGES and not name.startswith("liblzma"):
        return False
    if (
        any(version.startswith(v) for v in VULNERABLE_VERSIONS)
        and status == "Potentially vulnerable"
    ):
        return True
    return False


def title(event):
    host = event.get("hostIdentifier")
    name = event.deep_get("columns", "name", default="")
    version = event.deep_get("columns", "version", default="")
    status = event.deep_get("columns", "status", default="")
    alert_title = f"[CVE-2024-3094] {name} {version} {status} on {host}"
    return alert_title
