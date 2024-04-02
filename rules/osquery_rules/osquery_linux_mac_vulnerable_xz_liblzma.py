QUERY_NAMES = {
    "pack_vuln-management_homebrew_packages",
    "pack_vuln-management_deb_packages",
    "pack_vuln-management_rpm_packages",
}
VULNERABLE_PACKAGES = {"xz", "liblzma", "xz-libs", "xz-utils"}
VULNERABLE_VERSIONS = {"5.6.0", "5.6.1"}


def rule(event):
    package = event.deep_get("columns", "name", default="")
    version = event.deep_get("columns", "version", default="")
    return all(
        [
            event.get("name") in QUERY_NAMES,
            (package in VULNERABLE_PACKAGES or package.startswith("liblzma")),
            any(version.startswith(v) for v in VULNERABLE_VERSIONS),
        ]
    )


def title(event):
    host = event.get("hostIdentifier")
    name = event.deep_get("columns", "name", default="")
    version = event.deep_get("columns", "version", default="")
    return f"[CVE-2024-3094] {name} {version} Potentially vulnerable on {host}"
