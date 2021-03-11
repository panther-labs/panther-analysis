IGNORED = {}


def policy(resource):
    if not resource.get("RequireUppercaseCharacters") and "RequireUppercaseCharacters" not in IGNORED:
        return False

    if not resource.get("RequireLowercaseCharacters") and "RequireLowercaseCharacters" not in IGNORED:
        return False

    if not resource.get("RequireSymbols") and "RequireSymbols" not in IGNORED:
        return False

    if not resource.get("RequireNumbers") and "RequireNumbers" not in IGNORED:
        return False

    if (
        not (resource.get("MinimumPasswordLength") and resource.get("MinimumPasswordLength") >= 14)
        and "MinimumPasswordLength" not in IGNORED
    ):
        return False

    return True
