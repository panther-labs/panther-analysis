IGNORED = {}


def policy(resource):
    if not resource[
            'RequireUppercaseCharacters'] and 'RequireUppercaseCharacters' not in IGNORED:
        return False

    if not resource[
            'RequireLowercaseCharacters'] and 'RequireLowercaseCharacters' not in IGNORED:
        return False

    if not resource['RequireSymbols'] and 'RequireSymbols' not in IGNORED:
        return False

    if not resource['RequireNumbers'] and 'RequireNumbers' not in IGNORED:
        return False

    if not (resource['MinimumPasswordLength'] and
            resource['MinimumPasswordLength'] >= 14
           ) and 'MinimumPasswordLength' not in IGNORED:
        return False

    return True
