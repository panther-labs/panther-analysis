IGNORED_REQUIREMENTS = {}


def policy(resource):
    if not resource['RequireUppercaseCharacters'
                   ] and 'RequireUppercaseCharacters' not in IGNORED_REQUIREMENTS:
        return False

    if not resource['RequireLowercaseCharacters'
                   ] and 'RequireLowercaseCharacters' not in IGNORED_REQUIREMENTS:
        return False

    if not resource['RequireSymbols'] and 'RequireSymbols' not in IGNORED_REQUIREMENTS:
        return False

    if not resource['RequireNumbers'] and 'RequireNumbers' not in IGNORED_REQUIREMENTS:
        return False

    if not (
        resource['MinimumPasswordLength'] and resource['MinimumPasswordLength'] >= 14
    ) and 'MinimumPasswordLength' not in IGNORED_REQUIREMENTS:
        return False

    return True
