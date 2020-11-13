from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if event['id'].get('applicationName') != 'access_transparency':
        return False

    return bool(details_lookup('GSUITE_RESOURCE', ['ACCESS'], event))
