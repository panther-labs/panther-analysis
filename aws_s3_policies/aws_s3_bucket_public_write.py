from panther_base_helpers import deep_get

GRANTEES = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers'
}
PERMISSIONS = {'WRITE', 'WRITE_ACP', 'FULL_CONTROL'}


def policy(resource):
    for grant in resource['Grants'] or []:
        if deep_get(
                grant, 'Grantee',
                'URI') in GRANTEES and grant.get('Permission') in PERMISSIONS:
            return False

    return True
