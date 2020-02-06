GRANTEES = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers'
}
PERMISSIONS = {'WRITE', 'WRITE_ACP', 'FULL_CONTROL'}


def policy(resource):
    for grant in resource['Grants']:
        if grant['Grantee']['URI'] in GRANTEES and grant[
                'Permission'] in PERMISSIONS:
            return False

    return True
