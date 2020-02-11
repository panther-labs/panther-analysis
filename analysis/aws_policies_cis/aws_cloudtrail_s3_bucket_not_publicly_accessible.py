BAD_PERMISSIONS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers',
}


def policy(resource):
    # TODO: Use the get_resource() helper func here
    if resource['Bucket']['Grants'] is None:
        return True

    for grant in resource['Bucket']['Grants']:
        if grant['Grantee']['URI'] in BAD_PERMISSIONS:
            return False
    return True
