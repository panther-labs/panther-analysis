from panther import resource_lookup  # pylint disable:import-error
BAD_PERMISSIONS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers',
}


def policy(resource):
    bucket_arn = 'arn:aws:s3:::' + resource['S3BucketName']
    bucket = resource_lookup(bucket_arn)

    for grant in bucket['Grants'] or []:
        if grant['Grantee']['URI'] in BAD_PERMISSIONS:
            return False

    return True
