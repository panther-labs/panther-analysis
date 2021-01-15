from panther_oss_helpers import resource_lookup
from panther_base_helpers import deep_get

BAD_PERMISSIONS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers',
}


def policy(resource):
    bucket_arn = 'arn:aws:s3:::' + resource['S3BucketName']
    bucket = resource_lookup(bucket_arn)

    for grant in deep_get(bucket, 'Grants', default=[]):
        if deep_get(grant, 'Grantee', 'URI') in BAD_PERMISSIONS:
            return False

    return True
