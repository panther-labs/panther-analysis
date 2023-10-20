from panther_base_helpers import deep_get
from panther_oss_helpers import BadLookup, resource_lookup

BAD_PERMISSIONS = {
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    "http://acs.amazonaws.com/groups/global/AllUsers",
}


def policy(resource):
    bucket_arn = "arn:aws:s3:::" + resource["S3BucketName"]

    try:
        bucket = resource_lookup(bucket_arn)
    except BadLookup:
        return True

    for grant in bucket["Grants"] or []:
        if deep_get(grant, "Grantee", "URI") in BAD_PERMISSIONS:
            return False

    return True
