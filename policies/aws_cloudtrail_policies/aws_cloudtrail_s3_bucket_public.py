from panther_base_helpers import deep_get
from panther_default import aws_regions
from panther_oss_helpers import BadLookup, resource_lookup

BAD_PERMISSIONS = {
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    "http://acs.amazonaws.com/groups/global/AllUsers",
}

# docs.aws.amazon.com/codepipeline/latest/userguide/reference-ct-placeholder-buckets.html
EXCLUDED_BUCKET_NAMES = {
    f"codepipeline-cloudtrail-placeholder-bucket-{region}" for region in aws_regions()
}


def policy(resource):
    bucket_arn = "arn:aws:s3:::" + resource["S3BucketName"]

    try:
        bucket = resource_lookup(bucket_arn)
    except BadLookup:
        return True

    for grant in bucket["Grants"] or []:
        if deep_get(grant, "Grantee", "URI") in BAD_PERMISSIONS and not any(
            bucket_name in bucket_arn for bucket_name in EXCLUDED_BUCKET_NAMES
        ):
            return False

    return True
