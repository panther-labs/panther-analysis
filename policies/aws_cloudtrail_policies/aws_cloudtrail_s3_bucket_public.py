from panther_base_helpers import deep_get
from panther_oss_helpers import BadLookup, resource_lookup

BAD_PERMISSIONS = {
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    "http://acs.amazonaws.com/groups/global/AllUsers",
}


# https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-ct-placeholder-buckets.html
PLACEHOLDER_BUCKETS = {
    "codepipeline-cloudtrail-placeholder-bucket-us-east-2",
    "codepipeline-cloudtrail-placeholder-bucket-us-east-1",
    "codepipeline-cloudtrail-placeholder-bucket-us-west-1",
    "codepipeline-cloudtrail-placeholder-bucket-us-west-2",
    "codepipeline-cloudtrail-placeholder-bucket-ca-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-2",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-3",
    "codepipeline-cloudtrail-placeholder-bucket-eu-north-1",
    "codepipeline-cloudtrail-placeholder-bucket-ap-east-1",
    "codepipeline-cloudtrail-placeholder-bucket-ap-south-2",
    "codepipeline-cloudtrail-placeholder-bucket-ap-southeast-3",
    "codepipeline-cloudtrail-placeholder-bucket-ap-southeast-4",
    "codepipeline-cloudtrail-placeholder-bucket-ap-south-1",
    "codepipeline-cloudtrail-placeholder-bucket-ap-northeast-3-prod",
    "codepipeline-cloudtrail-placeholder-bucket-ap-northeast-1",
    "codepipeline-cloudtrail-placeholder-bucket-ap-northeast-2",
    "codepipeline-cloudtrail-placeholder-bucket-ap-southeast-1",
    "codepipeline-cloudtrail-placeholder-bucket-ap-southeast-2",
    "codepipeline-cloudtrail-placeholder-bucket-ap-northeast-1",
    "codepipeline-cloudtrail-placeholder-bucket-ca-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-2",
    "codepipeline-cloudtrail-placeholder-bucket-eu-south-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-west-3",
    "codepipeline-cloudtrail-placeholder-bucket-eu-south-2",
    "codepipeline-cloudtrail-placeholder-bucket-eu-north-1",
    "codepipeline-cloudtrail-placeholder-bucket-eu-central-2",
    "codepipeline-cloudtrail-placeholder-bucket-il-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-me-south-1",
    "codepipeline-cloudtrail-placeholder-bucket-me-central-1",
    "codepipeline-cloudtrail-placeholder-bucket-sa-east-1"
}


def policy(resource):
    if resource["S3BucketName"] in PLACEHOLDER_BUCKETS:
        return True

    bucket_arn = "arn:aws:s3:::" + resource["S3BucketName"]

    try:
        bucket = resource_lookup(bucket_arn)
    except BadLookup:
        return True

    for grant in bucket["Grants"] or []:
        if deep_get(grant, "Grantee", "URI") in BAD_PERMISSIONS:
            return False

    return True
