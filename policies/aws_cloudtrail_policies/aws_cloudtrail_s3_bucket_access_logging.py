from panther_oss_helpers import BadLookup, resource_lookup


def policy(resource):
    bucket_arn = "arn:aws:s3:::" + resource["S3BucketName"]
    try:
        bucket = resource_lookup(bucket_arn)
    except BadLookup:
        return True

    return bucket["LoggingPolicy"] is not None
