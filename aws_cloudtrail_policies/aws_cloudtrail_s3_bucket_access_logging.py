from panther_oss_helpers import resource_lookup  # pylint disable:import-error


def policy(resource):
    bucket_arn = 'arn:aws:s3:::' + resource['S3BucketName']
    bucket = resource_lookup(bucket_arn)

    return bucket['LoggingPolicy'] is not None
