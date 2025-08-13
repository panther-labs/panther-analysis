from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") == "GetObject"
        and event.deep_get("requestParameters", "bucketName") == "jn-model-training-data-5233"
        and event.deep_get("userIdentity", "type") != "AWSService"
    )
