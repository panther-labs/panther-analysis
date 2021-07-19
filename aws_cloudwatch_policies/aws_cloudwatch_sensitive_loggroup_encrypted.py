from fnmatch import fnmatch

# replace the log groups ARN regex with the
# log groups that should be encrypted with your CMK
SENSITIVE_LOG_GROUP_ARN_REGEXS = {"*LogGroup-2*"}


def policy(resource):
    if SENSITIVE_LOG_GROUP_ARN_REGEXS and not any(
        fnmatch(resource.get("Arn"), group_arn) for group_arn in SENSITIVE_LOG_GROUP_ARN_REGEXS
    ):
        return True
    return resource["KmsKeyId"] is not None
