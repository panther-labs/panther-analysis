from fnmatch import fnmatch

# replace the log groups ARN regex with the
# log groups that should be encrypted with your CMK
SENSITIVE_LOG_GROUP_ARN_REGEXS = {"*LogGroup-2*"}


def policy(resource):
    if resource["KmsKeyId"] is None:
        if SENSITIVE_LOG_GROUP_ARN_REGEXS and any(
            fnmatch(resource.get("Arn"), group_arn) for group_arn in SENSITIVE_LOG_GROUP_ARN_REGEXS
        ):
            return False
    return True
