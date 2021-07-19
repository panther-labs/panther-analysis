from fnmatch import fnmatch

# replace the log groups regex with the
# log groups you have encrypted with your CMK
SENSITIVE_LOG_GROUP_NAME_REGEXS = {"LogGroup-2*"}

SENSITIVE_LOG_GROUP_ARN_REGEXS = {}


def policy(resource):
    if SENSITIVE_LOG_GROUP_NAME_REGEXS and not any(
        fnmatch(resource.get("Name"), group_name) for group_name in SENSITIVE_LOG_GROUP_NAME_REGEXS
    ):
        return True
    if SENSITIVE_LOG_GROUP_ARN_REGEXS and not any(
        fnmatch(resource.get("arn"), group_arn) for group_arn in SENSITIVE_LOG_GROUP_ARN_REGEXS
    ):
        return True
    return resource["KmsKeyId"] is not None
