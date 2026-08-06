def policy(resource):
    # Aurora manages storage encryption at the cluster level. Since Feb 2024, AWS encrypts
    # all new Aurora clusters by default with an AWS owned KMS key, which never populates
    # KmsKeyId (or StorageEncrypted) on the instance resource, causing false positives here.
    # Ref: https://aws.amazon.com/blogs/database/use-default-encryption-at-rest-for-new-amazon-aurora-clusters/  # pylint: disable=line-too-long
    if resource.get("StorageType") == "aurora":
        return True

    return resource.get("KmsKeyId") is not None
