# AWS began encrypting all new Amazon Aurora clusters by default with an AWS owned key
# around this date. That default encryption never populates KmsKeyId (or StorageEncrypted)
# on the instance resource, so only Aurora instances created on/after this date are exempted
# below - older Aurora instances still require an explicit KmsKeyId to be considered compliant.
# Ref: https://aws.amazon.com/blogs/database/use-default-encryption-at-rest-for-new-amazon-aurora-clusters/  # pylint: disable=line-too-long
AURORA_DEFAULT_ENCRYPTION_DATE = "2026-02-17"


def policy(resource):
    if resource.get("KmsKeyId") is not None:
        return True

    created_at = resource.get("TimeCreated") or resource.get("InstanceCreateTime") or ""
    return resource.get("StorageType") == "aurora" and created_at >= AURORA_DEFAULT_ENCRYPTION_DATE
