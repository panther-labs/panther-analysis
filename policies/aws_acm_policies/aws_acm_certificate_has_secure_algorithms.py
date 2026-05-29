# Specify what key and signature algorithms meet your organizations level of security here.
# Included is the AWS ACM default when creating new certificates as an example.
SECURE_KEY_ALGORITHMS = {
    "RSA-2048",  # AWS ACM default
}

SECURE_SIGNATURE_ALGORITHMS = {
    "SHA256WITHRSA",  # AWS ACM default
}


def policy(resource):
    return (
        resource["KeyAlgorithm"] in SECURE_KEY_ALGORITHMS
        and resource["SignatureAlgorithm"] in SECURE_SIGNATURE_ALGORITHMS
    )
