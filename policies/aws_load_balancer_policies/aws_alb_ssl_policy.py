# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies
# Requirements to be "safe": 1) TLSv1.2+ only; 2) Forward Secrecy

TLS_SAFE_POLICIES = {
    "ELBSecurityPolicy-FS-1-2-2019-08",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
}


def policy(resource):
    # Ignore load balancers that aren't serving internet traffic
    if resource.get("Scheme") == "internal":
        return True

    return len(resource.get("Listeners") if resource.get("Listeners") else []) >= 1 and all(
        (each_policy in TLS_SAFE_POLICIES for each_policy in resource.get("SSLPolicies", {}).keys())
    )
