PRODUCTION_PROJECT_IDS = ["example-production", "example-platform"]
ORG_ID = "888888888888"

rule_exceptions = {
"gcp_k8s_exec_into_pod": {
    "allowed_principals": [
        {
        "principals": ["system:serviceaccount:example-namespace:example-namespace-service-account"],
        # If empty, then all namespaces
        "namespaces": [],
        "env": None,
        "ttl": ""
        },
        {
        "principals": [
           "example-allowed-user@example.com"
            ],
        "namespaces": ["istio-system"],
        "env": None,
        'ttl': ""
        },
    ]
    }
}
