from panther_base_helpers import deep_get

# 1.07 GB
QUERY_THRESHOLD_BYTES = 1073741824


def rule(event):
    return all(
        [
            deep_get(event, "resource", "type", default="<type not found>").startswith("bigquery"),
            deep_get(event, "operation", "last") is True,
            deep_get(event, "protoPayload", "metadata", "jobChange", "job", "jobConfig", "type")
            == "QUERY",
            deep_get(
                event,
                "protoPayload",
                "metadata",
                "jobChange",
                "job",
                "jobConfig",
                "queryConfig",
                "statementType",
            )
            == "SELECT",
            int(
                deep_get(
                    event,
                    "protoPayload",
                    "metadata",
                    "jobChange",
                    "job",
                    "jobStats",
                    "queryStats",
                    "totalBilledBytes",
                    default=0,
                )
            )
            > QUERY_THRESHOLD_BYTES,
        ]
    )


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    query_size = deep_get(
        event,
        "protoPayload",
        "metadata",
        "jobChange",
        "job",
        "jobStats",
        "queryStats",
        "totalBilledBytes",
        default=0,
    )
    return f"GCP: [{actor}] ran a large BigQuery query of [{query_size}] bytes."


def alert_context(event):
    return {
        "query": deep_get(
            event,
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "query",
            default="<QUERY_NOT_FOUND>",
        ),
        "actor": deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "query_size": deep_get(
            event,
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobStats",
            "queryStats",
            "totalBilledBytes",
            default=0,
        ),
    }
