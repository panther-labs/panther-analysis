# 1.07 GB
QUERY_THRESHOLD_BYTES = 1073741824


def rule(event):
    return all(
        [
            event.deep_get("resource", "type", default="<type not found>").startswith("bigquery"),
            event.deep_get("operation", "last") is True,
            event.deep_get("protoPayload", "metadata", "jobChange", "job", "jobConfig", "type")
            == "QUERY",
            event.deep_get(
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
                event.deep_get(
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
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return f"GCP: [{actor}] ran a large BigQuery query exceeding 1.07 GB threshold."


def alert_context(event):
    return {
        "query": event.deep_get(
            "protoPayload",
            "metadata",
            "jobChange",
            "job",
            "jobConfig",
            "queryConfig",
            "query",
            default="<QUERY_NOT_FOUND>",
        ),
        "actor": event.deep_get(
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "query_size": event.deep_get(
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
