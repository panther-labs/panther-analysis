from generate_indexes import analyze_yaml, extract_log_types_from_yaml


def test_analyze_yaml_databricks_query() -> None:
    detection_yaml = {
        "AnalysisType": "saved_query",
        "QueryName": "Test.Query",
        "DatabricksQuery": "select * from crowdstrike_aidmaster",
    }
    rv = analyze_yaml(detection_yaml)
    assert rv["DatabricksQuery"] == "select * from crowdstrike_aidmaster"


def test_extract_log_types_from_yaml_direct_databricks_query() -> None:
    logtype_lookup = {"crowdstrike_aidmaster": "Crowdstrike.AIDMaster"}
    yaml = {
        "AnalysisType": "saved_query",
        "DatabricksQuery": "select * from crowdstrike_aidmaster",
    }
    log_types = extract_log_types_from_yaml(yaml, query_lookup={}, logtype_lookup=logtype_lookup)
    assert log_types == ["Crowdstrike.AIDMaster"]


def test_extract_log_types_from_yaml_scheduled_query_databricks() -> None:
    logtype_lookup = {"crowdstrike_aidmaster": "Crowdstrike.AIDMaster"}
    query_lookup = {
        "Test.Scheduled.Query": {
            "AnalysisType": "saved_query",
            "QueryName": "Test.Scheduled.Query",
            "DatabricksQuery": "select * from crowdstrike_aidmaster",
        }
    }
    yaml = {
        "AnalysisType": "scheduled_rule",
        "ScheduledQueries": ["Test.Scheduled.Query"],
    }
    log_types = extract_log_types_from_yaml(yaml, query_lookup, logtype_lookup)
    assert log_types == ["Crowdstrike.AIDMaster"]


def test_extract_log_types_from_yaml_scheduled_query_prefers_query_over_databricks() -> None:
    # When both Query and DatabricksQuery are present, the plain Query field wins.
    logtype_lookup = {
        "crowdstrike_aidmaster": "Crowdstrike.AIDMaster",
        "snowflake.account_usage": "Snowflake.AccountUsage",
    }
    query_lookup = {
        "Test.Scheduled.Query": {
            "AnalysisType": "saved_query",
            "QueryName": "Test.Scheduled.Query",
            "Query": "select * from snowflake.account_usage",
            "DatabricksQuery": "select * from crowdstrike_aidmaster",
        }
    }
    yaml = {
        "AnalysisType": "scheduled_rule",
        "ScheduledQueries": ["Test.Scheduled.Query"],
    }
    log_types = extract_log_types_from_yaml(yaml, query_lookup, logtype_lookup)
    assert log_types == ["Snowflake.AccountUsage"]
