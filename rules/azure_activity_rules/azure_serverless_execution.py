from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

# AZT302.1/2/3 - Automation Account Runbook Job Execution
RUNBOOK_JOB_WRITE = "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/WRITE"

# AZT302.4 - Function Application Execution
FUNCTION_APP_ACTION = "MICROSOFT.WEB/SITES/HOSTRUNTIME/HOST/ACTION"

AZT302_OPERATIONS = [
    RUNBOOK_JOB_WRITE,
    FUNCTION_APP_ACTION,
]


def rule(event):
    operation = event.get("operationName", "").upper()
    return all([operation in AZT302_OPERATIONS, azure_activity_success(event)])


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    operation = event.get("operationName", "").upper()
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    if operation == RUNBOOK_JOB_WRITE:
        technique = "Automation Runbook Job"
        resource_name = _extract_automation_account(resource_id)
    elif operation == FUNCTION_APP_ACTION:
        technique = "Function App"
        resource_name = _extract_function_app(resource_id)
    else:
        technique = "Serverless Execution"
        resource_name = "<UNKNOWN_RESOURCE>"

    return f"Azure {technique} Executed on [{resource_name}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    operation = event.get("operationName", "").upper()
    resource_id = event.get("resourceId", "")

    # Add operation-specific context
    context["execution_method"] = _get_execution_method(operation)

    if operation == RUNBOOK_JOB_WRITE:
        context["resource_type"] = "Automation Runbook Job"
        context["automation_account"] = _extract_automation_account(resource_id)
        context["runbook_name"] = _extract_runbook_name(resource_id)
        context["job_id"] = _extract_job_id(resource_id)
    elif operation == FUNCTION_APP_ACTION:
        context["resource_type"] = "Function App"
        context["function_app_name"] = _extract_function_app(resource_id)

    return context


def _extract_automation_account(resource_id):
    """Extract automation account name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_ACCOUNT>"
    parts = resource_id.split("/")
    if "automationAccounts" in parts:
        try:
            return parts[parts.index("automationAccounts") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_ACCOUNT>"


def _extract_runbook_name(resource_id):
    """Extract runbook name from job resource ID"""
    if not resource_id:
        return "<UNKNOWN_RUNBOOK>"
    parts = resource_id.split("/")
    if "runbooks" in parts:
        try:
            return parts[parts.index("runbooks") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_RUNBOOK>"


def _extract_job_id(resource_id):
    """Extract job ID from resource ID"""
    if not resource_id:
        return "<UNKNOWN_JOB>"
    parts = resource_id.split("/")
    if "jobs" in parts:
        try:
            return parts[parts.index("jobs") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_JOB>"


def _extract_function_app(resource_id):
    """Extract function app name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_APP>"
    parts = resource_id.split("/")
    if "sites" in parts:
        try:
            return parts[parts.index("sites") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_APP>"


def _get_execution_method(operation):
    """Map operation to AZT302 sub-technique"""
    mapping = {
        RUNBOOK_JOB_WRITE: "AZT302.1/2/3 - Automation Runbook Job",
        FUNCTION_APP_ACTION: "AZT302.4 - Function Application",
    }
    return mapping.get(operation, "Unknown")
