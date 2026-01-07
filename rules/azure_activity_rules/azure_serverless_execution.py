from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

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

    if operation == RUNBOOK_JOB_WRITE:
        technique = "Automation Runbook Job"
        resource_name = extract_resource_name_from_id(
            resource_id, "automationAccounts", default="<UNKNOWN_ACCOUNT>"
        )
    elif operation == FUNCTION_APP_ACTION:
        technique = "Function App"
        resource_name = extract_resource_name_from_id(resource_id, "sites", default="<UNKNOWN_APP>")
    else:
        technique = "Serverless"
        resource_name = "<UNKNOWN_RESOURCE>"

    return f"Azure {technique} Execution detected on [{resource_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    operation = event.get("operationName", "").upper()
    resource_id = event.get("resourceId", "")

    if operation == RUNBOOK_JOB_WRITE:
        context["resource_type"] = "Automation Runbook Job"

        automation_account = extract_resource_name_from_id(
            resource_id, "automationAccounts", default=""
        )
        if automation_account:
            context["automation_account"] = automation_account

        runbook_name = extract_resource_name_from_id(resource_id, "runbooks", default="")
        if runbook_name:
            context["runbook_name"] = runbook_name

        job_id = extract_resource_name_from_id(resource_id, "jobs", default="")
        if job_id:
            context["job_id"] = job_id

    elif operation == FUNCTION_APP_ACTION:
        context["resource_type"] = "Function App"

        function_app_name = extract_resource_name_from_id(resource_id, "sites", default="")
        if function_app_name:
            context["function_app_name"] = function_app_name

    return context
