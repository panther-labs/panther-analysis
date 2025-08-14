from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    return event.get("eventName") == "LeaveOrganization"


def title(event: PantherEvent) -> str:
    account_name = event.get("recipientAccountId")
    actor = event.udm("actor_user")
    # Return a more informative message if the attempt was unsuccessful
    if not aws_cloudtrail_success(event):
        return f"Failed attempt to remove {account_name} from your AWS organization by {actor}"
    return f"Account {account_name} has been removed from your AWS organization by {actor}"


def severity(event: PantherEvent) -> str:
    # Downgrade to HIGH if attempt is unsuccessful
    if not aws_cloudtrail_success(event):
        return "HIGH"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    return aws_rule_context(event)
