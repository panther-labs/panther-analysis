from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.rules.asana_rules.asana_service_account_created import AsanaServiceAccountCreated
from pypanther.rules.aws_s3_rules.aws_s3_unauthenticated_access import (
    AWSS3ServerAccessUnauthenticated,
)

from v2_rules import (
    dual,
    subclass_custom_rule,
    subclass_panther_aws_rule,
    subclass_panther_base_rule,
)

# override a rule attribute in one line
AsanaServiceAccountCreated.Severity = PantherSeverity.Info

# override many attributes using override function
AWSS3ServerAccessUnauthenticated.override(
    Severity=PantherSeverity.Low,
    Runbook="https://freshpotof.coffee",
)


# register all custom rules
register(
    [
        subclass_custom_rule.SubclassCustomRule,
        subclass_panther_base_rule.SubclassPantherBaseRule,
        subclass_panther_aws_rule.SubclassPantherAwsRule,
        dual.Bob,  # rules can be defined in the same file
        dual.Charlie,
    ]
)

# register all panther rules with log types you use
register(
    get_panther_rules(
        LogTypes=[
            PantherLogType.Panther_Audit,
            PantherLogType.AWS_CloudTrail,
        ]
    )
)

# register all panther rules
# register(get_panther_rules())
