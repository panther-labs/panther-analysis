from pypanther import get_panther_rules, register
from pypanther.base import PantherSeverity
from pypanther.log_types import LogType
from pypanther.rules.asana_rules.asana_service_account_created import AsanaServiceAccountCreated
from pypanther.rules.aws_s3_rules.aws_s3_unauthenticated_access import (
    AWSS3ServerAccessUnauthenticated,
)

from v2_rules import subclass_custom_rule, subclass_panther_aws_rule, subclass_panther_base_rule

# override a rule attribute in one line
AsanaServiceAccountCreated.Severity = PantherSeverity.High

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
    ]
)

# register all panther rules with log types you use
register(
    get_panther_rules(
        LogTypes=[
            LogType.Panther_Audit,
            LogType.AWS_CloudTrail,
            LogType.Asana_Audit,
        ]
    )
)

# register all panther rules
# register(get_panther_rules())
