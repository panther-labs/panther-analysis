from pypanther.base import PantherRuleTest, PantherSeverity
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_created import AWSCloudTrailCreated

rule_tests = [
    PantherRuleTest(
        Name="checks for important",
        ExpectedResult=False,
        Log={
            "important": "also important",
        },
    ),
]


class SubclassPantherAwsRule(AWSCloudTrailCreated):
    RuleID = "SubclassPantherAwsRule-roast"
    Severity = PantherSeverity.Medium  # override old severity
    Runbook = "https://zombo.com"  # better runbook
    Tests = AWSCloudTrailCreated.Tests + rule_tests  # add new rule test

    def rule(self, event) -> bool:
        if event.get("important") == "also important":
            return False  # mimics a filter

        # call old rule logic
        return super().rule(event)
