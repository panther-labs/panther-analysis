from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType


class SubclassPantherBaseRule(PantherRule):
    RuleID = "SubclassPantherBaseRule-roast"
    Severity = PantherSeverity.High
    LogTypes = [LogType.Panther_Audit]
    Tests = [
        PantherRuleTest(
            Name="Rule1-test1",
            ExpectedResult=True,
            Log={"Thing": "thing"},
        )
    ]
    CreateAlert = False

    def rule(self, event) -> bool:
        return True
