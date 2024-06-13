from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity


class SubclassPantherBaseRule(PantherRule):
    RuleID = "SubclassPantherBaseRule-roast"
    Severity = PantherSeverity.High
    LogTypes = [PantherLogType.Panther_Audit]
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
