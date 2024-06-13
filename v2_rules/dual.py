from pypanther import PantherLogType, PantherRule, PantherSeverity


class Bob(PantherRule):
    RuleID = "Bob"
    Severity = PantherSeverity.High
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event) -> bool:
        return True


class Charlie(PantherRule):
    RuleID = "Charlie"
    Severity = PantherSeverity.High
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event) -> bool:
        return True
