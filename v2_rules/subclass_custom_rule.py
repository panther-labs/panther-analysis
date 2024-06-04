from pypanther.base import PantherSeverity

from .subclass_panther_base_rule import SubclassPantherBaseRule


class SubclassCustomRule(SubclassPantherBaseRule):
    RuleID = "SubclassCustomRule-roast"
    Severity = PantherSeverity.Low  # override old high severity
    CreateAlert = True  # create alerts now
