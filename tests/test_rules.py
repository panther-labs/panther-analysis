import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Type

import pytest
from pypanther import registered_rules
from pypanther.base import PantherRule
from pypanther.cache import DATA_MODEL_CACHE


class NoMainModuleError(Exception):
    """Raised when the main module is not found."""

    pass


def import_main(target_code_location: str, main_module_name: str) -> None:
    """Imports the main module from the target_code_location"""
    customer_main_file = main_module_name + ".py"

    path = Path(target_code_location) / customer_main_file
    if not path.is_file():
        raise NoMainModuleError(f"No {customer_main_file} found")

    sys.path.append(target_code_location)

    spec = spec_from_file_location(main_module_name, path)
    if spec is None:
        raise RuntimeError(f"No spec found for module={main_module_name} and path={path}")
    if spec.loader is None:
        raise RuntimeError(f"Spec has no loader for module={main_module_name} and path={path}")

    module = module_from_spec(spec)
    sys.modules[main_module_name] = module
    spec.loader.exec_module(module)


import_main(".", "main")


@pytest.mark.parametrize("rule", registered_rules(), ids=lambda x: x.RuleID)
def test_rule(rule: Type[PantherRule]):
    rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)


if __name__ == "__main__":
    pytest.main()
