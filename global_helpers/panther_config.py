from typing import Any

import panther_config_defaults
import panther_config_overrides


class Config:  # pylint: disable=too-few-public-methods
    def __getattr__(self, name) -> Any:
        if hasattr(panther_config_overrides, name):
            return getattr(panther_config_overrides, name)
        return getattr(panther_config_defaults, name, None)


config = Config()
