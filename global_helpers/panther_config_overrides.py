"""
Here, you can override the default, example configuration values from `panther_config_defaults`

Any attribute found to be defined in here will take precedence at lookup time.
For example, we can totally re-define a value:

# Total Override
panther_config_defaults.py
```
SUSPICIOUS_DOMAINS = [ "evil.example.com" ]
```

panther_config_overrides.py
```
SUSPICIOUS_DOMAINS = [ "betrug.example.com" ]
```

and at lookup-time:
```
from panther_config import config
print(config.SUSPICIOUS_DOMAINS)
```
prints ["betrug.example.com"]

# Mixing Values
panther_config_defaults.py
```
INTERNAL_NETWORKS = [ "10.0.0.0/8" ]
```

panther_config_overrides.py
```
import panther_config_defaults
INTERNAL_NETWORKS = panther_config_defaults.INTERNAL_NETWORKS + [ "192.0.2.0/24" ]
```

and at lookup-time:
```
from panther_config import config
print(config.INTERNAL_NETWORKS)
```
prints ["10.0.0.0/8", "192.0.2.0/24" ]
"""
