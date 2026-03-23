# Content Catalog

Interactive browser for panther-analysis detection content.

## Usage

```bash
# Build the catalog JSON from YAML detections
python catalog/build_catalog.py

# Serve locally
cd catalog && python -m http.server 8888
# Open http://localhost:8888
```

## Rebuilding MITRE lookup

`mitre_lookup.json` ships pre-built. To regenerate from the official ATT&CK STIX data:

```bash
pip install mitreattack-python
python -c "
from mitreattack.stix20 import MitreAttackData
import urllib.request, json, os
tmp = '/tmp/enterprise-attack.json'
urllib.request.urlretrieve('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', tmp)
src = MitreAttackData(tmp)
tactics = {}
for t in src.get_tactics():
    for ref in t.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            tactics[ref['external_id']] = {'name': t['name'], 'shortname': t.get('x_mitre_shortname', ''), 'stix_id': t['id']}
techniques = {}
for t in src.get_techniques():
    if t.get('revoked') or t.get('x_mitre_deprecated'): continue
    for ref in t.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            tech_tactics = [tid for tid, ti in tactics.items() for p in t.get('kill_chain_phases', []) if p.get('kill_chain_name') == 'mitre-attack' and ti['shortname'] == p['phase_name']]
            techniques[ref['external_id']] = {'name': t['name'], 'tactics': tech_tactics, 'is_sub': bool(t.get('x_mitre_is_subtechnique'))}
json.dump({'tactics': {k: v['name'] for k, v in tactics.items()}, 'techniques': techniques}, open('catalog/mitre_lookup.json', 'w'), indent=2)
os.remove(tmp)
"
```
