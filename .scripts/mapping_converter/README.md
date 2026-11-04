# Data Model Mapping Converter

A bi-directional tool for converting between Panther Data Model YAML files and a
flat CSV that's easy to diff, compare, and edit in a spreadsheet.

The tool is **framework-agnostic**: the unified field names in column 1 of the
CSV can come from any mapping framework you like — Sigma, OCSF, ECS, CIM, an
internal taxonomy, or an ad-hoc list. The script only cares that each row has a
field name and that each log-type column declares a `Path` or a `Method`.

- `yml2csv` — exports `Mappings` from one or more `*_data_model.yml` files into a
  single CSV with one column pair (`Value`, `Type`) per log type.
- `csv2yml` — reads that CSV back. If a YAML for the log type already exists,
  it's **updated in place** (comments, key order, and quoting are preserved via
  `ruamel.yaml`). If none exists, a new `*_data_model.yml` is created alongside a
  stub `*_data_model.py` so the dual-file convention is satisfied.

## Requirements

Runs against this repo's pipenv environment, which already provides
`panther_analysis_tool` and `ruamel.yaml`:

```bash
make install   # one-time, from repo root
```

## Usage

### Export YAML → CSV

```bash
# All data models in a directory
pipenv run python .scripts/mapping_converter/mapping_converter.py yml2csv \
  --input-dir data_models/edr_data_models \
  --output edr_mappings.csv

# Or specific files
pipenv run python .scripts/mapping_converter/mapping_converter.py yml2csv \
  --files data_models/edr_data_models/sentinelone_data_model.yml \
          data_models/edr_data_models/crowdstrike_fdr_data_model.yml \
  --output edr_mappings.csv
```

`yml2csv` emits a generic `Field` header on column 1. You can freely rename
that header to whatever fits your framework (`Sigma Field`, `OCSF Field`,
`ECS Field`, etc.) — `csv2yml` reads the unified field name by column position,
not by header label.

### Import CSV → YAML

```bash
# Update existing files in place (template-dir defaults to output-dir)
pipenv run python .scripts/mapping_converter/mapping_converter.py csv2yml \
  --input edr_mappings.csv \
  --output-dir data_models/edr_data_models

# Use a separate template directory if the existing YAMLs live elsewhere
pipenv run python .scripts/mapping_converter/mapping_converter.py csv2yml \
  --input edr_mappings.csv \
  --output-dir ./new_models \
  --template-dir data_models/edr_data_models
```

## CSV format

| Column              | Description                                                                |
| ------------------- | -------------------------------------------------------------------------- |
| Column 1            | Unified field name from your mapping framework (Sigma / OCSF / ECS / …)    |
| `{LogType} (Value)` | JSONPath (for `Path`) or function name (for `Method`)                      |
| `{LogType} (Type)`  | Either `Path` or `Method`                                                  |

The column-1 header can be named anything — `Field`, `Sigma Field`, `OCSF Field`,
`ECS Field`, etc. — the tool reads by position.

Example using OCSF field names across two IdP log types:

```csv
OCSF Field,Okta.SystemLog (Value),Okta.SystemLog (Type),OneLogin.Events (Value),OneLogin.Events (Type)
actor.user.name,$.actor.alternateId,Path,$.actor_user,Path
src_endpoint.ip,$.client.ipAddress,Path,$.ipaddr,Path
activity_name,$.eventType,Path,$.event_type_id,Path
http_request.user_agent,$.client.userAgent.rawUserAgent,Path,$.user_agent,Path
process.name,get_process_name,Method,get_process_name,Method
```

An empty `Value`/`Type` pair means "no mapping for this log type" and is skipped.

## How `csv2yml` decides what to write

For each log type column in the CSV:

1. Search `--template-dir` (default: `--output-dir`) for an existing data model
   whose `LogTypes:` contains that log type.
2. **If found:** the existing file is loaded with `ruamel.yaml`, the `Mappings`
   list is merged (entries with the same `Name` are updated in place, removed
   entries are dropped, new entries are appended), and the file is written back
   to its original path. Top-level comments, key order, and quoting survive.
   Comments attached to retained mapping entries also survive; comments attached
   to dropped entries do not.
3. **If not found:** a new `{logtype}_data_model.yml` is created in
   `--output-dir` (dots replaced with underscores, lowercased). If no matching
   `.py` exists, a stub is generated next to it containing placeholder functions
   for every `Method:` mapping, so the dual-file convention is satisfied and the
   model loads without `ImportError`. Replace the `TODO` bodies before enabling.

## Roundtrip guarantees

`yml2csv` → `csv2yml` on the existing EDR data models is byte-identical to the
original YAML (it only adds a trailing newline if one was missing). The lone
caveats: ordering inside the CSV is alphabetical by field name, but when
writing back, the existing file's mapping order is preserved for retained
entries, and any genuinely new entries are appended at the end.

## Typical workflow

```bash
# 1. Export current state
pipenv run python .scripts/mapping_converter/mapping_converter.py yml2csv \
  --input-dir data_models/edr_data_models --output /tmp/mappings.csv

# 2. Edit in a spreadsheet (add fields, fill gaps, fix paths)

# 3. Write changes back in place
pipenv run python .scripts/mapping_converter/mapping_converter.py csv2yml \
  --input /tmp/mappings.csv --output-dir data_models/edr_data_models

# 4. Review and test
git diff data_models/edr_data_models/
make data-models-unit-test
make fmt && make lint
```

## Bootstrapping a brand-new set of data models (e.g. IdPs)

Use this when you have a spreadsheet of unified → vendor field mappings for log
types that **don't yet have a data model in the repo** — for example a fresh
IdP suite covering `Okta.SystemLog`, `OneLogin.Events`,
`JumpCloud.DirectoryInsights`, mapped against whatever framework you've chosen
(Sigma, OCSF, ECS, etc.).

1. **Create the directory** that will hold the new family of data models:

   ```bash
   mkdir -p data_models/idp_data_models
   ```

2. **Author the CSV.** One row per unified field, two columns per log type. The
   `(Type)` column must be `Path` (JSONPath into the event) or `Method` (the
   name of a helper function you'll implement in the `.py`). Name column 1
   after your framework — the script reads it by position:

   ```csv
   OCSF Field,Okta.SystemLog (Value),Okta.SystemLog (Type),OneLogin.Events (Value),OneLogin.Events (Type)
   actor.user.name,$.actor.alternateId,Path,$.actor_user,Path
   src_endpoint.ip,$.client.ipAddress,Path,$.ipaddr,Path
   activity_name,$.eventType,Path,$.event_type_id,Path
   http_request.user_agent,$.client.userAgent.rawUserAgent,Path,$.user_agent,Path
   process.name,get_process_name,Method,get_process_name,Method
   ```

   Save it somewhere outside the data-models directory so it doesn't get picked
   up by PAT — e.g. `/tmp/idp_mappings.csv` or this script's directory.

3. **Run `csv2yml`** pointing `--output-dir` at the new directory. Since no
   existing YAML matches the log types, each one is created from scratch and a
   stub `.py` is emitted alongside it:

   ```bash
   pipenv run python .scripts/mapping_converter/mapping_converter.py csv2yml \
     --input /tmp/idp_mappings.csv \
     --output-dir data_models/idp_data_models
   ```

   You should see one `Creating new file for ...` line per log type, plus a
   matching `Created stub:` line for any `Method:` mappings.

4. **Fill in the stub `.py` files.** Each generated stub looks like:

   ```python
   """Okta.SystemLog Data Model - generated stub.

   Replace TODO bodies with real logic before enabling.
   """

   def get_process_name(event):  # noqa: ARG001
       """TODO: implement get_process_name."""
       return None
   ```

   Replace each `TODO` body with real logic, using `event.get(...)` /
   `event.deep_get(...)` for safe field access (see the rules in
   [`AGENTS.md`](../../AGENTS.md)). If a data model has **no** `Method:`
   mappings, the stub will be a near-empty file — that's fine; the `.py` still
   needs to exist for the dual-file rule.

5. **Sanity-check the generated YAML.** Verify, per file:
   - `Filename:` matches the sibling `.py` exactly.
   - `DataModelID:` is unique across the repo (generator default is
     `Standard.{LogType}` — adjust if that collides, or to reflect a framework
     other than Panther's standard naming).
   - `DisplayName:` reads well; default is `{LogType} - Field Mappings`.
   - `LogTypes:` has the right value.
   - The unified field names in `Mappings[].Name` match what your detection
     code / framework expects (Sigma names, OCSF dotted paths, ECS field names,
     etc.).

6. **Test and lint:**

   ```bash
   make data-models-unit-test
   make fmt && make lint
   pipenv run panther_analysis_tool test --path data_models/idp_data_models/
   ```

7. **Commit the YAML and Python together** (per CLAUDE.md rule #3). The CSV
   itself is a working artifact — commit it only if you want it tracked as
   documentation.

### Iterating on the spreadsheet after the initial run

Once the YAMLs exist, the same CSV becomes the source of truth for future
edits. Re-running `csv2yml` with the same `--output-dir` updates the existing
files in place (preserving comments and ordering) and only creates new files
for log types newly added to the CSV.

## Related references

- [`data_models/edr_data_models/SIGMA_FIELD_MAPPING_REFERENCE.md`](../../data_models/edr_data_models/SIGMA_FIELD_MAPPING_REFERENCE.md) — example reference for a Sigma-based mapping set.
- [`data_models/edr_data_models/UNIFIED_SIGMA_EDR_GUIDE.md`](../../data_models/edr_data_models/UNIFIED_SIGMA_EDR_GUIDE.md) — example guide for cross-platform detections built on a unified field set.
