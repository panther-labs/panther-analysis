#!/usr/bin/env python3
"""
Bi-directional converter for Panther Data Model YML files and CSV mappings.

This script can:
1. Parse YML data model files and export to CSV
2. Import CSV mappings and generate/update YML data model files

Usage:
    # Export YML to CSV
    python mapping_converter.py yml2csv --input-dir ./data_models/edr_data_models --output mappings.csv

    # Import CSV to YML
    python mapping_converter.py csv2yml --input mappings.csv --output-dir ./data_models/edr_data_models

    # Specify specific YML files
    python mapping_converter.py yml2csv --files file1.yml file2.yml --output mappings.csv

Roundtrip notes:
- When csv2yml finds an existing YAML for a log type, it updates that file in place
  (preserving top-level comments, key ordering, and quoting via ruamel.yaml).
- Within the Mappings list, comments attached to retained entries are preserved.
  Removed entries (and their attached comments) are dropped; new entries are
  appended at the end of the list.
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool.analysis_utils import load_analysis_specs
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq


def _yaml() -> YAML:
    """Configure a ruamel YAML round-tripper to match repo style."""
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 100
    return y


class MappingConverter:
    """Handles conversion between YML data models and CSV format."""

    def __init__(self):
        self.data_models: List[Dict[str, Any]] = []

    def load_yml_files(self, file_paths: List[Path]) -> None:
        """Load data model YML files using PAT's analysis loader."""
        dirs_to_load = set()
        for file_path in file_paths:
            if file_path.exists():
                dirs_to_load.add(str(file_path.parent))
            else:
                print(f"Warning: File not found: {file_path}", file=sys.stderr)

        requested = {fp.resolve() for fp in file_paths if fp.exists()}

        for directory in dirs_to_load:
            try:
                for spec_abs_path, _rel_path, spec, _err in load_analysis_specs([directory], []):
                    if spec.get("AnalysisType") != "datamodel":
                        continue

                    spec_path = Path(spec_abs_path).resolve()
                    if requested and spec_path not in requested:
                        continue

                    if "Mappings" not in spec:
                        print(f"Warning: No mappings found in {spec_path}", file=sys.stderr)
                        continue

                    self.data_models.append({"file_path": spec_path, "data": spec})
                    print(f"Loaded: {spec_path}")

            except Exception as e:
                print(f"Error loading from {directory}: {e}", file=sys.stderr)

    def yml_to_csv(self, output_path: Path) -> None:
        """Convert loaded YML files to CSV format."""
        if not self.data_models:
            print("No data models loaded. Exiting.", file=sys.stderr)
            return

        all_field_names = set()
        log_type_to_mappings: Dict[str, Dict[str, Dict[str, str]]] = {}

        for model in self.data_models:
            data = model["data"]
            for log_type in data.get("LogTypes", []):
                if log_type not in log_type_to_mappings:
                    log_type_to_mappings[log_type] = {}

                for mapping in data.get("Mappings", []):
                    field_name = mapping.get("Name")
                    if not field_name:
                        continue
                    all_field_names.add(field_name)

                    if "Path" in mapping and "Method" in mapping:
                        print(
                            f"Warning: {field_name} in {log_type} has both Path and Method; "
                            f"using Path",
                            file=sys.stderr,
                        )
                    if "Path" in mapping:
                        value, mapping_type = mapping["Path"], "Path"
                    elif "Method" in mapping:
                        value, mapping_type = mapping["Method"], "Method"
                    else:
                        continue

                    log_type_to_mappings[log_type][field_name] = {
                        "value": value,
                        "type": mapping_type,
                    }

        sorted_fields = sorted(all_field_names)
        sorted_log_types = sorted(log_type_to_mappings.keys())

        try:
            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                header = ["Field"]
                for log_type in sorted_log_types:
                    header.append(f"{log_type} (Value)")
                    header.append(f"{log_type} (Type)")

                writer = csv.writer(csvfile)
                writer.writerow(header)

                for field_name in sorted_fields:
                    row = [field_name]
                    for log_type in sorted_log_types:
                        info = log_type_to_mappings[log_type].get(field_name, {})
                        row.append(info.get("value", ""))
                        row.append(info.get("type", ""))
                    writer.writerow(row)

            print(f"\nSuccessfully exported to: {output_path}")
            print(f"Fields: {len(sorted_fields)}")
            print(f"Log Types: {len(sorted_log_types)}")
            print(f"  - {', '.join(sorted_log_types)}")

        except Exception as e:
            print(f"Error writing CSV: {e}", file=sys.stderr)
            sys.exit(1)

    def csv_to_yml(
        self, csv_path: Path, output_dir: Path, template_dir: Optional[Path] = None
    ) -> None:
        """Convert CSV mappings to YML data model files."""
        if not csv_path.exists():
            print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
            sys.exit(1)

        try:
            with open(csv_path, "r", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
                headers = reader.fieldnames

            if not rows:
                print("Error: CSV file is empty", file=sys.stderr)
                sys.exit(1)
            if not headers or len(headers) < 2:
                print("Error: CSV header is missing or malformed", file=sys.stderr)
                sys.exit(1)

            # First column is the unified field name; its label is framework-agnostic
            # ("Field", "Sigma Field", "OCSF Field", "ECS Field", etc.). Whatever the
            # author named it, we read by position.
            field_col = headers[0]

            log_types: List[str] = []
            for header in headers[1:]:
                if header.endswith(" (Value)"):
                    log_types.append(header[: -len(" (Value)")])

            print(f"Detected log types: {', '.join(log_types)}")

            log_type_mappings: Dict[str, List[Dict[str, str]]] = {lt: [] for lt in log_types}

            for row in rows:
                field_name = row.get(field_col, "").strip()
                if not field_name:
                    continue
                for log_type in log_types:
                    value = row.get(f"{log_type} (Value)", "").strip()
                    mapping_type = row.get(f"{log_type} (Type)", "").strip()
                    if not (value and mapping_type):
                        continue

                    mapping = {"Name": field_name}
                    if mapping_type == "Path":
                        mapping["Path"] = value
                    elif mapping_type == "Method":
                        mapping["Method"] = value
                    else:
                        print(
                            f"Warning: Unknown mapping type '{mapping_type}' for "
                            f"{field_name} in {log_type}",
                            file=sys.stderr,
                        )
                        continue
                    log_type_mappings[log_type].append(mapping)

            output_dir.mkdir(parents=True, exist_ok=True)
            search_dir = template_dir or output_dir

            for log_type, mappings in log_type_mappings.items():
                if not mappings:
                    print(f"Warning: No mappings found for {log_type}", file=sys.stderr)
                    continue

                template = self._find_template(log_type, search_dir)

                if template is not None:
                    template_path, yml_data = template
                    print(f"Updating existing file for {log_type}: {template_path}")
                    self._merge_mappings(yml_data, mappings)
                    self._write_yml_file(template_path, yml_data)
                else:
                    print(f"Creating new file for {log_type}")
                    yml_data, py_filename = self._create_basic_structure(log_type, mappings)
                    output_file = self._get_output_filename(log_type, output_dir)
                    self._write_yml_file(output_file, yml_data)
                    self._ensure_py_stub(output_dir / py_filename, log_type, mappings)

            print(f"\nProcessed {len(log_type_mappings)} log types")

        except Exception as e:
            print(f"Error processing CSV: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()
            sys.exit(1)

    def _find_template(
        self, log_type: str, search_dir: Path
    ) -> Optional[Tuple[Path, CommentedMap]]:
        """Find an existing YML for this log type. Returns (path, ruamel-loaded data)."""
        if not search_dir.exists():
            return None

        # Use PAT to locate the right file (matches by LogTypes), then re-load with
        # ruamel so comments / ordering / quoting are preserved on write-back.
        try:
            for spec_abs_path, _rel_path, spec, _err in load_analysis_specs(
                [str(search_dir)], []
            ):
                if spec.get("AnalysisType") != "datamodel":
                    continue
                if log_type not in spec.get("LogTypes", []):
                    continue

                spec_path = Path(spec_abs_path)
                with open(spec_path, "r", encoding="utf-8") as f:
                    data = _yaml().load(f)
                return spec_path, data
        except Exception as e:
            print(f"Warning: template lookup failed in {search_dir}: {e}", file=sys.stderr)

        return None

    @staticmethod
    def _merge_mappings(yml_data: CommentedMap, new_mappings: List[Dict[str, str]]) -> None:
        """Update Mappings in place: preserve comments on retained entries, drop
        removed entries, append truly-new ones at the end."""
        new_by_name = {m["Name"]: m for m in new_mappings}
        existing: CommentedSeq = yml_data.get("Mappings") or CommentedSeq()

        merged = CommentedSeq()
        # Preserve order & attached comments for entries still present.
        for entry in existing:
            name = entry.get("Name") if isinstance(entry, dict) else None
            if name is None or name not in new_by_name:
                continue
            updated = new_by_name.pop(name)
            entry.pop("Path", None)
            entry.pop("Method", None)
            if "Path" in updated:
                entry["Path"] = updated["Path"]
            elif "Method" in updated:
                entry["Method"] = updated["Method"]
            merged.append(entry)

        # Append entries that didn't exist before.
        for name, mapping in new_by_name.items():
            merged.append(CommentedMap(mapping))

        yml_data["Mappings"] = merged

    @staticmethod
    def _create_basic_structure(
        log_type: str, mappings: List[Dict[str, str]]
    ) -> Tuple[CommentedMap, str]:
        """Create basic YML structure for a new data model. Returns (yaml, py_filename)."""
        model_id = log_type.replace(".", "_").lower()
        py_filename = f"{model_id}_data_model.py"

        data = CommentedMap()
        data["AnalysisType"] = "datamodel"
        data["DataModelID"] = f"Standard.{log_type}"
        data["DisplayName"] = f"{log_type} - Field Mappings"
        data["Enabled"] = True
        data["Filename"] = py_filename
        data["LogTypes"] = [log_type]
        data["Mappings"] = CommentedSeq(CommentedMap(m) for m in mappings)
        return data, py_filename

    @staticmethod
    def _get_output_filename(log_type: str, output_dir: Path) -> Path:
        safe_name = log_type.replace(".", "_").lower()
        return output_dir / f"{safe_name}_data_model.yml"

    @staticmethod
    def _ensure_py_stub(py_path: Path, log_type: str, mappings: List[Dict[str, str]]) -> None:
        """Create a minimal .py stub so the dual-file convention is satisfied.

        Only writes if the file doesn't already exist. Includes stub functions
        for any Method: mappings so the data model loads without ImportError.
        """
        if py_path.exists():
            return

        method_names = sorted({m["Method"] for m in mappings if "Method" in m})
        lines = [
            f'"""{log_type} Data Model - generated stub.',
            "",
            "Replace TODO bodies with real logic before enabling.",
            '"""',
            "",
        ]
        for fn in method_names:
            lines.extend(
                [
                    f"def {fn}(event):  # noqa: ARG001",
                    f'    """TODO: implement {fn}."""',
                    "    return None",
                    "",
                    "",
                ]
            )
        if not method_names:
            # data model .py is required even with no helpers
            lines.append("# No helper methods required for this data model.\n")

        py_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"  Created stub: {py_path}")

    @staticmethod
    def _write_yml_file(file_path: Path, data: Any) -> None:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                _yaml().dump(data, f)
            print(f"  Wrote: {file_path}")
        except Exception as e:
            print(f"Error writing {file_path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Convert between Panther Data Model YML files and CSV mappings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    yml2csv_parser = subparsers.add_parser("yml2csv", help="Convert YML files to CSV")
    yml2csv_group = yml2csv_parser.add_mutually_exclusive_group(required=True)
    yml2csv_group.add_argument(
        "--input-dir", "-d", type=Path, help="Directory containing YML files"
    )
    yml2csv_group.add_argument("--files", "-f", nargs="+", type=Path, help="Specific YML files")
    yml2csv_parser.add_argument(
        "--output", "-o", type=Path, required=True, help="Output CSV file path"
    )

    csv2yml_parser = subparsers.add_parser("csv2yml", help="Convert CSV to YML files")
    csv2yml_parser.add_argument(
        "--input", "-i", type=Path, required=True, help="Input CSV file path"
    )
    csv2yml_parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        required=True,
        help="Output directory for new YML/.py files (existing files are updated in place)",
    )
    csv2yml_parser.add_argument(
        "--template-dir",
        "-t",
        type=Path,
        help="Directory with existing YML files to use as templates (defaults to --output-dir)",
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    converter = MappingConverter()

    if args.command == "yml2csv":
        if args.input_dir:
            if not args.input_dir.exists():
                print(f"Error: Directory not found: {args.input_dir}", file=sys.stderr)
                sys.exit(1)
            file_paths = list(args.input_dir.glob("*_data_model.yml"))
        else:
            file_paths = args.files

        if not file_paths:
            print("Error: No YML files found", file=sys.stderr)
            sys.exit(1)

        converter.load_yml_files(file_paths)
        converter.yml_to_csv(args.output)

    elif args.command == "csv2yml":
        converter.csv_to_yml(args.input, args.output_dir, args.template_dir)


if __name__ == "__main__":
    main()
