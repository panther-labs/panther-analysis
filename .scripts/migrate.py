import hashlib
import io
import os
import re
import shutil
from typing import Any
from ruamel.yaml import YAML
import json 


def get_yaml_loader(roundtrip=False) -> YAML:
    """Returns a YAML object with the correct settings for loading analysis specifications.

    Args:
        roundtrip: Whether or not the YAML parser should be roundtrip safe. Roundtrip safe YAML
            parser is not compatible with many PAT functions.
    """
    # If we need to roundtrip, we have different requirements. Most use cases will not need
    # round-tripping. We only need a roundtrip safe YAML parser if we are going to update
    # the YAML files.
    if roundtrip:
        yaml = YAML(typ="rt")
        yaml.preserve_quotes = True

    else:
        yaml = YAML(typ="safe")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False
    # allow very long lines to avoid unnecessary line changes
    yaml.width = 4096
    return yaml


rt_yaml = get_yaml_loader(roundtrip=True)
yaml = get_yaml_loader(roundtrip=False)


def handle_packs() -> None:
    shutil.rmtree("packs", ignore_errors=True)


enabled_regex = re.compile(r"^Enabled: (.*)$", re.MULTILINE)


def disable(data: bytes) -> bytes:
    match = enabled_regex.sub(r"Enabled: false", data)
    return match


def enable(data: bytes) -> bytes:
    match = enabled_regex.sub(r"Enabled: true", data)
    return match


def migrate_yaml_files():
    for dirpath, dirnames, filenames in os.walk("."):
        if dirpath == ".":
            dirnames[:] = [d for d in dirnames if d not in ["packs", "templates"]]

        for file in filenames:
            if not file.endswith(".yml") and not file.endswith(".yaml"):
                continue

            file_path = os.path.join(dirpath, file)
            with open(file_path, "r") as f:
                file_contents = f.read()

            data = yaml.load(io.StringIO(file_contents))

            if "AnalysisType" in data:
                analysis_type = data["AnalysisType"]
                if analysis_type in [AnalysisTypes.GLOBAL, AnalysisTypes.SAVED_QUERY]:
                    continue

                if "Enabled" not in data:
                    raise ValueError(f"Analysis {file_path} does not have an Enabled field")
                
                if analysis_type == AnalysisTypes.LOOKUP_TABLE:
                    # some lookup tables are disabled in purpose, don't touch them
                    continue

                new_file_contents = disable(file_contents)
                if new_file_contents != file_contents:
                    with open(file_path, "w") as f:
                        f.write(new_file_contents)


def get_sha256(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


class AnalysisTypes:
    DATA_MODEL = "datamodel"
    GLOBAL = "global"
    LOOKUP_TABLE = "lookup_table"
    PACK = "pack"
    POLICY = "policy"
    SAVED_QUERY = "saved_query"
    SCHEDULED_QUERY = "scheduled_query"
    RULE = "rule"
    DERIVED = "derived"
    SCHEDULED_RULE = "scheduled_rule"
    SIMPLE_DETECTION = "simple_detection"
    CORRELATION_RULE = "correlation_rule"


def lookup_analysis_id(analysis_spec: Any, analysis_type: str) -> str:
    analysis_id = "UNKNOWN_ID"
    if analysis_type == AnalysisTypes.DATA_MODEL:
        analysis_id = analysis_spec["DataModelID"]
    elif analysis_type == AnalysisTypes.GLOBAL:
        analysis_id = analysis_spec["GlobalID"]
    elif analysis_type == AnalysisTypes.LOOKUP_TABLE:
        analysis_id = analysis_spec["LookupName"]
    elif analysis_type == AnalysisTypes.PACK:
        analysis_id = analysis_spec["PackID"]
    elif analysis_type == AnalysisTypes.POLICY:
        analysis_id = analysis_spec["PolicyID"]
    elif analysis_type == AnalysisTypes.SCHEDULED_QUERY:
        analysis_id = analysis_spec["QueryName"]
    elif analysis_type == AnalysisTypes.SAVED_QUERY:
        analysis_id = analysis_spec["QueryName"]
    elif analysis_type in [
        AnalysisTypes.RULE,
        AnalysisTypes.SCHEDULED_RULE,
        AnalysisTypes.CORRELATION_RULE,
    ]:
        analysis_id = analysis_spec["RuleID"]
    return analysis_id



def generate_version_file():
    versions = {}
    try:
        with open("version.json", "r") as f:
            versions = json.load(f)["versions"]
    except FileNotFoundError:
        pass

    for dirpath, dirnames, filenames in os.walk("."):
        if dirpath == ".":
            dirnames[:] = [d for d in dirnames if d != "templates"]

        for file in filenames:
            if not file.endswith(".yml") and not file.endswith(".yaml"):
                continue
            file_path = os.path.join(dirpath, file)
            with open(file_path, "r") as f:
                data = yaml.load(f)
            if "AnalysisType" not in data:
                continue
            sha256 = get_sha256(data)
            content_id = lookup_analysis_id(data, data["AnalysisType"])

            content_info = versions.get(content_id, {})
            if content_info.get("sha256") != sha256:
                versions[content_id] = {"sha256": sha256, "type": data["AnalysisType"], "version": content_info.get("version", 0) + 1}

    with open("version.json", "w") as f:
        json.dump({"versions": versions}, f, sort_keys=True)

    validate_version_file()


def validate_version_file():
    with open("version.json", "r") as f:
        versions = json.load(f)["versions"]

    for dirpath, dirnames, filenames in os.walk("."):
        if dirpath == ".":
            dirnames[:] = [d for d in dirnames if d not in ["packs", "templates"]]

        for file in filenames:
            if not file.endswith(".yml") and not file.endswith(".yaml"):
                continue
            file_path = os.path.join(dirpath, file)
            with open(file_path, "r") as f:
                data = yaml.load(f)
            if "AnalysisType" not in data:
                continue
            content_id = lookup_analysis_id(data, data["AnalysisType"])
            if content_id not in versions:
                raise ValueError(f"Content {content_id} not found in version file")

    for content_id, content_info in versions.items():
        if content_info.get("sha256") is None:
            raise ValueError(f"Content {content_id} does not have a sha256")
        if content_info.get("type") is None:
            raise ValueError(f"Content {content_id} does not have a type")
        if content_info.get("version") is None:
            raise ValueError(f"Content {content_id} does not have a version")
        if content_info.get("version") < 1:
            raise ValueError(f"Content {content_id} has a version less than 1")


def main():
    handle_packs()
    migrate_yaml_files()
    generate_version_file()


if __name__ == "__main__":
    main()