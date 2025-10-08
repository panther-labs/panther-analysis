import dataclasses
import hashlib
import os
import subprocess
from typing import Any, Dict, Generator, Optional

import pydantic
import yaml

_VERSIONS_FILE_NAME = ".versions.yml"


class AnalysisVersionHistoryItem(pydantic.BaseModel):
    commit_hash: str
    pyFilePath: Optional[str] = None
    yamlFilePath: str


class AnalysisVersionItem(pydantic.BaseModel):
    history: dict[int, AnalysisVersionHistoryItem]
    sha256: str
    type: str
    version: int


class VersionsFile(pydantic.BaseModel):
    versions: dict[str, AnalysisVersionItem]


@dataclasses.dataclass
class AnalysisItem:
    _id: str
    type: str
    py: str
    analysis_spec: Dict[str, Any]
    yamlFilePath: str
    pyFilePath: str
    sha256: str
    version: int


def update_version_item(version_file: VersionsFile, analysis_item: AnalysisItem):
    versions = version_file.versions

    version_item = (
        versions[analysis_item._id]
        if analysis_item._id in versions
        else AnalysisVersionItem(
            version=1,
            sha256=analysis_item.sha256,
            type=analysis_item.type,
            history={},
        )
    )

    if version_item.sha256 != analysis_item.sha256:
        version_item.version = version_item.version + 1
        version_item.sha256 = analysis_item.sha256
        version_item.type = analysis_item.type

    analysis_item.version = version_item.version
    versions[analysis_item._id] = version_item


def update_version_history(
    version_file: VersionsFile, analysis_item: AnalysisItem, commit_hash: str
):
    versions = version_file.versions
    version_item = versions[analysis_item._id]
    history = version_item.history

    if analysis_item.version not in history:
        history[analysis_item.version] = AnalysisVersionHistoryItem(
            commit_hash=commit_hash,
            yamlFilePath=analysis_item.yamlFilePath,
            pyFilePath=analysis_item.pyFilePath
            if analysis_item.pyFilePath != ""
            else None,
        )

    version_item.history = history
    versions[analysis_item._id] = version_item


def load_analysis_items() -> Generator[AnalysisItem, None, None]:
    for root, _, files in os.walk("."):
        if (
            "/rules" not in root
            and "/policies" not in root
            and "/queries" not in root
            and "/simple_rules" not in root
            and "/correlation_rules" not in root
            and "/data_models" not in root
            and "/packs" not in root
            and "/global_helpers" not in root
        ):
            continue

        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                with open(os.path.join(root, file), "r") as f:
                    analysis_spec: Dict[str, Any] = yaml.safe_load(f)
                    py = ""
                    if "Filename" in analysis_spec:
                        with open(
                            os.path.join(root, analysis_spec["Filename"]), "r"
                        ) as f:
                            py = f.read()

                    yield AnalysisItem(
                        _id=analysis_id(analysis_spec),
                        type=analysis_spec["AnalysisType"],
                        py=py,
                        analysis_spec=analysis_spec,
                        yamlFilePath=os.path.join(root, file),
                        pyFilePath=os.path.join(root, analysis_spec["Filename"])
                        if py != ""
                        else "",
                        sha256=create_version_hash(analysis_spec, py),
                        version=1,
                    )


def create_version_hash(analysis_spec: Dict[str, Any], py: str) -> str:
    # TODO: should not be new version if yaml rearranged or comments changed
    return hashlib.sha256(f"{analysis_spec}{py}".encode("utf-8")).hexdigest()


def analysis_id(analysis_spec: Dict[str, Any]) -> str:
    match analysis_spec["AnalysisType"]:
        case "rule" | "scheduled_rule" | "simple_rule" | "correlation_rule":
            return analysis_spec["RuleID"]
        case "policy":
            return analysis_spec["PolicyID"]
        case "query" | "saved_query" | "scheduled_query":
            return analysis_spec["QueryName"]
        case "datamodel":
            return analysis_spec["DataModelID"]
        case "pack":
            return analysis_spec["PackID"]
        case "global":
            return analysis_spec["GlobalID"]
        case _:
            raise ValueError(f"Invalid analysis type: {analysis_spec['AnalysisType']}")


def load_versions_file() -> VersionsFile:
    # Create ".versions.yml" if it doesn't exist
    if not os.path.exists(_VERSIONS_FILE_NAME):
        with open(_VERSIONS_FILE_NAME, "w") as vf:
            vf.write("")

    # Load yaml from the file into a dict
    with open(_VERSIONS_FILE_NAME, "r") as vf:
        versions = yaml.safe_load(vf)
        if versions is None:
            versions = {}
        if "versions" not in versions:
            versions["versions"] = {}

    return VersionsFile(**versions)


def dump_versions_file(versions: VersionsFile):
    with open(_VERSIONS_FILE_NAME, "w") as vf:
        yaml.safe_dump(versions.model_dump(exclude_none=True), vf)


def generate_version_file(commit_hash: str):
    versions_file = load_versions_file()

    for analysis_item in load_analysis_items():
        update_version_item(versions_file, analysis_item)
        update_version_history(versions_file, analysis_item, commit_hash)

    dump_versions_file(versions_file)


def get_commit_hash() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True)
    if result.stderr:
        raise Exception(result.stderr.decode("utf-8"))
    return result.stdout.decode("utf-8").strip()


if __name__ == "__main__":
    commit_hash = get_commit_hash()
    print(f"Commit hash: {commit_hash}")
    generate_version_file(commit_hash)
