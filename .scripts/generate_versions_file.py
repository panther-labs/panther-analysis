"""
This script generates a versions file for the project.
The versions file is used to track the versions of the analysis items in the project.

Run with:
    make generate-versions

The script will:
1. Load all analysis items from the project directory
2. Update the versions and history for each analysis item
3. Write the updated versions file to disk

The resulting versions file will be in the root of the project at .versions.yml and will look like this:

```yaml
versions:
  a rule id:
    history:
      1:
        commit_hash: 7bef7e91ae1f808f6282837d2a546fd0d4131b4a
        yaml_file_path: ./rules/name.yml
        py_file_path: ./rules/name.py
    sha256: 2beac598a2584938d646fe8ba0db999a8c1533e10b0c5b58f818a727b385502d
    type: rule
    version: 1
  a policy id:
    history:
      1:
        commit_hash: 7bef7e91ae1f808f6282837d2a546fd0d4131b4a
        yaml_file_path: ./policies/name.yml
        py_file_path: ./policies/name.py
    sha256: 2beac598a2584938d646fe8ba0db999a8c1533e10b0c5b58f818a727b385502d
    type: policy
    version: 1
  a query id:
    history:
      1:
        commit_hash: 7bef7e91ae1f808f6282837d2a546fd0d4131b4a
        yaml_file_path: ./queries/name.yml
      2:
        commit_hash: 8f6282837d2a546fd0d4131b4a7bef7e91ae1f80
        yaml_file_path: ./queries/name.yml
    sha256: 2beac598a2584938d646fe8ba0db999a8c1533e10b0c5b58f818a727b385502d
    type: scheduled_query
    version: 2
...
```
"""

import dataclasses
import hashlib
import os
import pathlib
import subprocess
from typing import Any, Generator, Optional

import pydantic
import yaml
from panther_analysis_tool.analysis_utils import load_analysis_specs

_VERSIONS_FILE_NAME = ".versions.yml"


class AnalysisVersionHistoryItem(pydantic.BaseModel):
    commit_hash: str
    py_file_path: Optional[str] = None
    yaml_file_path: str


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
    analysis_spec: dict[str, Any]
    yaml_file_path: str
    py_file_path: str
    sha256: str
    version: int


def update_version_item(
    version_file: VersionsFile, analysis_item: AnalysisItem, commit_hash: str
):
    """
    Update or create a version item in the versions file.
    If the analysis item doesn't exist in the versions file, it creates a new entry.
    If the analysis item DOES NOT serialize to the same hash as the existing item,
    it increments the version and updates the SHA256 hash.
    If the item has a new version, it adds a new entry to the version history, with the commit it is from.

    Args:
        version_file (VersionsFile): The current versions file.
        analysis_item (AnalysisItem): The analysis item to update or create.
        commit_hash (str): The commit hash associated with this version.

    This function updates the version, SHA256 hash, and type of the analysis item
    in the versions file. If the item doesn't exist, it creates a new entry.
    """
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

    # update the version history for the item
    history = version_item.history

    if version_item.version not in history:
        history[version_item.version] = AnalysisVersionHistoryItem(
            commit_hash=commit_hash,
            yaml_file_path=analysis_item.yaml_file_path,
            py_file_path=analysis_item.py_file_path
            if analysis_item.py_file_path != ""
            else None,
        )

    version_item.history = history
    versions[analysis_item._id] = version_item


def load_analysis_items() -> Generator[AnalysisItem, None, None]:
    """
    Load all analysis items from the current directory.

    Yields:
        Generator[AnalysisItem, None, None]: A generator of AnalysisItem objects.
    """
    for spec_abs_path, rel_path, spec, _ in load_analysis_specs(["."], []):
        spec_path = pathlib.Path(rel_path) / pathlib.Path(spec_abs_path).name
        py_path = pathlib.Path()
        py = ""
        if "Filename" in spec:
            py_path = pathlib.Path(rel_path) / spec["Filename"]
            with open(py_path, "r") as f:
                py = f.read()

        yield AnalysisItem(
            _id=analysis_id(spec),
            type=spec["AnalysisType"],
            py=py,
            analysis_spec=spec,
            yaml_file_path=str(spec_path),
            py_file_path=str(py_path) if py else "",
            sha256=create_version_hash(spec, py),
            version=1,
        )


def create_version_hash(analysis_spec: dict[str, Any], py: str) -> str:
    """
    Create a hash of the analysis spec and py code.
    The hash is created by sorting the analysis spec keys alphabetically and then concatenating the spec and py code.
    This ensures that the hash is the same for the same analysis spec and py code, regardless of the order of the keys in the spec.

    Args:
        analysis_spec (dict[str, Any]): The analysis spec to hash.
        py: The python code to hash.

    Returns:
        A hash of the analysis spec and py code.
    """
    ordered_spec = dict(sorted(analysis_spec.items()))
    return hashlib.sha256(f"{ordered_spec}{py}".encode("utf-8")).hexdigest()


def analysis_id(analysis_spec: dict[str, Any]) -> str:
    """
    Determine the ID of an analysis item based on its type at `AnalysisType`.

    Args:
        analysis_spec (dict[str, Any]): The analysis specification.

    Returns:
        str: The ID of the analysis item.

    Raises:
        ValueError: If the analysis type is invalid.
    """
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
        case "lookup_table":
            return analysis_spec["LookupName"]
        case _:
            raise ValueError(f"Invalid analysis type: {analysis_spec['AnalysisType']}")


def load_versions_file() -> VersionsFile:
    """
    Load the versions file or create it if it doesn't exist.
    Reads the `.versions.yml` file into a VersionsFile object.

    Returns:
        VersionsFile: The loaded versions file.
    """
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
    """
    Write the versions file to disk at `.versions.yml`. Any
    None values are excluded from the file.

    Args:
        versions (VersionsFile): The versions file to write.
    """
    with open(_VERSIONS_FILE_NAME, "w") as vf:
        yaml.safe_dump(versions.model_dump(exclude_none=True), vf)


def generate_version_file(commit_hash: str):
    """
    Generate or update the versions file for all analysis items.
    This function loads all analysis items, updates their versions and history,
    and writes the updated information to the versions file.

    Args:
        commit_hash (str): The current commit hash.
    """
    versions_file = load_versions_file()

    for analysis_item in load_analysis_items():
        update_version_item(versions_file, analysis_item, commit_hash)
    dump_versions_file(versions_file)


def get_commit_hash() -> str:
    """
    Get the current Git commit hash.
    Runs the 'git rev-parse HEAD' command to get the current commit hash.

    Returns:
        str: The current Git commit hash.

    Raises:
        Exception: If there's an error executing the Git command.
    """
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True)
    if result.stderr:
        raise Exception(result.stderr.decode("utf-8"))
    return result.stdout.decode("utf-8").strip()


if __name__ == "__main__":
    commit_hash = get_commit_hash()
    print(f"Commit hash: {commit_hash}")
    generate_version_file(commit_hash)
