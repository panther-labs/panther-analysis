from typing import Any
from unittest.mock import MagicMock, mock_open, patch

import pytest
import yaml
from generate_versions_file import (
    AnalysisItem,
    AnalysisVersionHistoryItem,
    AnalysisVersionItem,
    VersionsFile,
    analysis_id,
    create_version_hash,
    dump_versions_file,
    generate_version_file,
    get_commit_hash,
    load_versions_file,
    update_version_item,
)


# Test fixtures
@pytest.fixture
def sample_analysis_spec() -> dict[str, Any]:
    return {
        "AnalysisType": "rule",
        "RuleID": "Test.Rule",
        "Filename": "test_rule.py",
    }


@pytest.fixture
def sample_analysis_item(sample_analysis_spec) -> AnalysisItem:
    return AnalysisItem(
        _id="Test.Rule",
        type="rule",
        py="def rule(event): return True",
        analysis_spec=sample_analysis_spec,
        yaml_file_path="rules/test_rule.yml",
        py_file_path="rules/test_rule.py",
        sha256=create_version_hash(
            sample_analysis_spec, "def rule(event): return True"
        ),
        version=1,
    )


@pytest.fixture
def sample_versions_file() -> VersionsFile:
    return VersionsFile(
        versions={
            "Test.Rule": AnalysisVersionItem(
                version=1,
                sha256="abc123",
                type="rule",
                history={
                    1: AnalysisVersionHistoryItem(
                        commit_hash="def456",
                        yaml_file_path="rules/test_rule.yml",
                        py_file_path="rules/test_rule.py",
                    )
                },
            )
        }
    )


# Test AnalysisItem and related functions
def test_analysis_id_rule(sample_analysis_spec) -> None:
    assert analysis_id(sample_analysis_spec) == "Test.Rule"


def test_analysis_id_policy() -> None:
    spec = {"AnalysisType": "policy", "PolicyID": "Test.Policy"}
    assert analysis_id(spec) == "Test.Policy"


def test_analysis_id_query() -> None:
    spec = {"AnalysisType": "query", "QueryName": "Test.Query"}
    assert analysis_id(spec) == "Test.Query"


def test_analysis_id_invalid() -> None:
    spec = {"AnalysisType": "invalid"}
    with pytest.raises(ValueError):
        analysis_id(spec)


def test_create_version_hash() -> None:
    spec = {"key": "value"}
    py_code = "def test(): pass"
    hash1 = create_version_hash(spec, py_code)
    hash2 = create_version_hash(spec, py_code)
    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 produces 64 character hex string


def test_create_version_hash_different_spec() -> None:
    spec1 = {"key": "value"}
    spec2 = {"key2": "value2"}
    py_code = "def test(): pass"
    hash1 = create_version_hash(spec1, py_code)
    hash2 = create_version_hash(spec2, py_code)
    assert hash1 != hash2


def test_create_version_hash_different_py_code() -> None:
    spec = {"key": "value"}
    py_code1 = "def test(): pass"
    py_code2 = "def test2(): pass"
    hash1 = create_version_hash(spec, py_code1)
    hash2 = create_version_hash(spec, py_code2)
    assert hash1 != hash2


def test_create_version_hash_spec_comment_changed() -> None:
    spec1 = yaml.safe_load("# comment 1\nkey: value")
    spec2 = yaml.safe_load("# comment 2\nkey: value")
    py_code = "def test(): pass"
    hash1 = create_version_hash(spec1, py_code)
    hash2 = create_version_hash(spec2, py_code)
    assert hash1 == hash2


def test_create_version_hash_spec_order_changed() -> None:
    spec1 = yaml.safe_load("key: value\nkey2: value2")
    spec2 = yaml.safe_load("key2: value2\nkey: value")
    py_code = "def test(): pass"
    hash1 = create_version_hash(spec1, py_code)
    hash2 = create_version_hash(spec2, py_code)
    assert hash1 == hash2


# Test version management functions
def test_update_version_with_new_item(sample_analysis_item) -> None:
    versions = VersionsFile(versions={})
    update_version_item(versions, sample_analysis_item, "abc123")

    assert sample_analysis_item._id in versions.versions
    assert versions.versions[sample_analysis_item._id].version == 1
    assert (
        versions.versions[sample_analysis_item._id].sha256
        == sample_analysis_item.sha256
    )
    assert versions.versions[sample_analysis_item._id].type == sample_analysis_item.type


def test_update_existing_version_item_same_hash(
    sample_analysis_item, sample_versions_file
) -> None:
    sample_versions_file.versions[
        sample_analysis_item._id
    ].sha256 = sample_analysis_item.sha256
    update_version_item(sample_versions_file, sample_analysis_item, "abc123")

    assert sample_versions_file.versions[sample_analysis_item._id].version == 1


def test_update_existing_version_item_different_hash(
    sample_analysis_item, sample_versions_file
) -> None:
    newSha = "something different"
    newCommit = "new commit"
    sample_analysis_item.sha256 = newSha
    update_version_item(sample_versions_file, sample_analysis_item, newCommit)

    item = sample_versions_file.versions[sample_analysis_item._id]
    assert item.version == 2
    assert item.sha256 == newSha
    assert item.type == sample_analysis_item.type

    assert len(item.history) == 2
    assert item.history[1].commit_hash != newCommit
    assert item.history[1].yaml_file_path == sample_analysis_item.yaml_file_path
    assert item.history[1].py_file_path == sample_analysis_item.py_file_path

    assert item.history[2].commit_hash == newCommit
    assert item.history[2].yaml_file_path == sample_analysis_item.yaml_file_path
    assert item.history[2].py_file_path == sample_analysis_item.py_file_path


def test_update_version_history_with_new_item(sample_analysis_item) -> None:
    versions = VersionsFile(versions={})
    update_version_item(versions, sample_analysis_item, "abc123")

    assert sample_analysis_item._id in versions.versions
    history = versions.versions[sample_analysis_item._id].history
    assert 1 in history
    assert history[1].commit_hash == "abc123"
    assert history[1].yaml_file_path == sample_analysis_item.yaml_file_path
    assert history[1].py_file_path == sample_analysis_item.py_file_path


# Test file operations
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data="")
def test_load_versions_file_empty(mock_file, mock_exists) -> None:
    mock_exists.return_value = True
    result = load_versions_file()
    assert isinstance(result, VersionsFile)
    assert len(result.versions) == 0


@patch("os.path.exists")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="versions:\n  Test.Rule:\n    version: 1\n    sha256: abc123\n    type: rule\n    history: {}",
)
def test_load_existing_versions_file(mock_file, mock_exists) -> None:
    mock_exists.return_value = True
    result = load_versions_file()
    assert isinstance(result, VersionsFile)
    assert "Test.Rule" in result.versions
    assert result.versions["Test.Rule"].version == 1


@patch("builtins.open", new_callable=mock_open)
def test_dump_versions_file(mock_file) -> None:
    versions = VersionsFile(
        versions={
            "Test.Rule": AnalysisVersionItem(
                version=1,
                sha256="abc123",
                type="rule",
                history={
                    1: AnalysisVersionHistoryItem(
                        commit_hash="def456",
                        yaml_file_path="rules/test_rule.yml",
                        py_file_path="rules/test_rule.py",
                    )
                },
            )
        }
    )
    dump_versions_file(versions)
    mock_file.assert_called_once_with(".versions.yml", "w")
    mock_file().write.assert_called()


@patch("subprocess.run")
def test_get_commit_hash_success(mock_run) -> None:
    mock_run.return_value = MagicMock(
        stdout=b"abc123\n",
        stderr=b"",
    )
    assert get_commit_hash() == "abc123"


@patch("subprocess.run")
def test_get_commit_hash_error(mock_run) -> None:
    mock_run.return_value = MagicMock(
        stdout=b"",
        stderr=b"fatal: not a git repository",
    )
    with pytest.raises(Exception):
        get_commit_hash()


# Integration test
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
@patch("subprocess.run")
def test_generate_version_file_integration(mock_run, mock_file, mock_exists) -> None:
    mock_exists.return_value = True
    mock_run.return_value = MagicMock(stdout=b"test123\n", stderr=b"")

    with patch("generate_versions_file.load_analysis_items") as mock_load_items:
        mock_load_items.return_value = [
            AnalysisItem(
                _id="Test.Rule",
                type="rule",
                py="def rule(event): return True",
                analysis_spec={"AnalysisType": "rule", "RuleID": "Test.Rule"},
                yaml_file_path="rules/test_rule.yml",
                py_file_path="rules/test_rule.py",
                sha256="test_hash",
                version=1,
            )
        ]

        generate_version_file("test123")

        # Verify file operations
        mock_file.assert_called()
        # Verify yaml dump was called
        mock_file().write.assert_called()
        mock_file().write.assert_called()
