from unittest.mock import MagicMock, mock_open, patch

import pytest
from generate_versions_file import (
    AnalysisItem,
    analysis_id,
    create_version_hash,
    dump_versions_file,
    generate_version_file,
    get_commit_hash,
    load_versions_file,
    update_version_history,
    update_version_item,
)


# Test fixtures
@pytest.fixture
def sample_analysis_spec():
    return {
        "AnalysisType": "rule",
        "RuleID": "Test.Rule",
        "Filename": "test_rule.py",
    }


@pytest.fixture
def sample_analysis_item(sample_analysis_spec):
    return AnalysisItem(
        _id="Test.Rule",
        type="rule",
        py="def rule(event): return True",
        analysis_spec=sample_analysis_spec,
        yamlFilePath="rules/test_rule.yml",
        pyFilePath="rules/test_rule.py",
        sha256=create_version_hash(
            sample_analysis_spec, "def rule(event): return True"
        ),
        version=1,
    )


@pytest.fixture
def sample_versions_file():
    return {
        "versions": {
            "Test.Rule": {
                "version": 1,
                "sha256": "abc123",
                "type": "rule",
                "history": {
                    1: {
                        "commit_hash": "def456",
                        "yamlFilePath": "rules/test_rule.yml",
                        "pyFilePath": "rules/test_rule.py",
                    }
                },
            }
        }
    }


# Test AnalysisItem and related functions
def test_analysis_id_rule(sample_analysis_spec):
    assert analysis_id(sample_analysis_spec) == "Test.Rule"


def test_analysis_id_policy():
    spec = {"AnalysisType": "policy", "PolicyID": "Test.Policy"}
    assert analysis_id(spec) == "Test.Policy"


def test_analysis_id_query():
    spec = {"AnalysisType": "query", "QueryName": "Test.Query"}
    assert analysis_id(spec) == "Test.Query"


def test_analysis_id_invalid():
    spec = {"AnalysisType": "invalid"}
    with pytest.raises(ValueError):
        analysis_id(spec)


def test_create_version_hash():
    spec = {"key": "value"}
    py_code = "def test(): pass"
    hash1 = create_version_hash(spec, py_code)
    hash2 = create_version_hash(spec, py_code)
    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 produces 64 character hex string


# Test version management functions
def test_update_version_item_new(sample_analysis_item):
    versions = {"versions": {}}
    update_version_item(versions, sample_analysis_item)

    assert sample_analysis_item._id in versions["versions"]
    assert versions["versions"][sample_analysis_item._id]["version"] == 1
    assert (
        versions["versions"][sample_analysis_item._id]["sha256"]
        == sample_analysis_item.sha256
    )
    assert (
        versions["versions"][sample_analysis_item._id]["type"]
        == sample_analysis_item.type
    )


def test_update_version_item_existing_same_hash(
    sample_analysis_item, sample_versions_file
):
    sample_versions_file["versions"][sample_analysis_item._id]["sha256"] = (
        sample_analysis_item.sha256
    )
    update_version_item(sample_versions_file, sample_analysis_item)

    assert sample_versions_file["versions"][sample_analysis_item._id]["version"] == 1


def test_update_version_item_existing_different_hash(
    sample_analysis_item, sample_versions_file
):
    update_version_item(sample_versions_file, sample_analysis_item)

    assert sample_versions_file["versions"][sample_analysis_item._id]["version"] == 2
    assert (
        sample_versions_file["versions"][sample_analysis_item._id]["sha256"]
        == sample_analysis_item.sha256
    )


def test_update_version_history(sample_analysis_item):
    versions = {"versions": {}}
    commit_hash = "test123"

    update_version_history(versions, sample_analysis_item, commit_hash)

    history = versions["versions"][sample_analysis_item._id]["history"]
    assert 1 in history
    assert history[1]["commit_hash"] == commit_hash
    assert history[1]["yamlFilePath"] == sample_analysis_item.yamlFilePath
    assert history[1]["pyFilePath"] == sample_analysis_item.pyFilePath


# Test file operations
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data="")
def test_load_versions_file_empty(mock_file, mock_exists):
    mock_exists.return_value = True
    result = load_versions_file()
    assert isinstance(result, dict)
    assert "versions" in result
    assert isinstance(result["versions"], dict)


@patch("os.path.exists")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="versions:\n  Test.Rule:\n    version: 1",
)
def test_load_versions_file_with_content(mock_file, mock_exists):
    mock_exists.return_value = True
    result = load_versions_file()
    assert isinstance(result, dict)
    assert "versions" in result
    assert "Test.Rule" in result["versions"]


@patch("builtins.open", new_callable=mock_open)
def test_dump_versions_file(mock_file):
    versions = {"versions": {"Test.Rule": {"version": 1}}}
    dump_versions_file(versions)
    mock_file.assert_called_once_with(".versions.yml", "w")
    mock_file().write.assert_called()


# Test get_commit_hash
@patch("subprocess.run")
def test_get_commit_hash_success(mock_run):
    mock_run.return_value = MagicMock(
        stdout=b"abc123\n",
        stderr=b"",
    )
    assert get_commit_hash() == "abc123"


@patch("subprocess.run")
def test_get_commit_hash_error(mock_run):
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
def test_generate_version_file_integration(mock_run, mock_file, mock_exists):
    mock_exists.return_value = True
    mock_run.return_value = MagicMock(stdout=b"test123\n", stderr=b"")

    with patch("generate_versions_file.load_analysis_items") as mock_load_items:
        mock_load_items.return_value = [
            AnalysisItem(
                _id="Test.Rule",
                type="rule",
                py="def rule(event): return True",
                analysis_spec={"AnalysisType": "rule", "RuleID": "Test.Rule"},
                yamlFilePath="rules/test_rule.yml",
                pyFilePath="rules/test_rule.py",
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
