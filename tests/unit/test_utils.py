# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the utilities in utils.py."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import RequestException

from utils import (
    call_microovn_command,
    check_metrics_endpoint,
    microovn_central_exists,
    wait_for_microovn_ready,
)


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run."""
    with patch("utils.subprocess.run") as mock_run:
        yield mock_run


@pytest.fixture
def mock_requests_get():
    """Mock requests.get."""
    with patch("utils.requests.get") as mock_get:
        yield mock_get


def test_call_microovn_command_success(mock_subprocess_run):
    """Test successful microovn command execution."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="output")
    res = call_microovn_command("status")

    mock_subprocess_run.assert_called_once_with(
        ["microovn", "status"],
        stdout=-1,
        stderr=-3,
        input=None,
        text=True,
    )
    assert res.returncode == 0
    assert res.stdout == "output"


def test_call_microovn_command_with_multiple_args(mock_subprocess_run):
    """Test microovn command with multiple arguments."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="cluster info")

    res = call_microovn_command("cluster", "list", "--format", "json")

    mock_subprocess_run.assert_called_once()
    call_args = mock_subprocess_run.call_args[0][0]
    assert call_args == ["microovn", "cluster", "list", "--format", "json"]
    assert res.returncode == 0
    assert res.stdout == "cluster info"


def test_call_microovn_command_with_stdin(mock_subprocess_run):
    """Test microovn command with stdin input."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="")

    res = call_microovn_command("certificates", "import", stdin="cert-data")

    mock_subprocess_run.assert_called_once()
    call_kwargs = mock_subprocess_run.call_args[1]
    assert call_kwargs["input"] == "cert-data"
    assert res.returncode == 0


def test_call_microovn_command_failure(mock_subprocess_run):
    """Test microovn command execution failure."""
    mock_subprocess_run.return_value = MagicMock(returncode=1, stderr="error message")

    res = call_microovn_command("invalid-command")

    assert res.returncode == 1
    assert res.stderr == "error message"


def test_call_microovn_command_no_args(mock_subprocess_run):
    """Test microovn command with no arguments."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="help")

    res = call_microovn_command()

    call_args = mock_subprocess_run.call_args[0][0]
    assert call_args == ["microovn"]
    assert res.returncode == 0


def test_wait_for_microovn_ready_success(mock_subprocess_run):
    """Test wait_for_microovn_ready when microovn is immediately ready."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="")

    result = wait_for_microovn_ready()

    assert result is True
    mock_subprocess_run.assert_called_once()


def test_wait_for_microovn_ready_failure(mock_subprocess_run):
    """Test wait_for_microovn_ready when retries are exhausted."""
    mock_subprocess_run.return_value = MagicMock(returncode=1, stdout="not ready")

    result = wait_for_microovn_ready()

    assert result is False
    assert mock_subprocess_run.call_count == 10


def test_check_metrics_endpoint_success():
    """Test successful metrics endpoint check."""
    url = "http://example.com/metrics"
    with patch("utils.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = check_metrics_endpoint(url)
        assert result is True


def test_check_metrics_endpoint_failure():
    """Test failed metrics endpoint check."""
    url = "http://example.com/metrics"
    with patch("utils.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = check_metrics_endpoint(url)
        assert result is False


def test_check_metrics_endpoint_exception():
    """Test metrics endpoint check with exception."""
    url = "http://example.com/metrics"
    with patch("utils.requests.get", side_effect=RequestException("Network error")):
        result = check_metrics_endpoint(url)
        assert result is False


def test_microovn_central_exists_success(mock_subprocess_run):
    """Test microovn_central_exists when central node exists."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="node1\ncentral\nnode2")

    result = microovn_central_exists()
    assert result is True


def test_microovn_central_exists_no_central(mock_subprocess_run):
    """Test microovn_central_exists when no central node exists."""
    mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="node1\nnode2")

    result = microovn_central_exists()
    assert result is False


def test_microovn_central_exists_failure(mock_subprocess_run):
    """Test microovn_central_exists when command fails."""
    mock_subprocess_run.return_value = MagicMock(returncode=1, stdout="error")

    with pytest.raises(subprocess.CalledProcessError):
        microovn_central_exists()
