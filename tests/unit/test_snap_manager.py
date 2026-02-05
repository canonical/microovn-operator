# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the SnapManager class."""

from unittest.mock import MagicMock, patch

import pytest
from charms.operator_libs_linux.v2 import snap

from snap_manager import SnapManager


@pytest.fixture
def mock_snap_cache():
    """Mock the snap.SnapCache."""
    with patch("snap_manager.snap.SnapCache") as mock_cache:
        yield mock_cache


@pytest.fixture
def mock_snap_add():
    """Mock the snap.add function."""
    with patch("snap_manager.snap.add") as mock_add:
        yield mock_add


@pytest.fixture
def mock_snap_remove():
    """Mock the snap.remove function."""
    with patch("snap_manager.snap.remove") as mock_remove:
        yield mock_remove


def test_install_success(mock_snap_cache, mock_snap_add):
    """Test successful snap installation."""
    mock_snap = MagicMock()
    mock_snap.present = True
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.install()

    mock_snap_add.assert_called_once_with("test-snap", channel="stable")
    assert result is True


def test_install_failure_snap_not_present(mock_snap_cache, mock_snap_add):
    """Test snap installation failure when snap is not present after installation."""
    mock_snap = MagicMock()
    mock_snap.present = False
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.install()

    assert result is False


def test_install_failure_snap_error(mock_snap_cache, mock_snap_add):
    """Test snap installation failure with SnapError exception."""
    mock_snap_add.side_effect = snap.SnapError("Installation failed")
    mock_snap_cache.return_value.__getitem__.return_value = MagicMock()

    client = SnapManager("test-snap", "stable")
    result = client.install()

    assert result is False


def test_remove_success(mock_snap_cache, mock_snap_remove):
    """Test successful snap removal."""
    mock_snap = MagicMock()
    mock_snap.present = False
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.remove()

    mock_snap_remove.assert_called_once()
    assert result is True


def test_remove_failure_snap_still_present(mock_snap_cache, mock_snap_remove):
    """Test snap removal failure when snap is still present after removal."""
    mock_snap = MagicMock()
    mock_snap.present = True
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.remove()

    assert result is False


def test_remove_failure_snap_error(mock_snap_cache, mock_snap_remove):
    """Test snap removal failure with SnapError exception."""
    mock_snap_remove.side_effect = snap.SnapError("Removal failed")
    mock_snap_cache.return_value.__getitem__.return_value = MagicMock()

    client = SnapManager("test-snap", "stable")
    result = client.remove()

    assert result is False


def test_connect_success_single_plug(mock_snap_cache):
    """Test successful connection of a single plug."""
    mock_snap = MagicMock()
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.connect([("network", None)])

    mock_snap.connect.assert_called_once_with("network", slot=None)
    assert result is True


def test_connect_success_multiple_plugs(mock_snap_cache):
    """Test successful connection of multiple plugs."""
    mock_snap = MagicMock()
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.connect(
        [("network", None), ("home", None), ("removable-media", "test-snap:removable-media")]
    )

    assert mock_snap.connect.call_count == 3
    mock_snap.connect.assert_any_call("network", slot=None)
    mock_snap.connect.assert_any_call("home", slot=None)
    mock_snap.connect.assert_any_call("removable-media", slot="test-snap:removable-media")
    assert result is True


def test_connect_failure_first_plug(mock_snap_cache):
    """Test plug connection failure on the first plug."""
    mock_snap = MagicMock()
    mock_snap.connect.side_effect = snap.SnapError("Connection failed")
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.connect([("network", None), ("home", None)])

    mock_snap.connect.assert_called_with("network", slot=None)
    assert result is False


def test_connect_failure_second_plug(mock_snap_cache):
    """Test plug connection failure on the second plug."""
    mock_snap = MagicMock()

    def connect_side_effect(plug, slot=None):
        if plug == "home":
            raise snap.SnapError("Connection failed")

    mock_snap.connect.side_effect = connect_side_effect
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.connect([("network", None), ("home", None)])

    assert mock_snap.connect.call_count == 6
    assert result is False


def test_enable_and_start(mock_snap_cache):
    """Test enabling and starting snap services."""
    mock_snap = MagicMock()
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    client.enable_and_start()

    mock_snap.start.assert_called_once_with(enable=True)


def test_enable_and_start_failure(mock_snap_cache):
    """Test enabling and starting snap services failure."""
    mock_snap = MagicMock()
    mock_snap.start.side_effect = snap.SnapError("Start failed")
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.enable_and_start()

    mock_snap.start.assert_called_once_with(enable=True)
    assert result is False


def test_disable_and_stop(mock_snap_cache):
    """Test disabling and stopping snap services."""
    mock_snap = MagicMock()
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    client.disable_and_stop()

    mock_snap.stop.assert_called_once_with(disable=True)


def test_disable_and_stop_failure(mock_snap_cache):
    """Test disabling and stopping snap services failure."""
    mock_snap = MagicMock()
    mock_snap.stop.side_effect = snap.SnapError("Stop failed")
    mock_snap_cache.return_value.__getitem__.return_value = mock_snap

    client = SnapManager("test-snap", "stable")
    result = client.disable_and_stop()

    mock_snap.stop.assert_called_once_with(disable=True)
    assert result is False
