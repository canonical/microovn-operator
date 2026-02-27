# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the MicroOVN charm."""

import json
from datetime import timedelta
from subprocess import CompletedProcess
from unittest.mock import ANY, MagicMock, patch

import ops
import pytest
from charms.microcluster_token_distributor.v0.token_distributor import TokenConsumer
from charms.tls_certificates_interface.v4.tls_certificates import (
    LIBID as TLS_CERTS_LIBID,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import testing

from charm import MicroovnCharm
from constants import (
    CERTIFICATES_RELATION,
    OVN_EXPORTER_METRICS_ENDPOINT,
    OVSDB_RELATION,
    OVSDBCMD_RELATION,
    WORKER_RELATION,
)
from snap_manager import SnapManager


@pytest.fixture()
def mock_logger():
    """Mock the charm logger."""
    with patch("charm.logger") as mock_logger:
        yield mock_logger


@pytest.fixture()
def mock_microovn_snap():
    """Mock the microovn snap client for charm tests."""
    mock_snap = MagicMock(spec=SnapManager)
    mock_snap.name = "microovn"
    with patch.object(MicroovnCharm, "microovn_snap_client", mock_snap):
        yield mock_snap


@pytest.fixture()
def mock_ovn_exporter_snap():
    """Mock the ovn-exporter snap client for charm tests."""
    mock_snap = MagicMock(spec=SnapManager)
    mock_snap.name = "ovn-exporter"
    with patch.object(MicroovnCharm, "ovn_exporter_snap_client", mock_snap):
        yield mock_snap


@pytest.fixture()
def mock_check_metrics_endpoint():
    """Mock check_metrics_endpoint function."""
    with patch("charm.check_metrics_endpoint") as mock:
        mock.return_value = True
        yield mock


@pytest.fixture()
def mock_call_microovn_command():
    """Mock call_microovn_command function."""
    with patch("charm.call_microovn_command") as mock:
        mock.return_value = CompletedProcess(args="", returncode=0, stderr="", stdout="")
        yield mock


@pytest.fixture()
def mock_microovn_central_exists():
    """Mock _microovn_central_exists method."""
    with patch("charm.microovn_central_exists") as mock:
        mock.return_value = True
        yield mock


@pytest.fixture()
def mock_wait_for_microovn_ready():
    """Mock wait_for_microovn_ready function."""
    with patch("charm.wait_for_microovn_ready") as mock:
        yield mock


def _generate_test_certificates():
    """Generate real test certificates for TLS testing."""
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        common_name="Test CA",
        validity=timedelta(days=365),
    )

    requirer_private_key = generate_private_key()
    csr = generate_csr(
        private_key=requirer_private_key,
        common_name="Charmed MicroOVN",
        add_unique_id_to_subject_name=True,
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=timedelta(days=365),
        is_ca=True,
    )

    return {
        "ca_private_key": ca_private_key,
        "ca_certificate": ca_certificate,
        "requirer_private_key": requirer_private_key,
        "csr": csr,
        "certificate": certificate,
    }


def test_on_install_success(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_wait_for_microovn_ready,
):
    """Test successful install event handling."""
    ctx = testing.Context(MicroovnCharm)
    ctx.run(ctx.on.install(), testing.State())

    mock_ovn_exporter_snap.install.assert_called_once()
    mock_microovn_snap.install.assert_called_once()
    mock_ovn_exporter_snap.connect.assert_called_once_with(
        [
            ("ovn-chassis", "microovn:ovn-chassis"),
            ("ovn-central-data", "microovn:ovn-central-data"),
        ]
    )
    mock_wait_for_microovn_ready.assert_called_once()


@pytest.mark.parametrize(
    "failing_snap",
    [
        "ovn-exporter",
        "microovn",
    ],
)
def test_on_install_snap_fails(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_wait_for_microovn_ready,
    failing_snap,
):
    """Test install event when snap installation fails."""
    if failing_snap == "ovn-exporter":
        mock_ovn_exporter_snap.install.return_value = False
    else:
        mock_microovn_snap.install.return_value = False

    ctx = testing.Context(MicroovnCharm)
    with pytest.raises(RuntimeError, match=f"Failed to install {failing_snap} snap"):
        ctx.run(ctx.on.install(), testing.State())


def test_on_install_connect_fails(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_wait_for_microovn_ready,
):
    """Test install event when snap interface connection fails."""
    mock_ovn_exporter_snap.connect.return_value = False

    ctx = testing.Context(MicroovnCharm)

    with pytest.raises(RuntimeError, match="Failed to connect ovn-exporter snap interfaces"):
        ctx.run(ctx.on.install(), testing.State())


def test_on_install_waitready_fails(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_wait_for_microovn_ready,
):
    """Test install event when microovn waitready fails."""
    mock_wait_for_microovn_ready.return_value = False

    ctx = testing.Context(MicroovnCharm)

    with pytest.raises(RuntimeError, match="microovn waitready failed after retries"):
        ctx.run(ctx.on.install(), testing.State())


def test_on_remove_success(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
):
    """Test successful remove event handling."""
    ctx = testing.Context(MicroovnCharm)
    ctx.run(ctx.on.remove(), testing.State())

    mock_ovn_exporter_snap.remove.assert_called_once()
    mock_microovn_snap.remove.assert_called_once()


@pytest.mark.parametrize(
    "failing_snap",
    [
        "ovn-exporter",
        "microovn",
    ],
)
def test_on_remove_snap_fails(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    failing_snap,
):
    """Test remove event when ovn-exporter removal fails."""
    if failing_snap == "ovn-exporter":
        mock_ovn_exporter_snap.remove.return_value = False
    else:
        mock_microovn_snap.remove.return_value = False

    ctx = testing.Context(MicroovnCharm)
    with pytest.raises(RuntimeError, match=f"Failed to remove {failing_snap} snap"):
        ctx.run(ctx.on.remove(), testing.State())


def test_on_update_status_active(
    mock_check_metrics_endpoint, mock_call_microovn_command, mock_microovn_central_exists
):
    """Test update_status sets ActiveStatus when all checks pass."""
    mock_check_metrics_endpoint.return_value = True
    mock_microovn_central_exists.return_value = True
    ovdvcms_relation = testing.Relation(endpoint=OVSDBCMD_RELATION)

    ctx = testing.Context(MicroovnCharm)
    with ctx(ctx.on.update_status(), testing.State(relations=[ovdvcms_relation])) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()


def test_on_update_status_metrics_unreachable(
    mock_check_metrics_endpoint, mock_microovn_central_exists
):
    """Test update_status sets BlockedStatus when metrics endpoint is unreachable."""
    mock_check_metrics_endpoint.return_value = False

    ctx = testing.Context(MicroovnCharm)
    with ctx(ctx.on.update_status(), testing.State()) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.BlockedStatus(
        "ovn-exporter metrics endpoint is not responding, check snap service status"
    )
    mock_check_metrics_endpoint.assert_called_with(OVN_EXPORTER_METRICS_ENDPOINT)


def test_on_update_status_no_central_nodes(
    mock_check_metrics_endpoint,
    mock_microovn_central_exists,
):
    """Test update_status sets BlockedStatus when no central nodes exist."""
    mock_microovn_central_exists.return_value = False

    ctx = testing.Context(MicroovnCharm)
    with ctx(ctx.on.update_status(), testing.State()) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.BlockedStatus(
        "microovn has no central nodes, this could either be due to a "
        "recently broken ovsdb-cms relation or a configuration issue"
    )


def test_on_update_status_with_ovsdb_relation(
    mock_check_metrics_endpoint, mock_call_microovn_command, mock_microovn_central_exists
):
    """Test update_status is active when ovsdb relation exists."""
    mock_check_metrics_endpoint.return_value = True

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    with ctx(ctx.on.update_status(), testing.State(relations=[ovsdb_relation])) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()


def test_on_ovsdbcms_broken(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """Test ovsdb-cms broken event handling."""
    mock_microovn_central_exists.return_value = False
    ovdvcms_relation = testing.Relation(endpoint=OVSDBCMD_RELATION)

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_broken(ovdvcms_relation), testing.State(relations=[ovdvcms_relation])
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_any_call("config", "delete", "ovn.central-ips")


def test_on_ovsdbcms_broken_delete_fails(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
    mock_logger,
):
    """Test ovsdb-cms broken event when config delete fails."""
    mock_call_microovn_command.return_value = CompletedProcess(
        args="", returncode=1, stderr="error"
    )
    mock_microovn_central_exists.return_value = False
    ovdvcms_relation = testing.Relation(endpoint=OVSDBCMD_RELATION)

    ctx = testing.Context(MicroovnCharm)
    with (
        ctx(
            ctx.on.relation_broken(ovdvcms_relation), testing.State(relations=[ovdvcms_relation])
        ) as manager,
    ):
        manager.charm.token_consumer._stored.in_cluster = True

    mock_logger.error.assert_any_call(
        "microovn config delete failed with error code %s, stderr: %s", 1, "error"
    )
    assert manager.charm.unit.status == ops.BlockedStatus(
        (
            "microovn has no central nodes, this could either be due to a "
            "recently broken ovsdb-cms relation or a configuration issue"
        )
    )


def test_on_ovsdbcms_ready(
    mock_check_metrics_endpoint,
    mock_microovn_central_exists,
    mock_call_microovn_command,
):
    """Test ovsdb-cms ready event handling."""
    mock_microovn_central_exists.return_value = True

    ctx = testing.Context(MicroovnCharm)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )
    ovsdb_relation = testing.Relation(OVSDB_RELATION)

    with ctx(
        ctx.on.relation_changed(ovsdb_cms_relation),
        testing.State(relations=[ovsdb_cms_relation, ovsdb_relation]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_called_with(
        "disable", "central", "--allow-disable-last-central"
    )
    assert manager.charm.unit.status == ops.ActiveStatus()


@patch("charm.TokenConsumer.add_to_mirror")
def test_on_certificates_available_success(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_logger,
):
    """Test certificates available event with valid certificate."""
    ctx = testing.Context(MicroovnCharm)

    certs = _generate_test_certificates()
    provider_app_data = {
        "certificates": json.dumps(
            [
                {
                    "ca": str(certs["ca_certificate"]),
                    "certificate_signing_request": str(certs["csr"]),
                    "certificate": str(certs["certificate"]),
                    "chain": [str(certs["certificate"]), str(certs["ca_certificate"])],
                    "revoked": False,
                }
            ]
        )
    }
    requirer_app_data = {
        "certificate_signing_requests": json.dumps(
            [
                {
                    "certificate_signing_request": str(certs["csr"]),
                    "ca": True,
                }
            ]
        )
    }
    private_key_secret = testing.Secret(
        tracked_content={"private-key": str(certs["requirer_private_key"])},
        label=f"{TLS_CERTS_LIBID}-private-key-{CERTIFICATES_RELATION}",
    )

    certs_relation = testing.Relation(
        endpoint=CERTIFICATES_RELATION,
        remote_app_data=provider_app_data,
        local_app_data=requirer_app_data,
    )
    state = testing.State(
        relations=[certs_relation],
        secrets=[private_key_secret],
        leader=True,
    )
    mock_call_microovn_command.return_value = CompletedProcess(
        args="", returncode=0, stdout="New CA certificate: Issued"
    )

    ctx = testing.Context(MicroovnCharm)
    with (
        ctx(ctx.on.relation_changed(certs_relation), state) as manager,
    ):
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_called_with(
        "certificates", "set-ca", "--combined", stdin=ANY
    )
    mock_logger.info.assert_any_call("CA certificate updated, new certificates issued")


def test_on_certificates_available_defers_when_not_in_cluster(
    mock_check_metrics_endpoint,
):
    """Test certificates available event defers when not in cluster."""
    ctx = testing.Context(MicroovnCharm)
    certs_relation = testing.Relation(CERTIFICATES_RELATION)

    with ctx(ctx.on.start(), testing.State(relations=[certs_relation])) as manager:
        mock_event = MagicMock()
        manager.charm._on_certificates_available(mock_event)

        mock_event.defer.assert_called_once()


def test_on_certificates_available_no_cert(
    mock_check_metrics_endpoint, mock_call_microovn_command
):
    """Test certificates available when no certificate is available."""
    ctx = testing.Context(MicroovnCharm)
    with (
        ctx(ctx.on.start(), testing.State()) as manager,
        patch.object(manager.charm.certificates, "get_assigned_certificate") as mock_get_cert,
    ):
        mock_get_cert.return_value = (None, None)
        manager.charm.token_consumer._stored.in_cluster = True
        manager.charm._on_certificates_available(MagicMock())

    mock_call_microovn_command.assert_not_called()


def test_on_certificates_available_not_issued(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_logger,
):
    """Test certificates available event when certificate is not issued."""
    mock_call_microovn_command.return_value = CompletedProcess(
        "", returncode=0, stdout="Certificate not issued"
    )

    ctx = testing.Context(MicroovnCharm)
    with (
        ctx(ctx.on.start(), testing.State()) as manager,
        patch.object(manager.charm.certificates, "get_assigned_certificate") as mock_get_cert,
    ):
        provider_cert = MagicMock()
        provider_cert.certificate = "test-cert"
        provider_cert.ca = "test-ca"
        mock_get_cert.return_value = (provider_cert, "test-key")
        manager.charm.token_consumer._stored.in_cluster = True
        manager.charm._on_certificates_available(MagicMock())

    mock_call_microovn_command.assert_called_with(
        "certificates", "set-ca", "--combined", stdin=ANY
    )
    mock_logger.info.assert_not_called()


def test_on_certificates_available_command_fails(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test certificates available event when command fails."""
    mock_call_microovn_command.return_value = CompletedProcess("", returncode=1, stderr="error")

    ctx = testing.Context(MicroovnCharm)
    with (
        ctx(ctx.on.start(), testing.State()) as manager,
        patch.object(manager.charm.certificates, "get_assigned_certificate") as mock_get_cert,
        pytest.raises(RuntimeError, match="Updating certificates failed with error code 1"),
    ):
        provider_cert = MagicMock()
        provider_cert.certificate = "test-cert"
        provider_cert.ca = "test-ca"
        mock_get_cert.return_value = (provider_cert, "test-key")

        manager.charm.token_consumer._stored.in_cluster = True
        manager.charm._on_certificates_available(MagicMock())


@patch("subprocess.run")
@patch.object(MicroovnCharm, "_dataplane_mode", return_value=True)
def test_on_cluster_changed_in_cluster_with_ovsdb(
    mock_dataplane_mode,
    mock_subprocess_run,
    mock_check_metrics_endpoint,
):
    """Test cluster changed event when in cluster with ovsdb relation."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )
    cluster_relation = testing.Relation(WORKER_RELATION)

    with ctx(
        ctx.on.relation_changed(cluster_relation),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation, cluster_relation]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()


def test_on_cluster_changed_not_in_cluster(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test cluster changed event when not in cluster."""
    ctx = testing.Context(MicroovnCharm)
    cluster_relation = testing.Relation(WORKER_RELATION)

    with ctx(
        ctx.on.relation_changed(cluster_relation),
        testing.State(relations=[cluster_relation]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = False

    mock_call_microovn_command.assert_not_called()
    assert manager.charm.unit.status == ops.BlockedStatus(
        "Not in cluster. Waiting for token distrbutor relation"
    )


def test_dataplane_mode_success(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test successful dataplane mode switch."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(
        ctx.on.start(),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=True),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is True
    mock_call_microovn_command.assert_any_call(
        "disable", "central", "--allow-disable-last-central"
    )


def test_dataplane_mode_not_in_cluster(
    mock_check_metrics_endpoint,
):
    """Test dataplane mode returns False when not in cluster."""
    ctx = testing.Context(MicroovnCharm)
    with ctx(ctx.on.start(), testing.State()) as manager:
        manager.charm.token_consumer._stored.in_cluster = False
        result = manager.charm._dataplane_mode()

    assert result is True


def test_dataplane_mode_no_ovsdb_relation(
    mock_check_metrics_endpoint,
):
    """Test dataplane mode returns False when no ovsdb relation."""
    ctx = testing.Context(MicroovnCharm)
    with ctx(ctx.on.start(), testing.State()) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is True


def test_dataplane_mode_disable_central_fails_already_disabled(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test dataplane mode when central is already disabled."""
    mock_call_microovn_command.side_effect = [
        CompletedProcess(
            "",
            returncode=1,
            stdout="this service is not enabled",
        ),
        CompletedProcess("", returncode=0, stdout=""),
    ]

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(
        ctx.on.start(),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=True),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is True


def test_dataplane_mode_disable_central_fails_other_error(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test dataplane mode when disable central fails with other error."""
    mock_call_microovn_command.side_effect = [
        CompletedProcess("", returncode=1, stderr="some other error", stdout=""),
        CompletedProcess("", returncode=0, stdout=""),
    ]

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with (
        ctx(
            ctx.on.start(),
            testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=True),
        ) as manager,
        pytest.raises(RuntimeError, match="Disabling central failed with error code 1"),
    ):
        manager.charm.token_consumer._stored.in_cluster = True
        manager.charm._dataplane_mode()


def test_dataplane_mode_not_leader(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test dataplane mode when not leader."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(
        ctx.on.start(),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=False),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is True
    mock_call_microovn_command.assert_called_once_with(
        "disable", "central", "--allow-disable-last-central"
    )


def test_dataplane_mode_set_central_ips_fails(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test dataplane mode when set_central_ips_config fails."""
    mock_call_microovn_command.side_effect = [
        CompletedProcess("", returncode=0, stdout=""),
        CompletedProcess("", returncode=1, stderr="error"),
    ]

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(
        ctx.on.start(),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=True),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is False


def test_dataplane_mode_remote_not_ready(
    mock_check_metrics_endpoint,
):
    """Test dataplane mode returns False when remote is not ready."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    # No loadbalancer-address means remote is not ready
    ovsdb_cms_relation = testing.Relation(OVSDBCMD_RELATION, remote_app_data={})

    with ctx(
        ctx.on.start(),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        result = manager.charm._dataplane_mode()

    assert result is True


def test_set_central_ips_config_success(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test successful set central IPs config."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(ctx.on.start(), testing.State(relations=[ovsdb_cms_relation])) as manager:
        result = manager.charm._set_central_ips_config()

    assert result is True
    mock_call_microovn_command.assert_called_with(
        "config", "set", "ovn.central-ips", "192.168.0.16"
    )


def test_set_central_ips_config_fails(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
):
    """Test set central IPs config when command fails."""
    mock_call_microovn_command.return_value = CompletedProcess("", returncode=1, stderr="error")

    ctx = testing.Context(MicroovnCharm)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(ctx.on.start(), testing.State(relations=[ovsdb_cms_relation])) as manager:
        result = manager.charm._set_central_ips_config()

    assert result is False


def test_set_central_ips_config_no_address(
    mock_check_metrics_endpoint,
):
    """Test set central IPs config when no loadbalancer address."""
    ctx = testing.Context(MicroovnCharm)
    ovsdb_cms_relation = testing.Relation(OVSDBCMD_RELATION, remote_app_data={})

    with ctx(ctx.on.start(), testing.State(relations=[ovsdb_cms_relation])) as manager:
        result = manager.charm._set_central_ips_config()

    assert result is False


def test_on_ovsdbcms_ready_dataplane_mode_fails(
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_logger,
):
    """Test ovsdb-cms ready event when dataplane mode fails."""
    mock_call_microovn_command.side_effect = [
        CompletedProcess("", returncode=0, stdout=""),
        CompletedProcess("", returncode=1, stderr="error"),
    ]

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )

    with ctx(
        ctx.on.relation_changed(ovsdb_cms_relation),
        testing.State(relations=[ovsdb_relation, ovsdb_cms_relation], leader=True),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_logger.error.assert_any_call("Failed to switch to dataplane mode on ovsdb-cms ready")
    assert manager.charm.unit.status == ops.BlockedStatus("Failed to switch to dataplane mode")


@patch("subprocess.run")
@patch("builtins.open")
def test_on_cluster_changed_dataplane_mode_fails(
    mock_open,
    mock_subprocess_run,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_logger,
):
    """Test cluster changed event when dataplane mode fails."""
    mock_call_microovn_command.side_effect = [
        CompletedProcess("", returncode=0, stdout=""),
        CompletedProcess("", returncode=1, stderr="error"),
    ]

    ctx = testing.Context(MicroovnCharm)
    ovsdb_relation = testing.Relation(OVSDB_RELATION)
    ovsdb_cms_relation = testing.Relation(
        OVSDBCMD_RELATION,
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )
    cluster_relation = testing.Relation(WORKER_RELATION)

    with ctx(
        ctx.on.relation_changed(cluster_relation),
        testing.State(
            relations=[ovsdb_relation, ovsdb_cms_relation, cluster_relation], leader=True
        ),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_logger.error.assert_any_call("Failed to switch to dataplane mode on cluster changed")
    assert manager.charm.unit.status == ops.BlockedStatus("Failed to switch to dataplane mode")


def test_on_bootstrapped(
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_logger,
):
    """Test bootstrapped event enables and starts ovn-exporter."""
    ctx = testing.Context(MicroovnCharm)
    cluster_relation = testing.Relation(WORKER_RELATION)

    with patch("charm.COSAgentProvider"):
        ctx.run(
            ctx.on.custom(TokenConsumer.on.bootstrapped),  # pyright: ignore
            testing.State(relations=[cluster_relation]),
        )

    mock_ovn_exporter_snap.enable_and_start.assert_called_once()
    mock_logger.info.assert_any_call(
        "microovn cluster was bootstrapped or joined, enabling the exporter"
    )
