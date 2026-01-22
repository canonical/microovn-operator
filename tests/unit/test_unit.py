#!/usr/bin/env python3

import subprocess
from unittest.mock import MagicMock, patch

import charm
import charms.tls_certificates_interface.v4.tls_certificates as tls_certs
import ops
import pytest
from ops import testing


@patch.object(charm.subprocess, "run")
def test_call_microovn_command(mock_run):
    charm.call_microovn_command("status")
    args, kwargs = mock_run.call_args
    assert args[0] == ["microovn", "status"]

    addresses = ["192.168.0.16", "8.8.8.8", "4.13.6.12"]
    charm.call_microovn_command("config", "set", "ovn.central-ips", ",".join(addresses))
    args, kwargs = mock_run.call_args
    assert args[0] == [
        "microovn",
        "config",
        "set",
        "ovn.central-ips",
        "192.168.0.16,8.8.8.8,4.13.6.12",
    ]


@patch.object(charm.subprocess, "run")
def test_install(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
    ctx = testing.Context(charm.MicroovnCharm)
    state_in = testing.State()
    ctx.run(ctx.on.install(), state_in)
    mock_run.assert_any_call(["snap", "wait", "system", "seed.loaded"], check=True)
    mock_run.assert_any_call(
        ["snap", "install", "microovn", "--channel", "latest/edge"], check=True
    )
    mock_run.assert_any_call(
        ["snap", "install", "ovn-exporter", "--channel", "latest/stable"], check=True
    )
    mock_run.assert_any_call(
        ["microovn", "waitready"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        input=None,
        text=True,
    )


@patch.object(charm.logger, "error")
@patch.object(charm.logger, "debug")
@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("in_cluster", [True, False])
@pytest.mark.parametrize("return_code", [0, 1])
@pytest.mark.parametrize("services", ["central, switch, chassis", "switch, chassis"])
def test_central_exists(
    mock_check_metrics_endpoint,
    microovn_command,
    logger_debug,
    logger_error,
    in_cluster,
    return_code,
    services,
):
    status_output = """
MicroOVN deployment summary:
- a (10.155.18.254)
    Services: {0}
OVN Database summary:
OVN Northbound: OK (7.3.0)
OVN Southbound: OK (20.33.0)
"""
    command_out = status_output.format(services)
    microovn_command.return_value = (return_code, command_out)

    ctx = testing.Context(charm.MicroovnCharm)
    with ctx(ctx.on.start(), testing.State()) as manager:
        manager.charm.token_consumer._stored.in_cluster = in_cluster
        try:
            output = manager.charm._microovn_central_exists()
            assert output is (in_cluster and "central" in services)
        except RuntimeError as e:
            assert in_cluster
            assert return_code != 0
            assert str(e) == "microovn status failed with error code 1 and stdout {0}".format(
                command_out
            )
        if in_cluster:
            microovn_command.assert_called_once_with("status")
        else:
            microovn_command.assert_not_called()


@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("leader", [True, False])
def test_dataplane_mode_passes(mock_check, microovn_command, leader):
    ctx = testing.Context(charm.MicroovnCharm)
    ovsdb_relation = testing.Relation(
        "ovsdb-external",
        "ovsdb-cms",
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )
    microovn_command.return_value = (0, "")
    with (
        ctx(ctx.on.start(), testing.State(relations=[ovsdb_relation], leader=leader)) as manager,
        patch.object(manager.charm, "_set_central_ips_config") as set_central_ips_config,
    ):
        set_central_ips_config.return_value = True
        manager.charm.token_consumer._stored.in_cluster = True
        assert manager.charm._dataplane_mode()
        assert manager.charm.ovsdbcms_requires.bound_addresses()
        microovn_command.assert_called_once_with(
            "disable", "central", "--allow-disable-last-central"
        )
        if leader:
            set_central_ips_config.assert_called_once()
        else:
            set_central_ips_config.assert_not_called()


@patch.object(charm.logger, "error")
@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("return_code", [0, 1])
def test_set_central_ips_config(mock_check, microovn_command, logger_error, return_code):
    ctx = testing.Context(charm.MicroovnCharm)
    ovsdb_relation = testing.Relation(
        "ovsdb-external",
        "ovsdb-cms",
        remote_app_data={"loadbalancer-address": "192.168.0.16"},
    )
    microovn_command.return_value = (return_code, "")
    with ctx(ctx.on.start(), testing.State(relations=[ovsdb_relation])) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        assert manager.charm._set_central_ips_config() == (not return_code)
        assert manager.charm.ovsdbcms_requires.bound_addresses()
        microovn_command.assert_called_once_with(
            "config", "set", "ovn.central-ips", "192.168.0.16"
        )
        if return_code == 0:
            logger_error.assert_not_called()
        else:
            logger_error.assert_called_once_with("calling config set failed with code 1")


@patch.object(charm.logger, "error")
@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("microovn_command_return_code", [0, 1])
def test_on_ovsdbcms_broken_passes(
    mock_check, microovn_command, logger_error, microovn_command_return_code
):
    ctx = testing.Context(charm.MicroovnCharm)
    microovn_command.return_value = (microovn_command_return_code, "")
    with (
        ctx(ctx.on.start(), testing.State()) as manager,
        patch.object(manager.charm, "_microovn_central_exists") as central_exists,
    ):
        manager.charm.token_consumer._stored.in_cluster = True
        central_exists.return_value = False
        manager.charm._on_ovsdbcms_broken(None)  # type: ignore
        microovn_command.assert_called_once_with("config", "delete", "ovn.central-ips")
        expected_status = ops.BlockedStatus(
            "microovn has no central nodes, this could either be due to a "
            + "recently broken ovsdb-cms relation or a configuration issue"
        )
        assert manager.charm.unit.status == expected_status
        if microovn_command_return_code == 0:
            logger_error.assert_not_called()
        else:
            logger_error.assert_called_once_with("microovn config delete failed with error code 1")


@patch.object(charm.logger, "error")
@patch.object(charm.logger, "debug")
@patch.object(charm.logger, "info")
@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("find_cert", [True, False])
@pytest.mark.parametrize("find_key", [True, False])
@pytest.mark.parametrize("microovn_command_return_code", [0, 1])
@pytest.mark.parametrize(
    "microovn_command_output", ["New CA certificate: Issued", "New CA certificate: Not Issued"]
)
def test_on_certs_available(
    mock_check,
    microovn_command,
    logger_info,
    logger_debug,
    logger_error,
    find_cert,
    find_key,
    microovn_command_return_code,
    microovn_command_output,
):
    """Test the _on_certificates_available command in microovn.

    Ensures _on_certificates_available responds as expected given all possible
    conditions and ensures it is logging and erroring correctly
    """
    fake_ca = "ca cert 413"
    fake_given_cert = "given cert 612"
    fake_priv_key = "priv key 1111"
    ctx = testing.Context(charm.MicroovnCharm)
    with (
        ctx(ctx.on.start(), testing.State()) as manager,
        patch.object(manager.charm.certificates, "get_assigned_certificate") as get_certs,
    ):
        priv_key = None
        provider_cert = None
        if find_cert:
            provider_cert = MagicMock(spec=tls_certs.ProviderCertificate)
            provider_cert.ca = fake_ca
            provider_cert.certificate = fake_given_cert
        if find_key:
            priv_key = MagicMock(spec=tls_certs.PrivateKey)
            priv_key.__str__ = MagicMock(return_value=fake_priv_key)
        get_certs.return_value = (provider_cert, priv_key)
        microovn_command.return_value = (microovn_command_return_code, microovn_command_output)
        manager.charm.token_consumer._stored.in_cluster = True

        try:
            manager.charm._on_certificates_available(None)  # type: ignore
            if not (find_cert and find_key):
                logger_info.assert_not_called()
                logger_debug.assert_called_once_with("Certificate or private key is not available")
                logger_error.assert_not_called()
            else:
                assert microovn_command_return_code == 0
                if microovn_command_output == "New CA certificate: Issued":
                    logger_info.assert_called_once_with(
                        "CA certificate updated, new certificates issued"
                    )
                    logger_debug.assert_not_called()
                    logger_error.assert_not_called()
                else:
                    logger_info.assert_not_called()
                    logger_debug.assert_not_called()
                    logger_error.assert_not_called()
        except RuntimeError as e:
            assert (find_cert and find_key) and (microovn_command_return_code == 1)
            logger_info.assert_not_called()
            logger_debug.assert_not_called()
            logger_error.assert_called_once_with(
                "microovn certificates set-ca failed with error code 1"
            )
            assert str(e) == "Updating certificates failed with error code 1"

        get_certs.assert_called_once_with(certificate_request=charm.CSR_ATTRIBUTES)
        if find_cert and find_key:
            microovn_command.assert_called_once_with(
                "certificates",
                "set-ca",
                "--combined",
                stdin="\n".join([fake_given_cert, fake_ca, fake_priv_key]),
            )


@patch.object(charm, "call_microovn_command")
@patch.object(charm, "check_metrics_endpoint")
@pytest.mark.parametrize("metrics_reachable", [True, False])
def test_update_status_check_metrics_endpoint(
    mock_check_metrics_endpoint,
    mock_microovn_command,
    metrics_reachable,
):
    """Test _update_status checks metrics endpoint and sets appropriate status."""
    mock_check_metrics_endpoint.return_value = metrics_reachable
    mock_microovn_command.return_value = (0, "central, switch, chassis")

    ctx = testing.Context(charm.MicroovnCharm)
    state_in = testing.State()

    with ctx(ctx.on.start(), state_in) as manager:
        manager.charm.token_consumer._stored.in_cluster = False
        manager.charm._update_status(None)  # type: ignore

    expected_url = f"http://localhost:{charm.OVN_EXPORTER_PORT}{charm.OVN_EXPORTER_METRICS_PATH}"
    mock_check_metrics_endpoint.assert_called_once_with(expected_url)

    if metrics_reachable:
        assert manager.charm.unit.status == ops.ActiveStatus()
    else:
        assert manager.charm.unit.status == ops.BlockedStatus(
            "ovn-exporter metrics endpoint is not reachable"
        )
