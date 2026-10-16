# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise initialization through real token-distributor relation events."""

import json
import os
import stat
from dataclasses import replace
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import ops
import pytest
import yaml
from charms.microcluster_token_distributor.v0 import token_distributor
from ops import testing

from charm import MicroovnCharm

TOKEN = "private-join-token"


def network(endpoint, address, interface="eth1"):
    """Include unrelated ingress addresses and secondary NICs to expose wrong selection."""
    return testing.Network(
        endpoint,
        bind_addresses=[
            testing.BindAddress([testing.Address(address)], interface_name=interface),
            testing.BindAddress([testing.Address("10.99.0.1")], interface_name="cilium0"),
        ],
        ingress_addresses=["198.51.100.90"],
        egress_subnets=["198.51.100.0/24"],
    )


def initialization_state(mode, cluster_address="10.10.0.2", data_address="10.20.0.2"):
    relation = testing.Relation(
        "cluster",
        remote_app_data={"bootstrap-app": "microovn"},
        remote_units_data={
            0: {"mirror": "up", **({"mirror-node": TOKEN} if mode == "join" else {})}
        },
    )
    return testing.State(
        leader=mode == "bootstrap",
        relations=[relation],
        networks=[network("cluster", cluster_address), network("data", data_address)],
    ), relation


def initialization_event(ctx, mode, relation):
    if mode == "bootstrap":
        return ctx.on.relation_joined(relation, remote_unit=0)
    return ctx.on.relation_changed(relation, remote_unit=0)


def in_cluster(state):
    stored = next(
        s for s in state.stored_states if s.owner_path == "MicroovnCharm/TokenConsumer[cluster]"
    )
    return stored.content["in_cluster"]


@pytest.fixture
def workload():
    seeds = []
    files = []

    def run(args, **kwargs):
        if args == ["microovn", "init"]:
            seed = kwargs["stdin"]
            assert stat.S_IMODE(os.fstat(seed.fileno()).st_mode) == 0o600
            files.append(seed)
            seeds.append(yaml.safe_load(seed))
            return CompletedProcess(args, 0, stdout="", stderr="")
        assert args[:2] == ["microovn", "cluster"]
        if args[2] == "list":
            return CompletedProcess(
                args, 0, stdout=json.dumps([{"name": "node", "role": "voter", "status": "ONLINE"}])
            )
        return CompletedProcess(args, 0, stdout="generated-token")

    with (
        patch("cluster.subprocess.run", side_effect=run) as command,
        patch.object(token_distributor, "get_hostname", return_value="node"),
        patch.object(MicroovnCharm, "_migrate_ovs") as migrate,
        patch.object(MicroovnCharm, "ovn_exporter_snap_client", MagicMock()) as exporter,
        patch("charm.microovn_central_exists", return_value=True),
        patch("charm.check_metrics_endpoint", return_value=True),
    ):
        yield command, seeds, files, migrate, exporter


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
@pytest.mark.parametrize(
    "cluster_address,data_address",
    [
        ("10.10.0.2", "10.20.0.2"),
        ("10.10.0.2", "10.10.0.2"),
        ("fd00:10::2", "fd00:20::2"),
        ("10.10.0.2", "fd00:20::2"),
        ("fd00:10::2", "10.20.0.2"),
    ],
)
def test_initialization_uses_local_bindings(workload, mode, cluster_address, data_address):
    command, seeds, files, migrate, exporter = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode, cluster_address, data_address)

    out = ctx.run(initialization_event(ctx, mode, relation), state)

    assert seeds == [
        {
            "mode": mode,
            "name": "node",
            "address": cluster_address,
            "custom_encapsulation_ip": data_address,
            "services": "auto",
            **({"token": TOKEN} if mode == "join" else {}),
        }
    ]
    assert all(f.closed for f in files)
    assert in_cluster(out)
    migrate.assert_called_once()
    exporter.enable_and_start.assert_called()
    assert not any(
        c.args[0][1:3] in (["cluster", "bootstrap"], ["cluster", "join"])
        for c in command.call_args_list
    )


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
@pytest.mark.parametrize("bound_endpoint", [None, "cluster", "data"])
def test_initialization_uses_default_network(workload, mode, bound_endpoint):
    """Unset endpoints keep Juju's default, including when only one is bound."""
    _, seeds, _, migrate, exporter = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode)
    state = replace(
        state,
        networks=[network(bound_endpoint, "10.10.0.2")] if bound_endpoint else [],
    )

    out = ctx.run(initialization_event(ctx, mode, relation), state)

    # Scenario supplies Juju's implicit default network for unset endpoints.
    default_address = testing.Network("cluster").bind_addresses[0].addresses[0].value
    assert seeds[0]["address"] == ("10.10.0.2" if bound_endpoint == "cluster" else default_address)
    assert seeds[0]["custom_encapsulation_ip"] == (
        "10.10.0.2" if bound_endpoint == "data" else default_address
    )
    assert in_cluster(out)
    assert not out.deferred
    migrate.assert_called_once()
    exporter.enable_and_start.assert_called()


def test_shared_cluster_uses_each_units_own_networks(workload):
    """Different NIC order and routed subnets must not reuse the bootstrapper's IP."""
    _, seeds, _, _, _ = workload
    for app, mode, cluster_address, data_address, interface in [
        ("microovn", "bootstrap", "10.10.0.2", "10.20.0.2", "eth1"),
        ("microovn", "join", "10.10.0.3", "10.20.0.3", "eno4"),
        ("other-microovn", "join", "10.11.0.2", "10.21.0.2", "bond0.200"),
    ]:
        ctx = testing.Context(MicroovnCharm, app_name=app)
        state, relation = initialization_state(mode, cluster_address, data_address)
        state = replace(
            state,
            networks=[
                network("cluster", cluster_address, interface="bond0.100"),
                network("data", data_address, interface=interface),
            ],
        )
        assert in_cluster(ctx.run(initialization_event(ctx, mode, relation), state))

    assert [s["address"] for s in seeds] == ["10.10.0.2", "10.10.0.3", "10.11.0.2"]
    assert [s["custom_encapsulation_ip"] for s in seeds] == ["10.20.0.2", "10.20.0.3", "10.21.0.2"]


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
@pytest.mark.parametrize(
    "first,second", [("10.10.0.2", "fd00:10::2"), ("fd00:10::2", "10.10.0.2")]
)
def test_dual_stack_respects_jujus_selected_address(workload, mode, first, second):
    """Do not override Juju's choice with our own IP-family or interface sorting."""
    _, seeds, _, _, _ = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode)
    state = replace(
        state,
        networks=[
            testing.Network(
                endpoint,
                bind_addresses=[
                    testing.BindAddress(
                        [testing.Address(first), testing.Address(second)], interface_name="bond0"
                    )
                ],
            )
            for endpoint in ("cluster", "data")
        ],
    )
    assert in_cluster(ctx.run(initialization_event(ctx, mode, relation), state))
    assert seeds[0]["address"] == first
    assert seeds[0]["custom_encapsulation_ip"] == first


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
@pytest.mark.parametrize("endpoint", ["cluster", "data"])
@pytest.mark.parametrize(
    "address",
    [
        None,
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "fe80::1",
        "fe80::1%eth1",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "not-an-ip",
    ],
)
def test_unusable_binding_blocks_before_migration(workload, mode, endpoint, address):
    command, _, _, migrate, exporter = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode)
    invalid = (
        network(endpoint, address) if address else testing.Network(endpoint, bind_addresses=[])
    )
    state = replace(
        state, networks=[n for n in state.networks if n.binding_name != endpoint] + [invalid]
    )

    out = ctx.run(initialization_event(ctx, mode, relation), state)

    assert isinstance(out.unit_status, ops.BlockedStatus)
    assert endpoint in out.unit_status.message
    assert out.deferred
    assert not in_cluster(out)
    migrate.assert_not_called()
    command.assert_not_called()
    exporter.enable_and_start.assert_not_called()
    # The charm's later status handler must not hide a binding failure.
    out = ctx.run(ctx.on.update_status(), out)
    assert isinstance(out.unit_status, ops.BlockedStatus)
    assert endpoint in out.unit_status.message


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
def test_missing_network_recovers_on_deferred_event(workload, mode):
    _, seeds, _, migrate, _ = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode)
    with patch.object(ops.Model, "get_binding", side_effect=ops.ModelError("network unavailable")):
        out = ctx.run(initialization_event(ctx, mode, relation), state)
    assert out.unit_status == ops.BlockedStatus("Cannot read cluster network binding")
    migrate.assert_not_called()

    out = ctx.run(ctx.on.update_status(), out)
    assert in_cluster(out)
    assert out.unit_status == ops.ActiveStatus()
    assert len(seeds) == 1


@pytest.mark.parametrize("mode", ["bootstrap", "join"])
def test_init_failure_is_retryable_and_redacts_token(workload, mode, caplog):
    command, seeds, files, _, exporter = workload
    successful_run = command.side_effect

    def fail(args, **kwargs):
        successful_run(args, **kwargs)
        return CompletedProcess(args, 1, stdout=TOKEN, stderr=f"Cannot initialize: {TOKEN}")

    command.side_effect = fail
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state(mode)
    out = ctx.run(initialization_event(ctx, mode, relation), state)

    assert out.unit_status == ops.BlockedStatus(f"MicroOVN {mode} failed; see debug-log")
    assert out.deferred
    assert not in_cluster(out)
    assert all(f.closed for f in files)
    exporter.enable_and_start.assert_not_called()
    if mode == "join":
        assert TOKEN not in caplog.text
    assert "Cannot initialize" in caplog.text

    out = ctx.run(ctx.on.update_status(), out)
    assert out.unit_status == ops.BlockedStatus(f"MicroOVN {mode} failed; see debug-log")
    assert not in_cluster(out)
    exporter.enable_and_start.assert_not_called()

    command.side_effect = successful_run
    out = ctx.run(ctx.on.update_status(), out)
    assert in_cluster(out)
    assert out.unit_status == ops.ActiveStatus()
    assert len(seeds) == 3


def test_init_execution_error_closes_preseed_and_defers(workload):
    command, _, files, _, exporter = workload
    successful_run = command.side_effect

    def fail(args, **kwargs):
        successful_run(args, **kwargs)
        raise FileNotFoundError("microovn")

    command.side_effect = fail
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state("join")
    out = ctx.run(initialization_event(ctx, "join", relation), state)
    assert out.unit_status == ops.BlockedStatus("Unable to run microovn init")
    assert not in_cluster(out)
    assert out.deferred
    assert all(f.closed for f in files)
    exporter.enable_and_start.assert_not_called()


def test_bindings_are_resolved_before_ovs_migration(workload):
    _, seeds, _, migrate, _ = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state("bootstrap")
    original_get_binding = ops.Model.get_binding
    with patch.object(ops.Model, "get_binding", autospec=True) as get_binding:
        get_binding.side_effect = original_get_binding

        def disrupt_network():
            get_binding.side_effect = ops.ModelError("OVS down")

        migrate.side_effect = disrupt_network
        out = ctx.run(ctx.on.relation_joined(relation, remote_unit=0), state)
    assert in_cluster(out)
    assert seeds[0]["address"] == "10.10.0.2"
    assert seeds[0]["custom_encapsulation_ip"] == "10.20.0.2"


def test_upgrade_preserves_library_state_and_does_not_reinitialize(workload):
    command, seeds, _, migrate, _ = workload
    ctx = testing.Context(MicroovnCharm)
    state, relation = initialization_state("join")
    # Seed the stored state using the original library as an older charm would.
    with patch("charm.TokenConsumer", token_distributor.TokenConsumer):
        with ctx(ctx.on.start(), state) as manager:
            manager.charm.token_consumer._stored.in_cluster = True
            manager.charm.unit.status = ops.ActiveStatus()
            state = manager.run()
    assert in_cluster(state)

    with patch.object(ops.Model, "get_binding", side_effect=AssertionError("Unexpected rebind")):
        state = ctx.run(ctx.on.upgrade_charm(), state)
        state = ctx.run(ctx.on.relation_changed(relation, remote_unit=0), state)
    assert in_cluster(state)
    assert not seeds
    migrate.assert_not_called()
    assert all(c.args[0][:2] == ["microovn", "cluster"] for c in command.call_args_list)
