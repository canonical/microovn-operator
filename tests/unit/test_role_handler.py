# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the RoleHandler."""

import json
from dataclasses import dataclass
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import ops
import pytest
from charms.role_distributor.v0.role_assignment import AssignmentStatus
from ops import testing

from charm import MicroovnCharm
from constants import (
    OVSDBCMD_RELATION,
    ROLE_ASSIGNMENT_RELATION,
)
from snap_manager import SnapManager


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
    """Mock call_microovn_command function in role_handler module."""
    with patch("role_handler.call_microovn_command") as mock:
        mock.return_value = CompletedProcess(args="", returncode=0, stderr="", stdout="")
        yield mock


@pytest.fixture()
def mock_subprocess_run():
    """Mock subprocess.run in role_handler module (used for ovs-vsctl gateway commands)."""
    with patch("role_handler.subprocess.run") as mock:
        mock.return_value = CompletedProcess(args="", returncode=0, stderr="", stdout="")
        yield mock


@pytest.fixture()
def mock_microovn_central_exists():
    """Mock microovn_central_exists method."""
    with patch("charm.microovn_central_exists") as mock:
        mock.return_value = True
        yield mock


def _make_role_assignment_relation(
    status: AssignmentStatus | str,
    roles: list[str] | None = None,
    message: str | None = None,
    workload_params: dict | None = None,
    unit_name: str = "microovn/0",
) -> testing.Relation:
    """Build a testing.Relation with Provider App databag for role-assignment."""
    assignment: dict = {"status": str(status)}
    if roles is not None:
        assignment["roles"] = roles
    if message is not None:
        assignment["message"] = message
    if workload_params is not None:
        assignment["workload-params"] = workload_params
    remote_app_data = {"assignments": json.dumps({unit_name: assignment})}
    return testing.Relation(
        endpoint=ROLE_ASSIGNMENT_RELATION,
        remote_app_data=remote_app_data,
    )


@dataclass(frozen=True)
class RoleMatrixCase:
    """Expected outcome for a role-assignment combination."""

    roles: tuple[str, ...]
    ovsdb_remote_app_data: dict[str, str] | None = None
    blocked_message_substring: str | None = None
    required_microovn_calls: tuple[tuple[str, ...], ...] = ()
    forbidden_microovn_calls: tuple[tuple[str, ...], ...] = ()
    expect_gateway_write: bool = False


def _make_ovsdb_external_relation(remote_app_data: dict[str, str]) -> testing.Relation:
    """Build an ovsdb-external relation for local or dataplane-only mode."""
    return testing.Relation(endpoint=OVSDBCMD_RELATION, remote_app_data=remote_app_data)


def _assert_role_matrix_case(
    manager,
    case: RoleMatrixCase,
    mock_call_microovn_command,
    mock_subprocess_run,
) -> None:
    """Assert status and workload mutations for a role matrix case."""
    if case.blocked_message_substring is None:
        assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)
    else:
        assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
        assert case.blocked_message_substring in manager.charm.unit.status.message.lower()

    calls = [call.args for call in mock_call_microovn_command.call_args_list]
    for expected in case.required_microovn_calls:
        assert expected in calls
    for forbidden in case.forbidden_microovn_calls:
        assert forbidden not in calls

    gateway_write_calls = [
        call
        for call in mock_subprocess_run.call_args_list
        if "set" in str(call) or "remove" in str(call)
    ]
    if case.expect_gateway_write:
        assert gateway_write_calls
        assert any("enable-chassis-as-gw" in str(call) for call in gateway_write_calls)
    else:
        assert not gateway_write_calls


LOCAL_ROLE_CASES = (
    pytest.param(
        RoleMatrixCase(
            roles=("chassis",),
            required_microovn_calls=(("enable", "chassis"), ("disable", "central")),
            forbidden_microovn_calls=(("disable", "central", "--allow-disable-last-central"),),
        ),
        id="chassis",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("central", "chassis"),
            required_microovn_calls=(("enable", "chassis"), ("enable", "central")),
        ),
        id="central-chassis",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("gateway",),
            blocked_message_substring="chassis",
        ),
        id="gateway-blocked",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("central", "gateway"),
            blocked_message_substring="chassis",
        ),
        id="central-gateway-blocked",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("central", "chassis"),
            ovsdb_remote_app_data={},
            required_microovn_calls=(("enable", "chassis"), ("enable", "central")),
        ),
        id="central-chassis-unready-ovsdb",
    ),
)

DATAPLANE_ROLE_CASES = (
    pytest.param(
        RoleMatrixCase(
            roles=("chassis",),
            ovsdb_remote_app_data={"loadbalancer-address": "192.168.0.16"},
            required_microovn_calls=(
                ("enable", "chassis"),
                ("disable", "central", "--allow-disable-last-central"),
            ),
        ),
        id="chassis",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("chassis", "gateway"),
            ovsdb_remote_app_data={"loadbalancer-address": "192.168.0.16"},
            required_microovn_calls=(
                ("enable", "chassis"),
                ("disable", "central", "--allow-disable-last-central"),
            ),
            expect_gateway_write=True,
        ),
        id="chassis-gateway",
    ),
    pytest.param(
        RoleMatrixCase(
            roles=("central", "chassis"),
            ovsdb_remote_app_data={"loadbalancer-address": "192.168.0.16"},
            blocked_message_substring="dataplane-only",
        ),
        id="central-chassis-blocked",
    ),
)


# --- Role matrix tests ---


@pytest.mark.parametrize("case", LOCAL_ROLE_CASES)
def test_role_matrix_local(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    case,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Role combinations in local mode should enforce the expected invariants."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=list(case.roles))
    relations = [role_rel]
    if case.ovsdb_remote_app_data is not None:
        relations.append(_make_ovsdb_external_relation(case.ovsdb_remote_app_data))

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=relations),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    _assert_role_matrix_case(manager, case, mock_call_microovn_command, mock_subprocess_run)


@pytest.mark.parametrize("case", DATAPLANE_ROLE_CASES)
def test_role_matrix_dataplane_only(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    case,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Role combinations in dataplane-only mode should enforce the expected invariants."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=list(case.roles))
    ovsdb_ext_rel = _make_ovsdb_external_relation(case.ovsdb_remote_app_data or {})

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel, ovsdb_ext_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    _assert_role_matrix_case(manager, case, mock_call_microovn_command, mock_subprocess_run)


def test_not_in_cluster_defers(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """When not in cluster, event should be deferred and no commands run."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.start(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = False
        mock_event = MagicMock()
        mock_event.status = AssignmentStatus.ASSIGNED
        mock_event.roles = ("central", "chassis")
        manager.charm.role_handler.apply(mock_event)

        mock_event.defer.assert_called_once()

    mock_call_microovn_command.assert_not_called()


# --- Status handling tests ---


def test_pending_status_sets_waiting(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """Pending status should result in WaitingStatus and no commands."""
    role_rel = _make_role_assignment_relation(status="pending")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.WaitingStatus)
    mock_call_microovn_command.assert_not_called()


def test_error_status_sets_blocked(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """Error status should result in BlockedStatus with provider message."""
    role_rel = _make_role_assignment_relation(status="error", message="insufficient resources")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "insufficient resources" in manager.charm.unit.status.message
    mock_call_microovn_command.assert_not_called()


def test_no_assignment_for_this_unit_is_noop(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """Assignment for a different unit should result in no action."""
    role_rel = _make_role_assignment_relation(
        status="assigned",
        roles=["central", "chassis"],
        unit_name="microovn/99",
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_not_called()


def test_assignment_with_workload_params_still_applies_roles(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Assigned workload_params should not change role enforcement semantics."""
    role_rel = _make_role_assignment_relation(
        status="assigned",
        roles=["central", "chassis"],
        workload_params={"bridge-mapping": "physnet1:br-ex"},
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_any_call("enable", "chassis")
    mock_call_microovn_command.assert_any_call("enable", "central")
    gateway_write_calls = [
        call
        for call in mock_subprocess_run.call_args_list
        if "set" in str(call) or "remove" in str(call)
    ]
    assert not gateway_write_calls


def test_missing_assignment_entry_does_not_clear_cached_roles(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """A missing unit entry is not treated like a revoke by the stateless library."""
    role_rel = _make_role_assignment_relation(
        status="assigned",
        roles=["central", "chassis"],
        unit_name="microovn/99",
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.start(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        manager.charm.role_handler._save_applied_roles({"central", "chassis"})

        manager.charm.role_handler.enforce_roles()

        assert manager.charm.role_handler._get_applied_roles() == {"central", "chassis"}

    mock_call_microovn_command.assert_not_called()


def test_unknown_status_treated_as_pending(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """Unknown status should be treated as pending (WaitingStatus)."""
    role_rel = _make_role_assignment_relation(status="some-future-status")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.WaitingStatus)
    mock_call_microovn_command.assert_not_called()


# --- Role application tests ---


def test_disabling_last_central_outside_dataplane_only_blocks(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Local central removal must not use the destructive disable flag."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["chassis"])
    mock_call_microovn_command.side_effect = lambda *args: (
        CompletedProcess(args=args, returncode=0, stderr="", stdout="")
        if args == ("enable", "chassis")
        else CompletedProcess(
            args=args,
            returncode=1,
            stderr="cannot disable last central node",
            stdout="",
        )
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "last central" in manager.charm.unit.status.message.lower()
    calls = [call.args for call in mock_call_microovn_command.call_args_list]
    assert ("disable", "central") in calls
    assert ("disable", "central", "--allow-disable-last-central") not in calls


def test_gateway_removed_clears_option(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """[central, chassis] without gateway should clear enable-chassis-as-gw."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    # ovs-vsctl get returns existing gateway option
    mock_subprocess_run.side_effect = [
        CompletedProcess(args="", returncode=0, stderr="", stdout='"enable-chassis-as-gw"'),  # get
        CompletedProcess(args="", returncode=0, stderr="", stdout=""),  # set (clear)
    ]

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)
    # Verify ovs-vsctl remove was called to clear the option
    remove_calls = [c for c in mock_subprocess_run.call_args_list if "remove" in str(c)]
    assert remove_calls


# --- Revocation tests ---


def test_revoke_keeps_workload_state(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Relation broken keeps current workload state, no commands executed."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_broken(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_not_called()
    mock_subprocess_run.assert_not_called()


def test_revoke_clears_stored_roles(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Relation broken clears stored applied roles, so future events don't enforce."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_broken(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        # Pre-populate stored roles to simulate a prior apply
        manager.charm.role_handler._save_applied_roles({"central", "chassis"})
        assert manager.charm.role_handler._get_applied_roles() == {"central", "chassis"}

    # After the relation_broken event, stored roles should be cleared
    assert manager.charm.role_handler._get_applied_roles() is None


def test_revoke_recomputes_status_via_relation_broken(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Relation broken triggers status recomputation and reaches ActiveStatus."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_broken(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    # _on_role_assignment_revoked now calls _on_update_status,
    # which should reach ActiveStatus since the relation is gone.
    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_not_called()
    mock_subprocess_run.assert_not_called()


# --- Idempotency tests ---


def test_same_roles_twice_no_extra_commands(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Re-applying the same roles should not block even if enable-central reports already enabled.

    Verifies idempotency: "already enabled" response is treated as success.
    """
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    # First application succeeds normally
    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)

    # Second application: enable central returns "already enabled" error
    def already_enabled_side_effect(*args):
        if args == ("enable", "central"):
            return CompletedProcess(
                args=args, returncode=1, stderr="this service is already enabled", stdout=""
            )
        return CompletedProcess(args=args, returncode=0, stderr="", stdout="")

    mock_call_microovn_command.side_effect = already_enabled_side_effect

    ctx2 = testing.Context(MicroovnCharm)
    with ctx2(
        ctx2.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager2:
        manager2.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager2.charm.unit.status, ops.BlockedStatus)


def test_stored_roles_skip_mutation(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """When stored roles match desired roles, no microovn commands should run."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    # First application
    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    mock_call_microovn_command.assert_called()
    mock_call_microovn_command.reset_mock()
    mock_subprocess_run.reset_mock()

    # Second application via enforce_roles (simulating update-status path)
    ctx2 = testing.Context(MicroovnCharm)
    with ctx2(
        ctx2.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager2:
        manager2.charm.token_consumer._stored.in_cluster = True
        # Pre-populate stored state to simulate prior apply
        manager2.charm.role_handler._save_applied_roles({"central", "chassis"})

    # No microovn commands should have been called for role application
    mock_call_microovn_command.assert_not_called()
    mock_subprocess_run.assert_not_called()


# --- Concurrent relation lifecycle tests ---


def test_ovsdb_external_ready_with_control_role_blocks(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Ready ovsdb-external with central role assigned should block with dataplane-only message.

    Verifies that mixing central and dataplane-only modes results in a BlockedStatus.
    """
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])
    ovsdb_ext_rel = testing.Relation(
        endpoint=OVSDBCMD_RELATION, remote_app_data={"loadbalancer-address": "192.168.0.16"}
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel, ovsdb_ext_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "dataplane-only" in manager.charm.unit.status.message
    mock_call_microovn_command.assert_not_called()


def test_local_chassis_only_after_ovsdb_external_removed_succeeds(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Chassis-only without ready ovsdb-external should stay valid in local mode."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_any_call("enable", "chassis")
    mock_call_microovn_command.assert_any_call("disable", "central")


# --- Update-status preserving assignment invariants ---


def test_update_status_enforces_role_constraints(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """update-status with role relation should re-evaluate and enforce constraints."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    # enforce_roles should have been called, resulting in enable central
    mock_call_microovn_command.assert_any_call("enable", "central")


def test_update_status_pending_stays_waiting(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """update-status with pending assignment should show WaitingStatus."""
    role_rel = _make_role_assignment_relation(status="pending")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.WaitingStatus)
    mock_call_microovn_command.assert_not_called()


def test_update_status_error_stays_blocked(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """update-status with error assignment should show BlockedStatus."""
    role_rel = _make_role_assignment_relation(status="error", message="bad config")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "bad config" in manager.charm.unit.status.message
    mock_call_microovn_command.assert_not_called()


def test_update_status_no_role_relation_active(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_microovn_central_exists,
):
    """update-status without role-assignment relation should reach ActiveStatus normally."""
    mock_microovn_central_exists.return_value = True

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_not_called()


# --- Gateway config get failure ---


def test_gateway_config_get_failure_does_not_clobber_on_enable(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """When ovs-vsctl get fails and we enable gateway, set only the gateway flag."""
    role_rel = _make_role_assignment_relation(
        status="assigned", roles=["central", "chassis", "gateway"]
    )

    mock_subprocess_run.side_effect = [
        # get fails, no existing key
        CompletedProcess(args="", returncode=1, stderr="no key", stdout=""),
        # set succeeds
        CompletedProcess(args="", returncode=0, stderr="", stdout=""),
    ]

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)
    # Verify the set call only contains the gateway flag
    set_call = mock_subprocess_run.call_args_list[1]
    assert "enable-chassis-as-gw" in str(set_call)


def test_gateway_config_get_failure_preserves_state_on_disable(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """When ovs-vsctl get fails and we disable gateway, don't write anything."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    mock_subprocess_run.return_value = CompletedProcess(
        args="", returncode=1, stderr="no key", stdout=""
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)
    # Only the get call, no set/remove call
    assert mock_subprocess_run.call_count == 1


def test_gateway_config_preserves_other_options(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """When adding gateway, existing ovn-cms-options should be preserved."""
    role_rel = _make_role_assignment_relation(
        status="assigned", roles=["central", "chassis", "gateway"]
    )

    mock_subprocess_run.side_effect = [
        # get returns existing options
        CompletedProcess(args="", returncode=0, stderr="", stdout='"other-option"'),
        # set succeeds
        CompletedProcess(args="", returncode=0, stderr="", stdout=""),
    ]

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert not isinstance(manager.charm.unit.status, ops.BlockedStatus)
    set_call = mock_subprocess_run.call_args_list[1]
    set_args = str(set_call)
    assert "other-option" in set_args
    assert "enable-chassis-as-gw" in set_args


# --- Gateway transient failure tests ---


def test_gateway_transient_get_failure_blocks_on_enable(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Transient ovs-vsctl get failure should block, not write from empty."""
    role_rel = _make_role_assignment_relation(
        status="assigned", roles=["central", "chassis", "gateway"]
    )

    mock_subprocess_run.return_value = CompletedProcess(
        args="", returncode=1, stderr="database connection failed", stdout=""
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "gateway" in manager.charm.unit.status.message.lower()
    # No write (set/remove) calls, only get calls
    write_calls = [
        c for c in mock_subprocess_run.call_args_list if "set" in str(c) or "remove" in str(c)
    ]
    assert not write_calls


def test_gateway_transient_get_failure_blocks_on_disable(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Transient ovs-vsctl get failure on disable should block, not skip."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    mock_subprocess_run.return_value = CompletedProcess(
        args="", returncode=1, stderr="database connection failed", stdout=""
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "gateway" in manager.charm.unit.status.message.lower()
    # No write (set/remove) calls, only get calls
    write_calls = [
        c for c in mock_subprocess_run.call_args_list if "set" in str(c) or "remove" in str(c)
    ]
    assert not write_calls


# --- Revoke clears stale error status ---


def test_revoke_clears_stale_error_status(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Relation broken after error assignment clears BlockedStatus."""
    role_rel = _make_role_assignment_relation(status="error", message="bad config")

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_broken(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    # _on_update_status should have recomputed status to Active
    assert manager.charm.unit.status == ops.ActiveStatus()


# --- Cache invalidation across dataplane transitions ---


def test_cache_invalidated_re_applies_roles(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """After cache invalidation, enforce_roles re-applies even if roles match.

    Reproduces the high-priority bug: _dataplane_mode() disables central
    outside RoleHandler, cache still says {central, chassis} is applied,
    so enforce_roles short-circuits. After invalidation, it should
    re-enable central.
    """
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True
        # Pre-populate cache (simulates prior successful apply)
        manager.charm.role_handler._save_applied_roles({"central", "chassis"})
        # Invalidate (simulates what _on_ovsdbcms_broken does)
        manager.charm.role_handler.invalidate_applied_roles()

    # enforce_roles ran via _on_update_status and since cache was
    # invalidated, it should have re-applied roles
    mock_call_microovn_command.assert_any_call("enable", "central")


# --- Successful apply reaches ActiveStatus ---


def test_apply_assigned_reaches_active_status(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Successful role application should end at ActiveStatus, not stale.

    Verifies that _on_role_assignment_changed calls _on_update_status
    after apply(), clearing any prior WaitingStatus.
    """
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.relation_changed(role_rel),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_any_call("enable", "central")


# --- Central role + later ovsdb-external lifecycle change ---


def test_control_role_then_ready_ovsdb_external_added_blocks_on_update_status(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """After central+chassis applied, ready ovsdb-external should block on update-status."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["central", "chassis"])
    ovsdb_ext_rel = testing.Relation(
        endpoint=OVSDBCMD_RELATION, remote_app_data={"loadbalancer-address": "192.168.0.16"}
    )

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel, ovsdb_ext_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert isinstance(manager.charm.unit.status, ops.BlockedStatus)
    assert "dataplane-only" in manager.charm.unit.status.message


# --- Chassis-only role + later ovsdb-external removal stays valid on update-status ---


def test_chassis_only_ovsdb_external_removed_stays_active_on_update_status(
    mock_microovn_snap,
    mock_ovn_exporter_snap,
    mock_check_metrics_endpoint,
    mock_call_microovn_command,
    mock_subprocess_run,
    mock_microovn_central_exists,
):
    """Chassis-only role without ready ovsdb-external should remain valid on update-status."""
    role_rel = _make_role_assignment_relation(status="assigned", roles=["chassis"])

    ctx = testing.Context(MicroovnCharm)
    with ctx(
        ctx.on.update_status(),
        testing.State(relations=[role_rel]),
    ) as manager:
        manager.charm.token_consumer._stored.in_cluster = True

    assert manager.charm.unit.status == ops.ActiveStatus()
    mock_call_microovn_command.assert_any_call("enable", "chassis")
    mock_call_microovn_command.assert_any_call("disable", "central")
