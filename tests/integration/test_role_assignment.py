#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import jubilant
import yaml

TOKEN_DISTRIBUTOR_CHARM = "microcluster-token-distributor"
TOKEN_DISTRIBUTOR_CHANNEL = "latest/edge"
ROLE_DISTRIBUTOR_CHARM = "role-distributor"
ROLE_DISTRIBUTOR_CHANNEL = "latest/candidate"


def _set_role_mapping(juju: jubilant.Juju, model_name: str, app_name: str, mapping: dict) -> None:
    """Set the role-mapping config on the role-distributor charm.

    The role-distributor expects a model + application scoped hierarchy:
        model-name:
          application-name:
            machines:
              machine-id:
                roles: [...]
    """
    juju.config(
        ROLE_DISTRIBUTOR_CHARM,
        {"role-mapping": yaml.dump({model_name: {app_name: mapping}})},
    )


def _deploy_microovn_cluster(juju: jubilant.Juju, charm_path: Path, app_name: str) -> None:
    """Deploy microovn + token-distributor and wait for active cluster."""
    juju.deploy(charm_path, app=app_name)
    juju.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju.wait(jubilant.all_active)


def _deploy_role_distributor(juju: jubilant.Juju) -> None:
    """Deploy role-distributor and wait until it is ready to relate."""
    juju.deploy(ROLE_DISTRIBUTOR_CHARM, channel=ROLE_DISTRIBUTOR_CHANNEL)
    juju.wait(
        lambda status: ROLE_DISTRIBUTOR_CHARM in status.apps
        and f"{ROLE_DISTRIBUTOR_CHARM}/0" in status.apps[ROLE_DISTRIBUTOR_CHARM].units
        and status.apps[ROLE_DISTRIBUTOR_CHARM]
        .units[f"{ROLE_DISTRIBUTOR_CHARM}/0"]
        .juju_status.current
        == "idle"
    )


def test_role_assignment_basic_flow(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    """Deploy microovn + role-distributor, assign central+chassis, verify central enabled."""
    _deploy_microovn_cluster(juju_lxd, charm_path, app_name)

    _deploy_role_distributor(juju_lxd)

    juju_lxd.integrate(app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_agents_idle(status))

    status = juju_lxd.status()
    model_name = status.model.name
    machine_id = status.apps[app_name].units[f"{app_name}/0"].machine

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["central", "chassis"]}}},
    )

    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)

    output = juju_lxd.exec("microovn status", unit=f"{app_name}/0")
    assert "central" in output.stdout


def test_role_assignment_chassis_only_local_blocks_on_last_central(
    juju_lxd: jubilant.Juju, charm_path: Path, app_name: str
):
    """Single-node local chassis-only must block rather than force-dropping the last central."""
    _deploy_microovn_cluster(juju_lxd, charm_path, app_name)

    _deploy_role_distributor(juju_lxd)

    juju_lxd.integrate(app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_agents_idle(status))

    status = juju_lxd.status()
    model_name = status.model.name
    machine_id = status.apps[app_name].units[f"{app_name}/0"].machine

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["chassis"]}}},
    )

    juju_lxd.wait(lambda status: jubilant.all_blocked(status, app_name))
    juju_lxd.wait(jubilant.all_agents_idle)

    status = juju_lxd.status()
    assert "last central" in status.apps[app_name].units[f"{app_name}/0"].workload_status.message


def test_role_assignment_gateway_toggle(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    """Assign gateway role, verify enabled, remove, verify disabled."""
    _deploy_microovn_cluster(juju_lxd, charm_path, app_name)

    _deploy_role_distributor(juju_lxd)

    juju_lxd.integrate(app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_agents_idle(status))

    status = juju_lxd.status()
    model_name = status.model.name
    machine_id = status.apps[app_name].units[f"{app_name}/0"].machine

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["central", "chassis", "gateway"]}}},
    )
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)

    cms_cmd = "microovn.ovs-vsctl get open_vswitch . external-ids:ovn-cms-options"
    output = juju_lxd.exec(cms_cmd, unit=f"{app_name}/0")
    assert "enable-chassis-as-gw" in output.stdout

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["central", "chassis"]}}},
    )
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)

    # Key may be removed entirely when no options remain
    output = juju_lxd.exec(
        "microovn.ovs-vsctl get open_vswitch . external-ids:ovn-cms-options || echo ''",
        unit=f"{app_name}/0",
    )
    assert "enable-chassis-as-gw" not in output.stdout


def test_role_assignment_gateway_requires_chassis(
    juju_lxd: jubilant.Juju, charm_path: Path, app_name: str
):
    """Gateway-only assignment should be rejected."""
    _deploy_microovn_cluster(juju_lxd, charm_path, app_name)

    _deploy_role_distributor(juju_lxd)

    juju_lxd.integrate(app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_agents_idle(status))

    status = juju_lxd.status()
    model_name = status.model.name
    machine_id = status.apps[app_name].units[f"{app_name}/0"].machine

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["gateway"]}}},
    )

    juju_lxd.wait(lambda status: jubilant.all_blocked(status, app_name))
    juju_lxd.wait(jubilant.all_agents_idle)


def test_role_assignment_relation_broken(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    """Remove role-assignment relation, verify charm handles gracefully."""
    _deploy_microovn_cluster(juju_lxd, charm_path, app_name)

    _deploy_role_distributor(juju_lxd)

    juju_lxd.integrate(app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_agents_idle(status))

    status = juju_lxd.status()
    model_name = status.model.name
    machine_id = status.apps[app_name].units[f"{app_name}/0"].machine

    _set_role_mapping(
        juju_lxd,
        model_name,
        app_name,
        {"machines": {machine_id: {"roles": ["central", "chassis", "gateway"]}}},
    )
    juju_lxd.wait(jubilant.all_active)

    juju_lxd.cli("remove-relation", app_name, ROLE_DISTRIBUTOR_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_active(status, app_name))
    juju_lxd.wait(jubilant.all_agents_idle)

    # Revoke keeps current state, gateway should still be enabled
    cms_cmd = "microovn.ovs-vsctl get open_vswitch . external-ids:ovn-cms-options"
    output = juju_lxd.exec(cms_cmd, unit=f"{app_name}/0")
    assert "enable-chassis-as-gw" in output.stdout


def test_backwards_compatibility_no_role_assignment(
    juju_lxd: jubilant.Juju, charm_path: Path, app_name: str
):
    """Deploy without role-assignment relation, verify charm works as before."""
    juju_lxd.deploy(charm_path, app=app_name)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)
    juju_lxd.exec("microovn status", unit=f"{app_name}/1")
