# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Role assignment handler for MicroOVN charm."""

from __future__ import annotations

import enum
import json
import logging
import subprocess
from typing import TYPE_CHECKING

import ops
from charms.role_distributor.v0.role_assignment import (
    AssignmentStatus,
    RoleAssignmentChangedEvent,
    RoleAssignmentRequirer,
    RoleAssignmentRevokedEvent,
    UnitRoleAssignment,
)

from utils import call_microovn_command, count_microovn_cluster_members

if TYPE_CHECKING:
    from charm import MicroovnCharm

logger = logging.getLogger(__name__)


class Role(enum.StrEnum):
    """Supported MicroOVN roles."""

    CENTRAL = "central"
    CHASSIS = "chassis"
    GATEWAY = "gateway"


class ProcessCallResult(enum.Enum):
    """Outcome of a subprocess call performed by RoleHandler."""

    OK = enum.auto()
    FAILED = enum.auto()
    # The call did not succeed but the condition is expected to be transient.
    # The caller should wait and retry rather than treat this as a failure.
    RETRY = enum.auto()


class RoleHandler(ops.Object):
    """Handles role-assignment relation logic for MicroOVN."""

    _stored = ops.StoredState()

    def __init__(self, charm: MicroovnCharm, relation_name: str) -> None:
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self.requirer = RoleAssignmentRequirer(charm, relation_name)
        self._stored.set_default(applied_roles="")
        self._stored.set_default(applied_dataplane_only=False)

    def get_assignment(self) -> UnitRoleAssignment | None:
        """Return the current role assignment for this unit, or None if unassigned."""
        return self.requirer.get_assignment()

    @property
    def has_relation(self) -> bool:
        """Return whether the role-assignment relation exists."""
        return self._charm.model.get_relation(self._relation_name) is not None

    def _get_applied_roles(self) -> set[str] | None:
        """Return previously applied roles, or None if never applied."""
        raw: str = str(self._stored.applied_roles)
        if not raw:
            return None
        return set(json.loads(raw))

    def _save_applied_roles(self, roles: set[str]) -> None:
        """Persist the set of roles that were successfully applied."""
        self._stored.applied_roles = json.dumps(sorted(roles))
        self._stored.applied_dataplane_only = bool(self._charm.is_dataplane_only)

    def _clear_applied_roles(self) -> None:
        """Clear the stored applied roles."""
        self._stored.applied_roles = ""
        self._stored.applied_dataplane_only = False

    def _applied_dataplane_only(self) -> bool:
        """Return whether the cached roles were applied in dataplane-only mode."""
        return bool(self._stored.applied_dataplane_only)

    def invalidate_applied_roles(self) -> None:
        """Invalidate the applied-roles cache.

        Must be called whenever workload state is mutated outside of
        RoleHandler (e.g. by _dataplane_mode()), so that the next
        enforce_roles() re-applies instead of short-circuiting.
        """
        self._clear_applied_roles()

    def _resolve_assignment_roles(
        self, status: AssignmentStatus | str, roles: tuple[str, ...], message: str | None
    ) -> set[str] | None:
        """Translate assignment status into a unit status or a normalized role set."""
        match AssignmentStatus.coerce(status):
            case AssignmentStatus.ERROR:
                self._charm.unit.status = ops.BlockedStatus(f"Role assignment error: {message}")
                return None
            case AssignmentStatus.ASSIGNED:
                return self._normalize_roles(set(roles))
            case _:
                self._charm.unit.status = ops.WaitingStatus("Waiting for role assignment")
                return None

    def apply(self, event: RoleAssignmentChangedEvent) -> None:
        """Apply roles from a role assignment changed event."""
        roles = self._resolve_assignment_roles(event.status, event.roles, event.message)
        if roles is None:
            return
        if not self._charm.is_in_cluster:
            logger.info("Not in cluster, deferring role application")
            event.defer()
            return

        if self.enforce_roles(roles) is ProcessCallResult.RETRY:
            # A peer application sharing this MicroOVN cluster may still
            # be enabling its central nodes. Defer so we retry once the
            # cluster has another central available.
            logger.info("Deferring role application until a peer central node is available")
            event.defer()

    def revoke(self, event: RoleAssignmentRevokedEvent) -> None:
        """Handle role assignment revocation.

        Keeps current workload state but clears stored roles so that
        enforce_roles is no longer called on subsequent lifecycle events.
        """
        logger.info("Role assignment relation broken, keeping current workload state")
        self._clear_applied_roles()

    def enforce_roles(self, roles: set[str] | None = None) -> ProcessCallResult:
        """Enforce role assignment constraints and apply roles if needed.

        This is the single entry point for role enforcement, callable from
        any lifecycle event. When called without explicit roles, reads the
        current assignment from the relation databag.

        Does nothing when no role-assignment relation exists and no roles
        are provided.

        Returns the outcome of the role application.
        RETRY means the operation is pending because central could not be
        disabled yet (it is currently the last central in a shared cluster)
        and callers handling an event should defer.
        Non-mutating paths return OK.
        """
        if roles is None:
            assignment = self.get_assignment()
            if assignment is None:
                return ProcessCallResult.OK
            roles = self._resolve_assignment_roles(
                assignment.status, assignment.roles, assignment.message
            )
            if roles is None:
                return ProcessCallResult.OK

        if not roles:
            self._charm.unit.status = ops.BlockedStatus("No recognized roles assigned")
            return ProcessCallResult.OK

        dataplane_only = self._charm.is_dataplane_only
        if Role.GATEWAY in roles and Role.CHASSIS not in roles:
            self._charm.unit.status = ops.BlockedStatus("Gateway role requires chassis role")
            return ProcessCallResult.OK
        if dataplane_only and Role.CENTRAL in roles:
            self._charm.unit.status = ops.BlockedStatus(
                "Cannot enable central while in dataplane-only mode"
            )
            return ProcessCallResult.OK

        previously_applied = self._get_applied_roles()
        if previously_applied == roles and self._applied_dataplane_only() == dataplane_only:
            logger.info(
                "Roles already applied: %s (dataplane_only=%s), skipping mutation",
                roles,
                dataplane_only,
            )
            return ProcessCallResult.OK

        result = self._apply_roles(roles, dataplane_only=dataplane_only)
        if result is ProcessCallResult.RETRY:
            self._charm.unit.status = ops.WaitingStatus(
                "Waiting for another central node in the cluster before disabling central"
            )
        return result

    @staticmethod
    def _normalize_roles(roles: set[str]) -> set[str]:
        """Filter to known roles, logging warnings for unknown ones."""
        known_values = {r.value for r in Role}
        unknown_roles = roles - known_values
        if unknown_roles:
            logger.warning("Ignoring unrecognized roles: %s", unknown_roles)
        return roles & known_values

    def _apply_roles(self, roles: set[str], *, dataplane_only: bool) -> ProcessCallResult:
        desired_central = Role.CENTRAL in roles
        desired_chassis = Role.CHASSIS in roles
        desired_gateway = Role.GATEWAY in roles

        if not desired_gateway and self._disable_gateway() is not ProcessCallResult.OK:
            return ProcessCallResult.FAILED

        if desired_chassis:
            if self._enable_chassis() is not ProcessCallResult.OK:
                return ProcessCallResult.FAILED
        elif self._disable_chassis() is not ProcessCallResult.OK:
            return ProcessCallResult.FAILED

        if desired_central:
            if self._enable_central() is not ProcessCallResult.OK:
                return ProcessCallResult.FAILED
        else:
            result = self._disable_central(allow_disable_last=dataplane_only)
            if result is not ProcessCallResult.OK:
                # Propagate the transient last-central case so the caller can
                # wait and retry instead of blocking permanently.
                return result

        if desired_gateway and self._enable_gateway() is not ProcessCallResult.OK:
            return ProcessCallResult.FAILED

        self._save_applied_roles(roles)
        return ProcessCallResult.OK

    def _set_service_enabled(
        self, service: Role, enabled: bool, *, allow_disable_last: bool = False
    ) -> ProcessCallResult:
        action = "enable" if enabled else "disable"
        command = [action, service.value]
        if service is Role.CENTRAL and not enabled and allow_disable_last:
            command.append("--allow-disable-last-central")

        res = call_microovn_command(*command)
        if res.returncode == 0:
            return ProcessCallResult.OK

        service_name = service.value.capitalize()
        if enabled and "this service is already enabled" in res.stderr:
            logger.info("%s service already enabled", service_name)
            return ProcessCallResult.OK
        if not enabled and "this service is not enabled" in res.stderr:
            logger.info("%s service already disabled", service_name)
            return ProcessCallResult.OK
        if service is Role.CENTRAL and not enabled and not allow_disable_last:
            if "last central" in res.stderr.lower():
                # - Single-member cluster: this really is the last central and
                #   the last node. Disabling it would destroy the OVN NB/SB
                #   databases, so block and let the operator decide. Never force
                #   --allow-disable-last-central here.
                # - Multi-member cluster: a peer member can provide central but may
                #   not have enabled it yet. This is transient, so wait and retry.
                if count_microovn_cluster_members() > 1:
                    logger.info(
                        "Cannot disable central yet: currently the last central in a "
                        "multi-member cluster. Waiting for a peer central node before "
                        "retrying."
                    )
                    return ProcessCallResult.RETRY

                logger.error(
                    "Refusing to disable the last central node of a single-member "
                    "cluster outside dataplane-only mode"
                )
                self._charm.unit.status = ops.BlockedStatus(
                    "Cannot disable the last central node outside dataplane-only mode"
                )
                return ProcessCallResult.FAILED

        logger.error(
            "microovn %s %s failed with code %s, stderr: %s",
            action,
            service.value,
            res.returncode,
            res.stderr,
        )
        self._charm.unit.status = ops.BlockedStatus(f"Failed to {action} {service.value} service")
        return ProcessCallResult.FAILED

    def _enable_central(self) -> ProcessCallResult:
        return self._set_service_enabled(Role.CENTRAL, enabled=True)

    def _enable_chassis(self) -> ProcessCallResult:
        return self._set_service_enabled(Role.CHASSIS, enabled=True)

    def _disable_chassis(self) -> ProcessCallResult:
        return self._set_service_enabled(Role.CHASSIS, enabled=False)

    def _disable_central(self, *, allow_disable_last: bool = False) -> ProcessCallResult:
        return self._set_service_enabled(
            Role.CENTRAL, enabled=False, allow_disable_last=allow_disable_last
        )

    def _enable_gateway(self) -> ProcessCallResult:
        return self._set_gateway_option(enable=True)

    def _disable_gateway(self) -> ProcessCallResult:
        return self._set_gateway_option(enable=False)

    def _set_gateway_option(self, *, enable: bool) -> ProcessCallResult:
        res = subprocess.run(
            ["microovn.ovs-vsctl", "get", "open_vswitch", ".", "external-ids:ovn-cms-options"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            if "no key" not in res.stderr:
                # Transient / unexpected failure, fail closed.
                logger.error(
                    "Failed to read ovn-cms-options, code %s, stderr: %s",
                    res.returncode,
                    res.stderr,
                )
                self._charm.unit.status = ops.BlockedStatus("Failed to read gateway configuration")
                return ProcessCallResult.FAILED
            # Key absent, safe to treat as empty on enable,
            # nothing to remove on disable.
            if enable:
                current_options: set[str] = set()
            else:
                logger.info("ovn-cms-options key absent, nothing to disable for gateway")
                return ProcessCallResult.OK
        else:
            raw = res.stdout.strip().strip('"')
            current_options = {o.strip() for o in raw.split(",") if o.strip()}

        desired = current_options.copy()
        if enable:
            desired.add("enable-chassis-as-gw")
        else:
            desired.discard("enable-chassis-as-gw")

        if desired == current_options:
            logger.info("Gateway option already in desired state")
            return ProcessCallResult.OK

        new_value = ",".join(sorted(desired))
        if new_value:
            cmd = [
                "microovn.ovs-vsctl",
                "set",
                "open_vswitch",
                ".",
                f"external-ids:ovn-cms-options={new_value}",
            ]
        else:
            cmd = [
                "microovn.ovs-vsctl",
                "remove",
                "open_vswitch",
                ".",
                "external-ids",
                "ovn-cms-options",
            ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            logger.error(
                "Failed to set ovn-cms-options, code %s, stderr: %s",
                res.returncode,
                res.stderr,
            )
            self._charm.unit.status = ops.BlockedStatus("Failed to update gateway configuration")
            return ProcessCallResult.FAILED
        return ProcessCallResult.OK
