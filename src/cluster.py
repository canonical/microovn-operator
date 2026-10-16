# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""MicroOVN-specific initialization for the token distributor consumer."""

import logging
import subprocess
import tempfile
from functools import cached_property
from ipaddress import IPv6Address, ip_address

import ops
import yaml
from charms.microcluster_token_distributor.v0 import token_distributor

from constants import DATA_BINDING, WORKER_RELATION

logger = logging.getLogger(__name__)


class InitializationError(Exception):
    """MicroOVN could not initialize with the requested network bindings."""


class TokenConsumer(token_distributor.TokenConsumer):
    """Initialize MicroOVN with a preseed while retaining token coordination.

    Keep the library's class name and object key: they form the framework handle
    for its StoredState and deferred events. Renaming this class would lose the
    existing in_cluster flag on upgrade and try to bootstrap joined units again.
    """

    def _binding_address(self, endpoint: str) -> str:
        """Use Juju's local bind address, never an ingress address or NIC guess."""
        try:
            binding = self.charm.model.get_binding(endpoint)
            address = binding.network.bind_address if binding else None
        except (ops.ModelError, ValueError) as exc:
            raise InitializationError(f"Cannot read {endpoint} network binding") from exc

        if address is None:
            raise InitializationError(f"No bind address for {endpoint} network binding")
        try:
            address = ip_address(str(address))
        except ValueError as exc:
            raise InitializationError(
                f"Invalid bind address for {endpoint} network binding"
            ) from exc

        # Private IPv4 and IPv6 ULA addresses are valid. Link-local and scoped
        # addresses cannot be advertised to other hosts as cluster endpoints.
        unscoped = not isinstance(address, IPv6Address) or address.scope_id is None
        if (
            not unscoped
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise InitializationError(f"Unusable bind address for {endpoint} network binding")
        return str(address)

    @cached_property
    def initialization_addresses(self) -> dict[str, str]:
        """Resolve both bindings once per hook, before OVS migration can disrupt networking."""
        # Juju resolves unbound endpoints through its default network, so no
        # user-created spaces or explicit --bind options are required.
        return {
            "address": self._binding_address(WORKER_RELATION),
            "custom_encapsulation_ip": self._binding_address(DATA_BINDING),
        }

    def _call_cluster_command(self, *args) -> tuple[int, str]:
        if not args or args[0] not in ("bootstrap", "join"):
            return super()._call_cluster_command(*args)

        mode = args[0]
        token = args[1] if mode == "join" else ""
        preseed = {
            "mode": mode,
            "name": token_distributor.get_hostname(),
            "services": "auto",
            **self.initialization_addresses,
        }
        if token:
            preseed["token"] = token

        try:
            # MicroOVN detects preseed input on stdin; there is no --preseed
            # flag. The anonymous, mode-0600 file also keeps join tokens out of
            # argv and is removed on both success and failure.
            with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as seed:
                yaml.safe_dump(preseed, seed)
                seed.seek(0)
                result = subprocess.run(
                    ["microovn", "init"],
                    stdin=seed,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
        except OSError as exc:
            raise InitializationError("Unable to run microovn init") from exc

        if result.returncode:
            # Do not let the generic consumer log a failed join's token.
            stderr = (result.stderr or "").strip()
            if token:
                stderr = stderr.replace(token, "<redacted>")
            logger.error("microovn init (%s) failed: %s", mode, stderr or result.returncode)
            raise InitializationError(f"MicroOVN {mode} failed; see debug-log")
        return result.returncode, result.stdout

    def _initialization_failed(self, event: ops.EventBase, error: InitializationError) -> None:
        logger.error("%s", error)
        self.charm.unit.status = ops.BlockedStatus(str(error))
        event.defer()

    def _on_cluster_changed(self, event: ops.RelationChangedEvent):
        try:
            # Validate before emitting prejoin/prebootstrap. An exception in a
            # nested event leaves it queued for replay outside this handler.
            if not self._stored.in_cluster:
                self.initialization_addresses
            super()._on_cluster_changed(event)
        except InitializationError as exc:
            self._initialization_failed(event, exc)

    def _handle_relation_joined(self, event: ops.RelationJoinedEvent):
        try:
            if not self._stored.in_cluster:
                self.initialization_addresses
            super()._handle_relation_joined(event)
        except InitializationError as exc:
            self._initialization_failed(event, exc)
