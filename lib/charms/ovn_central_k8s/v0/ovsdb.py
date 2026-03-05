# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.


"""This module defines the OVSDBCMS relation interface for Juju charms.

The module provides two main classes for implementing the OVSDB CMS (Clustered 
Management System) relation pattern"""

import json
import logging
import typing

import ops
from ops.framework import (
    EventBase,
    EventSource,
    Object,
    ObjectEvents,
    StoredState,
)

# The unique Charmhub library identifier, never change it
LIBID = "114b7bb1970445daa61650e451f9da62"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 4

LOADBALANCER_KEY = "loadbalancer-address"
EXTERNAL_KEY = "external-connectivity"

class OVSDBCMSConnectedEvent(EventBase):
    """OVSDBCMS connected Event."""

    pass


class OVSDBCMSReadyEvent(EventBase):
    """OVSDBCMS ready for use Event."""

    pass


class OVSDBCMSGoneAwayEvent(EventBase):
    """OVSDBCMS relation has gone-away Event"""

    pass


class OVSDBCMSServerEvents(ObjectEvents):
    """Events class for `on`"""

    connected = EventSource(OVSDBCMSConnectedEvent)
    ready = EventSource(OVSDBCMSReadyEvent)
    goneaway = EventSource(OVSDBCMSGoneAwayEvent)


class OVSDBCMSRequires(Object):
    """
    OVSDBCMSRequires class
    """

    on = OVSDBCMSServerEvents()  # pyright: ignore
    _stored = StoredState()

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
        external_connectivity: bool = False,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.external_connectivity = external_connectivity
        self.framework.observe(
            self.charm.on[relation_name].relation_joined,
            self._on_ovsdb_cms_relation_joined,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_ovsdb_cms_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_departed,
            self._on_ovsdb_cms_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken,
            self._on_ovsdb_cms_relation_broken,
        )
        self.request_access(external_connectivity)

    def request_access(self, external_connectivity: bool) -> None:
        """Request access to the external connectivity."""
        if self.model.unit.is_leader():
            for rel in self.model.relations[self.relation_name]:
                rel.data[self.model.app][EXTERNAL_KEY] = json.dumps(
                    external_connectivity
                )

    def _on_ovsdb_cms_relation_joined(self, event):
        """OVSDBCMS relation joined."""
        logging.debug("OVSDBCMSRequires on_joined")
        self.on.connected.emit()

    def bound_hostnames(self):
        return self.get_all_unit_values("bound-hostname")

    def bound_addresses(self):
        return self.get_all_unit_values("bound-address")

    def loadbalancer_address(self) -> str | None:
        relation = self.model.get_relation(self.relation_name)
        if relation:
            return relation.data[relation.app].get(LOADBALANCER_KEY)
        return None

    def remote_ready(self) -> bool:
        if self.external_connectivity:
            return self.loadbalancer_address() is not None
        return all(self.bound_hostnames()) or all(self.bound_addresses())

    def _on_ovsdb_cms_relation_changed(self, event):
        """OVSDBCMS relation changed."""
        logging.debug("OVSDBCMSRequires on_changed")
        if self.remote_ready():
            self.on.ready.emit()

    def _on_ovsdb_cms_relation_broken(self, event):
        """OVSDBCMS relation broken."""
        logging.debug("OVSDBCMSRequires on_broken")
        self.on.goneaway.emit()

    def get_all_unit_values(self, key: str) -> typing.List[str]:
        """Retrieve value for key from all related units."""
        values = []
        relation = self.framework.model.get_relation(self.relation_name)
        if relation:
            for unit in relation.units:
                values.append(relation.data[unit].get(key))
        return values


class OVSDBCMSClientConnectedEvent(EventBase):
    """OVSDBCMS connected Event."""

    pass


class OVSDBCMSClientReadyEvent(EventBase):
    """OVSDBCMS ready for use Event."""

    pass


class OVSDBCMSClientGoneAwayEvent(EventBase):
    """OVSDBCMS relation has gone-away Event"""

    pass


class OVSDBCMSClientEvents(ObjectEvents):
    """Events class for `on`"""

    connected = EventSource(OVSDBCMSClientConnectedEvent)
    ready = EventSource(OVSDBCMSClientReadyEvent)
    goneaway = EventSource(OVSDBCMSClientGoneAwayEvent)


class OVSDBCMSProvides(Object):
    """
    OVSDBCMSProvides class
    """

    on = OVSDBCMSClientEvents()  # pyright: ignore
    _stored = StoredState()

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
        loadbalancer_address: str | None = None,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.loadbalancer_address = loadbalancer_address
        self.framework.observe(
            self.charm.on[relation_name].relation_joined,
            self._on_ovsdb_cms_relation_joined,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_ovsdb_cms_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken,
            self._on_ovsdb_cms_relation_broken,
        )
        self.update_relation_data(loadbalancer_address)

    def update_relation_data(
        self, loadbalancer_address: str | None = None
    ) -> None:
        """Update relation data."""
        if loadbalancer_address and self.model.unit.is_leader():
            for rel in self.model.relations[self.relation_name]:
                rel.data[self.model.app][
                    LOADBALANCER_KEY
                ] = loadbalancer_address

    def _on_ovsdb_cms_relation_joined(self, event):
        """Handle ovsdb-cms joined."""
        logging.debug("OVSDBCMSProvides on_joined")
        self.on.connected.emit()

    def _on_ovsdb_cms_relation_changed(self, event):
        """Handle ovsdb-cms changed."""
        logging.debug("OVSDBCMSProvides on_changed")
        self.on.ready.emit()

    def _on_ovsdb_cms_relation_broken(self, event):
        """Handle ovsdb-cms broken."""
        logging.debug("OVSDBCMSProvides on_departed")
        self.on.goneaway.emit()

    def set_unit_data(self, settings: typing.Dict[str, str]) -> None:
        """Publish settings on the peer unit data bag."""
        relations = self.framework.model.relations[self.relation_name]
        for relation in relations:
            for k, v in settings.items():
                relation.data[self.model.unit][k] = v
