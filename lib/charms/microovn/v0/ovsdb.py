"""This is a charm library for the ovsdb interface.

This contains two classes to ease development of charms using this interface,
one for provides and one for requires.

The provides part of this takes the ovsdb connection strings from the microovn
environment file.

The requires part communicates with the relation data and gets these strings to
be easily returned and used for interaction with the ovsdb databases.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from ops import CharmBase, EventBase, StoredState
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "599e7729d8cf403db3f6afb6d7c64c92"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

ENV_FILE = "/var/snap/microovn/common/data/env/ovn.env"
CONNECT_ENV_NAME = "OVN_{0}_CONNECT"
CONNECT_STR_KEY = "db_{0}_connection_str"

logger = logging.getLogger(__name__)


@dataclass
class OVSDBConnectionString:
    """Class for storing the northbound and southbound connection strings."""

    nb: str
    sb: str


class OVSDBRequires(Object):
    """Class for implementing the requires side of the ovsdb relation."""

    _stored = StoredState()

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

    def get_connection_strings(self) -> Optional[OVSDBConnectionString]:
        """Return the ovsdb connection strings.

        Get the northbound and southbound database connection strings from the
        relation data as an instance of OVSDBConnectionString and return them.
        On failure return None.
        """
        if not (relation := self.charm.model.get_relation(self.relation_name)):
            return None

        ovsdb_app_data = relation.data[relation.app]
        nb_connect = ovsdb_app_data.get(CONNECT_STR_KEY.format("nb"))
        sb_connect = ovsdb_app_data.get(CONNECT_STR_KEY.format("sb"))
        if nb_connect and sb_connect:
            return OVSDBConnectionString(nb=nb_connect, sb=sb_connect)
        else:
            return None


class OVSDBProvides(Object):
    """Class for implementing the provides side of the ovsdb relation."""

    _stored = StoredState()

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_ovsdb_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_created,
            self._on_ovsdb_relation_changed,
        )

    def _on_ovsdb_relation_changed(self, _: EventBase):
        self.update_relation_data()

    def update_relation_data(self):
        """Update the data stored in the application databag for the relation."""
        token_consumer = getattr(self.charm, "token_consumer", None)
        if not token_consumer:
            return

        if not (self.charm.unit.is_leader() and token_consumer._stored.in_cluster):
            return

        if not (relation := self.charm.model.get_relation(self.relation_name)):
            return

        connect_str = self.get_connection_strings()
        if connect_str:
            relation.data[self.charm.app][CONNECT_STR_KEY.format("nb")] = connect_str.nb
            relation.data[self.charm.app][CONNECT_STR_KEY.format("sb")] = connect_str.sb
            logger.info("connection strings updated")

    def get_connection_strings(self) -> Optional[OVSDBConnectionString]:
        """Get the ovsdb connection strings from local environment file.

        Get the northbound and southbound database connection strings from the
        microovn environment file at ENV_FILE. Return this as an instance of
        OVSDBConnectionString.
        On failure or the strings not being present return None.
        """
        nb_connect = None
        sb_connect = None
        try:
            with open(ENV_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(CONNECT_ENV_NAME.format("NB")):
                        nb_connect = line.split("=", 1)[1].strip('"')
                    if line.startswith(CONNECT_ENV_NAME.format("SB")):
                        sb_connect = line.split("=", 1)[1].strip('"')
        except FileNotFoundError:
            logger.error("OVN env file not found, is this unit in the microovn cluster?")
            raise FileNotFoundError("{0} not found".format(ENV_FILE))

        if nb_connect and sb_connect:
            return OVSDBConnectionString(nb=nb_connect, sb=sb_connect)
        else:
            return None
