"""TODO: Add a proper docstring here.

This is a placeholder docstring for this charm library. Docstrings are
presented on Charmhub and updated whenever you push a new version of the
library.

Complete documentation about creating and documenting libraries can be found
in the SDK docs at https://juju.is/docs/sdk/libraries.

See `charmcraft publish-lib` and `charmcraft fetch-lib` for details of how to
share and consume charm libraries. They serve to enhance collaboration
between charmers. Use a charmer's libraries for classes that handle
integration with their charm.

Bear in mind that new revisions of the different major API versions (v0, v1,
v2 etc) are maintained independently.  You can continue to update v0 and v1
after you have pushed v3.

Markdown is supported, following the CommonMark specification.
"""

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

import logging

from ops import CharmBase, StoredState, EventBase
from ops.framework import Object
from ops.model import (
    Application,
    ModelError,
    Relation,
    SecretNotFoundError,
    Unit,
)

logger = logging.getLogger(__name__)

class OVSDBRequires(Object):
    _stored = StoredState()

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

    def get_connection_strings(self):
        if not (relation := self.charm.model.get_relation(self.relation_name)):
            return None

        ovsdb_app_data = relation.data[relation.app]
        nb_connect = ovsdb_app_data.get(CONNECT_STR_KEY.format("nb"))
        sb_connect = ovsdb_app_data.get(CONNECT_STR_KEY.format("sb"))
        if nb_connect and sb_connect:
            return (nb_connect, sb_connect)
        else:
            return None

class OVSDBProvides(Object):
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
        if not (self.charm.unit.is_leader() and self.charm._stored.in_cluster):
            return

        if not (relation := self.charm.model.get_relation(self.relation_name)):
            return

        (nb_connect, sb_connect) = self.get_connection_strings()
        if (nb_connect != None) and (sb_connect != None):
            relation.data[self.charm.app][CONNECT_STR_KEY.format("nb")] = nb_connect
            relation.data[self.charm.app][CONNECT_STR_KEY.format("sb")] = sb_connect
            logger.info("connection strings updated")

    def get_connection_strings(self):
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

        return (nb_connect,sb_connect)
