#!/usr/bin/env python3
import ops

from charms.ovsdb_interface.v0.ovsdb import OVSDBRequires

class InterfaceConsumerCharm(ops.CharmBase):
    ovsdb_requires = None

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.ovsdb_relation_created, self._on_ovsdb_created)
        self.framework.observe(self.on.ovsdb_relation_changed, self._on_ovsdb_changed)
        self.ovsdb_requires = OVSDBRequires(
            charm=self,
            relation_name="ovsdb",
        )

    def _on_ovsdb_created(self, _: ops.EventBase):
        self.unit.status = ops.MaintenanceStatus("connected to ovsdb")

    def _on_ovsdb_changed(self, event: ops.RelationChangedEvent):
        if constr := self.ovsdb_requires.get_connection_strings():
            self.unit.status = ops.ActiveStatus("got string")

if __name__ == "__main__":  # pragma: nocover
    ops.main(InterfaceConsumerCharm)
