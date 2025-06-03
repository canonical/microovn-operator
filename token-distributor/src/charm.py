#!/usr/bin/env python3
import logging, ops, os

logger = logging.getLogger(__name__)
CONTROL_RELATION = "microovn-cluster"
MIRROR_PREFIX = "mirror-"

def mirrorid(hostname):
    return "{0}{1}".format(MIRROR_PREFIX,hostname)

class TokenDistributor(ops.CharmBase):
    def handle_mirror(self, relation_name):
        if not (relation := self.model.get_relation(relation_name)):
            return False

        relation_data = relation.data
        if "mirror" not in relation_data[self.unit]:
            relation_data[self.unit]["mirror"] = "up"

        for unit in relation_data:
            if "mirror" in relation_data[unit] and relation_data[unit]["mirror"] == "up":
                # add all tokens in the other side of the mirror to this side
                for k, v in relation_data[unit].items():
                    if MIRROR_PREFIX in k:
                        relation_data[self.unit][k] = v

            if not "hostname" in relation_data[unit]:
                continue

            mirror_key = mirrorid(relation_data[unit]["hostname"])
            if self.unit.name != unit.name and not mirror_key in relation_data[self.unit]:
                logger.info("added {0} to mirror".format(mirror_key))
                relation_data[self.unit][mirror_key] = "empty"
        return True

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.leader_elected , self._on_leader_elected)
        framework.observe(self.on[CONTROL_RELATION].relation_changed,
                            self._on_peers_changed)

    def _on_start(self, event: ops.StartEvent):
        self.unit.status = ops.ActiveStatus()

    def _on_peers_changed(self, event: ops.RelationChangedEvent):
        if self.unit.is_leader():
            self._handle_mirror(CONTROL_RELATION)

    def _on_leader_elected(self, event: ops.RelationChangedEvent):
        if not (relation := self.model.get_relation(CONTROL_RELATION)):
            return

        if self.unit.is_leader():
            relation.data[self.unit]["mirror"]="up"
        elif relation.data[self.unit].get("mirror"):
            relation.data[self.unit]["mirror"]="down"

if __name__ == "__main__":  # pragma: nocover
    ops.main(TokenDistributor)
