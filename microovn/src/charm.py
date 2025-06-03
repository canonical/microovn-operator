#!/usr/bin/env python3
import logging, ops, os

logger = logging.getLogger(__name__)
WORKER_RELATION = "cluster"
MIRROR_PREFIX = "mirror-"

def get_hostname():
    return os.uname().nodename

def mirrorid(hostname):
    return MIRROR_PREFIX + hostname

class MicroovnCharm(ops.CharmBase):
    _stored = ops.StoredState()

    def update_tokens(self, relation_name):
        if not (relation := self.model.get_relation(relation_name)):
            return False

        relation_data = relation.data
        if "mirror" not in relation_data[self.unit]:
            relation_data[self.unit]["mirror"] = "up"

        distributor_mirrors = {
            unit
            for unit in relation.units
            if (mirror := relation_data[unit].get("mirror")) and mirror == "up"
        }

        if len(distributor_mirrors) != 1:
            return False

        (distributor_unit, ) = distributor_mirrors
        distributor_mirror = relation_data[distributor_unit]
        newToken = False

        # found token distributor leader
        for mirror_key in distributor_mirror.keys():
            if MIRROR_PREFIX not in mirror_key:
                continue
            hostname = mirror_key[len(MIRROR_PREFIX):]

            # skip if token generated
            if distributor_mirror[mirror_key] != "empty" or \
               mirror_key in relation_data[self.unit]:
                continue

            #generate token and add to this side of mirror
            token = os.popen(
                    "microovn cluster add {}".format(hostname)).read()
            token = token.strip()
            relation_data[self.unit][mirror_key] = token
            logger.info("added token for {}".format(hostname))
            newToken=True

        return newToken

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(in_cluster=False)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.remove, self._on_remove)
        framework.observe(self.on.leader_elected , self._on_leader_elected)
        framework.observe(self.on[WORKER_RELATION].relation_changed,
                            self._on_cluster_changed)
        framework.observe(self.on[WORKER_RELATION].relation_created,
                            self._handle_relation_created)


    def add_hostname(self, relation_name):
        relation = self.model.get_relation(relation_name)
        relation.data[self.unit]["hostname"] = get_hostname()

    def find_token(self, relation_name):
        if not (relation := self.model.get_relation(relation_name)):
            return False

        tokens = {
            token
            for unit in relation.units
            if (token := relation.data[unit].get(mirrorid(get_hostname()))) and \
            token != "empty"
        }
        if len(tokens) > 1:
            self.unit.status = ops.MaintenanceStatus("Too many tokens")
            return False
        if len(tokens) == 0:
            self.unit.status = ops.MaintenanceStatus("No token yet")
            return False

        logger.info("found token")
        (token, ) = tokens
        return token

    def join_with_token(self, token):
        self.unit.status = ops.MaintenanceStatus("Joining cluster")
        os.system("microovn cluster join {}".format(token))
        self._stored.in_cluster=True
        self.unit.status = ops.ActiveStatus("Joined cluster")

    def _on_install(self, event: ops.InstallEvent):
        self.unit.status = ops.MaintenanceStatus("installing microovn snap")
        os.system("snap install microovn --channel latest/edge")
        self.unit.status = ops.MaintenanceStatus("waiting for microovn ready")
        os.system("microovn waitready")
        self.unit.status = ops.MaintenanceStatus("waiting for cluster setup")

    def _on_start(self, event: ops.StartEvent):
        if self.unit.is_leader():
            # only bootstrap if leader
            # TODO: fix cluster bootstrapped, leader changes to new node not in
            #       cluster, bootstrapps new cluster can be fixed via having some
            #       other characteristic determine who manages this side of the
            #       mirror ie: microcluster leader
            os.system(f"microovn cluster bootstrap")
            self._stored.in_cluster = True
            self.unit.status = ops.ActiveStatus("cluster bootstrapped")

    def _handle_relation_created(self, event: ops.RelationCreatedEvent):
        self.add_hostname(WORKER_RELATION)
        if self.unit.is_leader():
            self.update_tokens(WORKER_RELATION)

    def _on_remove(self, event: ops.RemoveEvent):
        if self._stored.in_cluster:
            os.system("microovn cluster remove {}".format(get_hostname()))

    def _handle_relation_joined(self, relation_name):
        if not self.unit.is_leader() or not self._stored.in_cluster:
            return False

        return self.update_tokens(relation_name)

    def _on_leader_elected(self, event: ops.RelationChangedEvent):
        if not (relation := self.model.get_relation(WORKER_RELATION)):
            return

        if self.unit.is_leader():
            relation.data[self.unit]["mirror"]="up"
        elif relation.data[self.unit].get("mirror"):
            relation.data[self.unit]["mirror"]="down"

    def _on_cluster_changed(self, event: ops.RelationChangedEvent):
        if not self._stored.in_cluster:
            if (token := self.find_token(WORKER_RELATION)):
                self.join_with_token(token)

        self._handle_relation_joined(WORKER_RELATION)

if __name__ == "__main__":  # pragma: nocover
    ops.main(MicroovnCharm)
