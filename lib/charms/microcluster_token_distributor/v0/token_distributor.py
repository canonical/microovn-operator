"""Microcluster token distributor library.

This is a library for the microcluster-token-distributor operator charm and
charms that aim to integrate with it. It allows for distribution generation and
usage of tokens using the token distributor units as a sort of mirror for key
data that the units of the actual microcluster charm expose allowing
communication without the usage of the peer relation.
"""

import json
import logging
import os
import subprocess
import time
from collections import Counter

import ops

# The unique Charmhub library identifier, never change it
LIBID = "ec674038842544928b4e21ee6e199666"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)

MIRROR_PREFIX = "mirror-"
EMPTY_STRING = "empty"


def mirror_id(hostname):
    """Return the mirror id for the specified hostname.

    :return: the mirror id for the specified hostname
    """
    return "{0}{1}".format(MIRROR_PREFIX, hostname)


def get_hostname():
    """Return the hostname."""
    return os.uname().nodename


def corroborate(items: list, default=""):
    """Return the most frequent value in a list.

    Iterate through the list finding the most frequent value, while ignoring
    default. However if no non-default values are found return default.

    NOTE: In the event of two non default values with equal frequency we return
    the first one, this is not ideal however, it is also not a use case that
    should come up when using token distributor
    """
    if len(items) == 0:
        return default
    if len(items) == 1:
        return items[0]
    try:
        return Counter([item for item in items if item != default]).most_common(1)[0][0]
    except IndexError:
        return default


class TokenDistributorProvides(ops.framework.Object):
    """Token Distributor Provider class.

    The provides side of the token distributor library.
    It exposes the hostnames found in the connected cluster and copies any data
    put up to be mirrored (typically tokens) in the leader units mirror for
    consumption by units in the connected cluster.
    """

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
    ):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

        self.framework.observe(self.charm.on.leader_elected, self._on_leader_elected)
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_token_relation_changed
        )

    def _handle_mirror(self, relation):
        relation_data = relation.data
        relation_data[self.charm.unit]["mirror"] = "up"
        for unit in relation.units:
            if relation_data[unit].get("mirror") == "up":
                # add all tokens in the other side of the mirror to this side
                for k, v in relation_data[unit].items():
                    if MIRROR_PREFIX in k:
                        relation_data[self.charm.unit][k] = v

            if "hostname" not in relation_data[unit]:
                continue
            mirror_key = mirror_id(relation_data[unit]["hostname"])
            if mirror_key not in relation_data[self.charm.unit]:
                logger.info("added {0} to mirror".format(mirror_key))
                relation_data[self.charm.unit][mirror_key] = EMPTY_STRING

    def _on_token_relation_changed(self, event: ops.RelationChangedEvent):
        if self.charm.unit.is_leader():
            self._handle_mirror(event.relation)

    def _on_leader_elected(self, _: ops.RelationChangedEvent):
        if relation := self.charm.model.get_relation(self.relation_name):
            if self.charm.unit.is_leader():
                relation.data[self.charm.unit]["mirror"] = "up"
                self._handle_mirror(relation)
            elif relation.data[self.charm.unit].get("mirror"):
                relation.data[self.charm.unit]["mirror"] = "down"


class ClusterBootstrappedEvent(ops.EventBase):
    """Event for when this unit bootstraps the cluster."""

    pass


class TokenGeneratedEvent(ops.EventBase):
    """Event for when a token is generated for a unit."""

    pass


class ClusterJoinedEvent(ops.EventBase):
    """Event for when a the unit joins the cluster.

    bootstrapper: True if the unit bootstrapped the cluster
    """

    def __init__(self, handle: ops.Handle, bootstrapper: bool):
        super().__init__(handle)
        self.bootstrapper = bootstrapper


class TokenConsumerEvents(ops.ObjectEvents):
    """Events class for `on`."""

    bootstrapped = ops.EventSource(ClusterBootstrappedEvent)
    token_generated = ops.EventSource(TokenGeneratedEvent)
    joined = ops.EventSource(ClusterJoinedEvent)


class TokenConsumer(ops.framework.Object):
    """Token Consumer class.

    This uses the token distributor relation as a mirror to get information about
    the cluster such as hostnames that need tokens generated. It then generates
    neccicary tokens, which are then consumed by the respective units
    allowing easy cluster management.
    """

    on = TokenConsumerEvents()
    _stored = ops.framework.StoredState()

    def _call_cluster_command(self, *args) -> (int, str):
        result = subprocess.run(
            self.command_name + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.returncode, result.stdout

    def _to_mirror_key(self, key: str) -> str:
        """Take a key and append it to the mirror prefix, returning that.

        Take a key and return a key of the form mirror-<key>, such that the
        other side of the mirror recognises it as data to be mirrored and
        therefore mirrors it.
        """
        return "{0}{1}".format(MIRROR_PREFIX, key)

    def add_to_mirror(self, relation: ops.Relation, data: dict[str, str]):
        """Add data into the units databag in a mirrorable form."""
        for k, v in data.items():
            relation.data[self.charm.unit][self._to_mirror_key(k)] = v

    def find_value(self, relation: ops.Relation, key: str, keep_empty=True) -> bool | str:
        """Find corresponding value in mirror.

        Return false if value not found, if keep_empty is enabled 'empty' an
        empty value will be accepted.
        """
        values = [
            value
            for mirror in self.find_mirrors(relation)
            if (value := relation.data[mirror].get(self._to_mirror_key(key)))
            and (keep_empty or value != EMPTY_STRING)
        ]

        if len(values) == 0:
            return False

        return corroborate(values, default=EMPTY_STRING)

    def any_data_exists(self, relation: ops.Relation) -> bool:
        """Check if there is any non empty value on the remote side of the mirror."""
        for unit in relation.units:
            for k in relation.data[unit].keys():
                if k.startswith(MIRROR_PREFIX) and relation.data[unit][k] != EMPTY_STRING:
                    return True
        return False

    def find_mirrors(self, relation: ops.Relation) -> list[ops.Unit]:
        """Find all remote mirror units."""
        relation_data = relation.data
        distributor_mirrors = [
            unit
            for unit in relation.units
            if (mirror := relation_data[unit].get("mirror")) and mirror == "up"
        ]
        return distributor_mirrors

    def get_relevant_mirror_data(self, relation: ops.Relation, keep_empty=True) -> dict[str, str]:
        """Return data in the mirror, where the key is of the form mirror-key.

        Return a dictionary of the relevant data in the mirror, with the mirror
        prefix stripped from the key.
        If keep_empty is true treat a value of empty as a valid value.
        """
        relation_data = relation.data
        data = {}
        for mirror in self.find_mirrors(relation):
            mirror_data = relation_data[mirror]
            for mirror_key in mirror_data.keys():
                if not mirror_key.startswith(MIRROR_PREFIX):
                    continue
                if (not keep_empty) and mirror_data[mirror_key] == EMPTY_STRING:
                    continue

                key = mirror_key[len(MIRROR_PREFIX) :]
                # create list in case it exists multiple times
                if key in data:
                    data[key].append(mirror_data[mirror_key])
                else:
                    data[key] = [mirror_data[mirror_key]]

        for key in data.keys():
            data[key] = corroborate(data[key], default=EMPTY_STRING)

        return data

    def _update_tokens(self, relation: ops.Relation) -> bool:
        """Generate tokens for keys with empty values.

        This will generate tokens for any relevant data with the value
        EMPTY_STRING however discerning a hostname from a key without just
        checking if its of the standard machine charm unit hostname format is
        awkward.
        """
        mirror_data = self.get_relevant_mirror_data(relation, keep_empty=True)
        if len(mirror_data) == 0:
            return False

        new_token = False
        # found token distributor leader
        for key, value in mirror_data.items():
            # skip if token generated
            if value != EMPTY_STRING or self._to_mirror_key(key) in relation.data[self.charm.unit]:
                continue

            # generate token and add to this side of mirror
            error, token = self._call_cluster_command("add", key)
            if not error:
                token = token.strip()
                self.add_to_mirror(relation, {key: token})
                self.on.token_generated.emit()
                logger.info("added token for {0}".format(key))
                new_token = True
            else:
                logger.info(
                    "generate token for {0} with code {1} and stdout {2}".format(key, error, token)
                )

        return new_token

    def __init__(self, charm: ops.CharmBase, relation_name: str, command_name: list):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.command_name = command_name
        self.relation_name = relation_name
        self._stored.set_default(in_cluster=False)

        self.framework.observe(self.charm.on.install, self._on_install)
        self.framework.observe(self.charm.on.remove, self._on_remove)
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_cluster_changed
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_created, self._handle_relation_created
        )

        def default_return_list():
            return []

        self.join_args_func = default_return_list
        self.bootstrap_args_func = default_return_list

    def _wait_for_pending(self) -> bool:
        previous_status = self.charm.unit.status
        self.charm.unit.status = ops.WaitingStatus("Waiting on pending nodes")
        pending_nodes = True
        while pending_nodes:
            pending_nodes = False
            error, output = self._call_cluster_command("list", "-f", "json")
            if error:
                logger.error(
                    "{0} calling cluster list failed with code {1}".format(get_hostname(), error)
                )
                return False
            json_output = json.loads(output)
            for x in json_output:
                if x["role"] == "PENDING":
                    pending_nodes = True
                    time.sleep(1)
                    break
        self.charm.unit.status = previous_status
        return True

    def _handle_mirror(self, relation: ops.Relation) -> bool:
        self._update_mirror_state(relation.data)
        if self.__is_communicator_node():
            return self._update_tokens(relation)

    def __is_communicator_node(self) -> bool:
        # needs to be in cluster and the pending wait must succeed
        if not self._stored.in_cluster or not self._wait_for_pending():
            return False
        error, output = self._call_cluster_command("list", "-f", "json")
        if error:
            logger.error(
                "{0} calling cluster list failed with code {1}".format(get_hostname(), error)
            )
            return False
        json_output = json.loads(output)
        # get nodenames for online voters
        voter_names = [
            x["name"] for x in json_output if (x["role"] in "voter") and (x["status"] == "ONLINE")
        ]
        # return True if there are names and its the lowest name
        return (len(voter_names) > 0) and (get_hostname() == min(voter_names))

    def _update_mirror_state(
        self, relation_data: dict[ops.Unit | ops.Application, dict[str, str]]
    ):
        logger.info("updating mirror status")
        if self.__is_communicator_node():
            relation_data[self.charm.unit]["mirror"] = "up"
        elif relation_data[self.charm.unit].get("mirror"):
            relation_data[self.charm.unit]["mirror"] = "down"

    def _join_with_token(self, token: str) -> bool:
        self.charm.unit.status = ops.MaintenanceStatus("Joining cluster")
        error, _ = self._call_cluster_command("join", token, *self.join_args_func())
        if error:
            return False
        self._stored.in_cluster = True
        self.charm.unit.status = ops.ActiveStatus("Joined cluster")
        self.on.joined.emit(bootstrapper=False)
        return True

    def _add_hostname(self, relation: ops.Relation):
        relation.data[self.charm.unit]["hostname"] = get_hostname()

    def _on_install(self, event: ops.InstallEvent):
        if not self.charm.model.get_relation(self.relation_name):
            self.charm.unit.status = ops.MaintenanceStatus("Waiting for token distrbutor relation")

    def _on_remove(self, event: ops.RemoveEvent):
        if self._stored.in_cluster:
            error, _ = self._call_cluster_command("remove", get_hostname())
            if error:
                logger.error("failed removing {0} from cluster".format(get_hostname()))

    def _on_cluster_changed(self, event: ops.RelationChangedEvent):
        if not self._stored.in_cluster:
            if token := self.find_value(event.relation, get_hostname(), keep_empty=False):
                successful = self._join_with_token(token)
                if not successful:
                    self.charm.unit.status = ops.BlockedStatus("Joining cluster failed")
                    logger.error(
                        "failed {0} joining cluster with token: {1}".format(get_hostname(), token)
                    )
                    event.defer()
                    return
            else:
                self.charm.unit.status = ops.MaintenanceStatus("Token not in mirror")

        if self._stored.in_cluster:
            self._handle_mirror(event.relation)

    def _handle_relation_created(self, event: ops.RelationCreatedEvent):
        self._add_hostname(event.relation)
        token_in_cluster = self.any_data_exists(event.relation)

        # could lead to a deadlock if a unit joins and adds data to the mirror
        # before being in the cluster
        if not self._stored.in_cluster and self.charm.unit.is_leader() and not token_in_cluster:
            error, _ = self._call_cluster_command("bootstrap", *self.bootstrap_args_func())
            if error:
                logger.error("{0} unable to bootstrap cluster".format(get_hostname()))
                self.charm.unit.status = ops.BlockedStatus("Unable to bootstrap cluster")
                event.defer()
                return
            self._stored.in_cluster = True
            self.charm.unit.status = ops.ActiveStatus("Cluster bootstrapped")
            self.on.bootstrapped.emit()
            self.on.joined.emit(bootstrapper=True)
            self._handle_mirror(event.relation)
