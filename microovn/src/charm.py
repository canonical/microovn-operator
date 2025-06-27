#!/usr/bin/env python3
import json
import logging
import os
import time
import subprocess
from pathlib import Path

import ops

from charms.microovn.v0.ovsdb import OVSDBProvides
from typing import Optional

from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)

logger = logging.getLogger(__name__)
OVSDB_RELATION = "ovsdb"
WORKER_RELATION = "cluster"
CERTIFICATES_RELATION = "certificates"
MIRROR_PREFIX = "mirror-"

CSR_ATTRIBUTES = CertificateRequestAttributes(
    common_name="Charmed MicroOVN",
    is_ca=True,
)

SECURE_FILE_MODE = 0o600
def secure_opener(path, flags):
    return os.open(path, flags, SECURE_FILE_MODE)

def get_hostname():
    return os.uname().nodename

def mirror_id(hostname):
    return MIRROR_PREFIX + hostname

def call_microovn_command(*args, stdin=None):
    result = subprocess.run(
        ["microovn", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        input=stdin,
        text=True
    )
    return result.returncode, result.stdout

class MicroovnCharm(ops.CharmBase):
    _stored = ops.StoredState()
    ovsdb_provides = None

    def wait_for_pending(self):
        self.unit.status = ops.WaitingStatus("Waiting on pending nodes")
        pending_nodes = True
        while pending_nodes:
            pending_nodes = False
            error, output = call_microovn_command("cluster", "list",
                                                  "-f", "json")
            if error:
                logger.error(
                    "{0} calling cluster list failed with code {1}".format(
                        get_hostname(),error))
                return False
            json_output = json.loads(output)
            for x in json_output:
                if x["role"] == "PENDING":
                    pending_nodes=True
                    time.sleep(1)
                    break
        self.unit.status = ops.ActiveStatus()
        return True

    def handle_mirror(self, relation):
        self.update_mirror_state(relation.data)
        if self.is_communicator_node():
            return self.update_tokens(relation)

    def is_communicator_node(self):
        #needs to be in cluster and the pending wait must succeed
        if not self._stored.in_cluster or not self.wait_for_pending():
            return False
        error, output = call_microovn_command("cluster", "list",
                                                "-f", "json")
        if error:
            logger.error("{0} calling cluster list failed with code {1}".format(
                    get_hostname(),error))
            return False
        json_output = json.loads(output)
        #get nodenames for online voters
        voter_names = [ x["name"] for x in json_output
                        if (x["role"] in "voter") and (x["status"] == "ONLINE") ]
        # return True if there are names and its the lowest name
        return (len(voter_names) > 0) and (get_hostname() == min(voter_names))

    def update_mirror_state(self, relation_data):
        logger.info("updating mirror status")
        if self.is_communicator_node():
            relation_data[self.unit]["mirror"]="up"
        elif relation_data[self.unit].get("mirror"):
            relation_data[self.unit]["mirror"]="down"

    def update_tokens(self, relation):
        relation_data = relation.data
        distributor_mirrors = [
            unit
            for unit in relation.units
            if (mirror := relation_data[unit].get("mirror")) and mirror == "up"
        ]

        if len(distributor_mirrors) != 1:
            return False

        distributor_mirror = relation_data[distributor_mirrors[0]]
        new_token = False

        # found token distributor leader
        for mirror_key in distributor_mirror.keys():
            if not mirror_key.startswith(MIRROR_PREFIX):
                continue

            hostname = mirror_key[len(MIRROR_PREFIX):]

            # skip if token generated
            if distributor_mirror[mirror_key] != "empty" or \
               mirror_key in relation_data[self.unit]:
                continue

            #generate token and add to this side of mirror
            error, token = call_microovn_command("cluster", "add", hostname)
            if not error:
                token = token.strip()
                relation_data[self.unit][mirror_key] = token
                logger.info("added token for {}".format(hostname))
                new_token=True

        return new_token

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(in_cluster=False)

        self.ca_dir = Path("/var/snap/microovn/common/data/pki")
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=CERTIFICATES_RELATION,
            certificate_requests=[CSR_ATTRIBUTES],
            mode=Mode.APP,
        )

        self.ovsdb_provides = OVSDBProvides(
            charm=self,
            relation_name=OVSDB_RELATION,
        )

        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.remove, self._on_remove)
        framework.observe(self.on[WORKER_RELATION].relation_changed,
                            self._on_cluster_changed)
        framework.observe(self.on[WORKER_RELATION].relation_created,
                            self._handle_relation_created)
        framework.observe(
            self.certificates.on.certificate_available, self._on_certificates_available
        )

    def _on_certificates_available(self, _: ops.EventBase):
        """Check if the certificate or private key needs an update and perform the update.

        This method retrieves the currently assigned certificate and private key associated with
        the charm's TLS relation. It checks whether the certificate or private key has changed
        or needs to be updated. If an update is necessary, the new certificate or private key is
        stored.
        """
        provider_certificate, private_key = self.certificates.get_assigned_certificate(
            certificate_request=CSR_ATTRIBUTES
        )
        if not provider_certificate or not private_key:
            logger.debug("Certificate or private key is not available")
            return
        combined_cert = str(provider_certificate.certificate) + "\n" + str(provider_certificate.ca)
        combined_input = combined_cert + "\n" + str(private_key)
        err, output = call_microovn_command("certificates", "set-ca",
                                "--combined",stdin=combined_input)
        if err:
            logger.error(
                "microovn certificates set-ca failed with error code {0}".format(code))
            raise RuntimeError(
                "Updating certificates failed with error code {0}".format(code))
        if "New CA certificate: Issued" in output:
            logger.info("CA certificate updated, new certificates issued")
            return True

        return False

    def add_hostname(self, relation_name):
        relation = self.model.get_relation(relation_name)
        relation.data[self.unit]["hostname"] = get_hostname()

    def find_token(self, relation):
        tokens = [
            token
            for unit in relation.units
            if (token := relation.data[unit].get(mirror_id(get_hostname()))) and \
            token != "empty"
        ]
        if len(tokens) > 1:
            self.unit.status = ops.MaintenanceStatus("Too many tokens")
            return False
        if len(tokens) == 0:
            self.unit.status = ops.MaintenanceStatus("No token yet")
            return False

        logger.info("found token")
        return tokens[0]

    def join_with_token(self, token):
        self.unit.status = ops.MaintenanceStatus("Joining cluster")
        error, _ = call_microovn_command("cluster", "join", token)
        if error:
            return False
        self._stored.in_cluster=True
        self.unit.status = ops.ActiveStatus("Joined cluster")
        return True

    def _on_install(self, event: ops.InstallEvent):
        self.unit.status = ops.MaintenanceStatus("Installing microovn snap")
        while retries := 3:
            try:
                subprocess.run(
                    ["snap", "wait", "system", "seed.loaded"],
                    check=True)
                subprocess.run(
                    ["snap", "install", "microovn", "--channel", "latest/edge"],
                    check=True)
                break
            except subprocess.CalledProcessError as e:
                if retries:
                    retries -= 1
                    self.unit.status = ops.MaintenanceStatus(
                        f"Snap install failed, {retries} retries left")
                    time.sleep(1)
                    continue
                raise e

        self.unit.status = ops.MaintenanceStatus("Waiting for microovn ready")
        retries = 0
        while (code := call_microovn_command("waitready")[0]):
            retries+=1
            if retries>3:
                logger.error(
                    "microovn waitready failed with error code {0}".format(code))
                raise RuntimeError("microovn waitready failed 3 times")
            self.unit.status = ops.MaintenanceStatus(
                "Microovn waitready failed, retry {0}".format(retries))
            time.sleep(1)
        if not (relation := self.model.get_relation(WORKER_RELATION)):
            self.unit.status = ops.MaintenanceStatus(
                "Waiting for token distrbutor relation")

    def any_token_exists(self, relation):
        for unit in relation.units:
            for k in relation.data[unit].keys():
                if k.startswith(MIRROR_PREFIX) and \
                   relation.data[unit][k] != "empty":
                    return True
        return False

    def _handle_relation_created(self, event: ops.RelationCreatedEvent):
        self.add_hostname(WORKER_RELATION)

        token_in_cluster = False
        if relation := self.model.get_relation(WORKER_RELATION):
            token_in_cluster = self.any_token_exists(relation)

        if not self._stored.in_cluster and self.unit.is_leader() and \
           not token_in_cluster:
            error, _ = call_microovn_command("cluster", "bootstrap")
            if error:
                logger.error("{0} unable to bootstrap cluster".format(
                    get_hostname()))
                self.unit.status = ops.BlockedStatus("Unable to bootstrap cluster")
                event.defer()
                return
            self._stored.in_cluster = True
            self.unit.status = ops.ActiveStatus("Cluster bootstrapped")
            self.handle_mirror(event.relation)


    def _on_remove(self, event: ops.RemoveEvent):
        if self._stored.in_cluster:
            error, _ = call_microovn_command("cluster", "remove", get_hostname())
            if error:
                logger.error("failed removing {0} from cluster".format(
                    get_hostname()))

    def _on_cluster_changed(self, event: ops.RelationChangedEvent):
        if not self._stored.in_cluster:
            if (token := self.find_token(event.relation)):
                successful = self.join_with_token(token)
                if not successful:
                    self.unit.status = ops.BlockedStatus("Joining cluster failed")
                    logger.error(
                        "failed {0} joining cluster with token: {1}".format(
                            get_hostname(),token))
                    event.defer()
                    return

        if self._stored.in_cluster:
            self.handle_mirror(event.relation)
            self.ovsdb_provides.update_relation_data()

if __name__ == "__main__":  # pragma: nocover
    ops.main(MicroovnCharm)
