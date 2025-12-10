#!/usr/bin/env python3

"""Microovn Charm.

This charm provides logic for managing a microovn cluster and any relations with
other charms it may need
"""

import logging
import subprocess
import time

import ops
from charms.microcluster_token_distributor.v0.token_distributor import TokenConsumer
from charms.microovn.v0.ovsdb import OVSDBProvides
from charms.ovn_central_k8s.v0.ovsdb import OVSDBCMSRequires
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)

logger = logging.getLogger(__name__)
OVSDB_RELATION = "ovsdb"
WORKER_RELATION = "cluster"
CERTIFICATES_RELATION = "certificates"
OVSDBCMD_RELATION = "ovsdb-external"
MICROOVN_CHANNEL = "25.03/stable"

CSR_ATTRIBUTES = CertificateRequestAttributes(
    common_name="Charmed MicroOVN",
    is_ca=True,
)


def call_microovn_command(*args, stdin=None):
    """Call the command microovn with the given arguments."""
    result = subprocess.run(
        ["microovn", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        input=stdin,
        text=True,
    )
    return result.returncode, result.stdout


class MicroovnCharm(ops.CharmBase):
    """The implementation of the majority of the charms logic."""

    ovsdb_provides = None

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
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

        self.token_consumer = TokenConsumer(
            charm=self, relation_name=WORKER_RELATION, command_name=["microovn", "cluster"]
        )

        self.ovsdbcms_requires = OVSDBCMSRequires(
            charm=self,
            relation_name=OVSDBCMD_RELATION,
            external_connectivity=True,
        )

        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on[WORKER_RELATION].relation_changed, self._on_cluster_changed)
        framework.observe(self.on.update_status, self._update_status)

        framework.observe(
            self.certificates.on.certificate_available, self._on_certificates_available
        )
        framework.observe(self.ovsdbcms_requires.on.ready, self._on_ovsdbcms_ready)
        framework.observe(self.ovsdbcms_requires.on.goneaway, self._on_ovsdbcms_broken)

    def _set_central_ips_config(self):
        address = self.ovsdbcms_requires.loadbalancer_address()
        if not address:
            # Note(gboutry): This should not happen as caller is calling `remote_ready` first
            logger.error("No loadbalancer address provided by ovsdb-cms")
            return False
        err, _ = call_microovn_command("config", "set", "ovn.central-ips", address)
        if err:
            logger.error("calling config set failed with code {0}".format(err))
            return False
        return True

    def _dataplane_mode(self):
        if (
            not self.token_consumer._stored.in_cluster
            or not self.model.get_relation(OVSDBCMD_RELATION)
            or not self.ovsdbcms_requires.remote_ready()
        ):
            logger.debug(
                (
                    "not going into dataplane mode, one of these is false in_cluster: "
                    "{0}, relation_exists: {1}, remote_ready: {2}"
                ).format(
                    self.token_consumer._stored.in_cluster,
                    self.model.get_relation(OVSDBCMD_RELATION),
                    self.ovsdbcms_requires.remote_ready(),
                )
            )
            return False

        self.unit.status = ops.MaintenanceStatus("switching to dataplane mode")
        err, output = call_microovn_command("disable", "central", "--allow-disable-last-central")
        if err:
            if "this service is not enabled" in output:
                logger.debug("central service already disabled")
            else:
                logger.error(
                    "disabling central failed with error code: {0} and output: {1}".format(
                        err, output
                    )
                )
        if self.unit.is_leader():
            if not self._set_central_ips_config():
                self.unit.status = ops.MaintenanceStatus("failed switching to dataplane mode")
                return False
        self.unit.status = ops.ActiveStatus()
        return True

    def _microovn_central_exists(self):
        if not self.token_consumer._stored.in_cluster:
            return False
        err, output = call_microovn_command("status")
        if err:
            logger.error("microovn status failed with error code {0}".format(err))
            raise RuntimeError(
                "microovn status failed with error code {0} and stdout {1}".format(err, output)
            )
        return "central" in output

    def _update_status(self, _: ops.EventBase):
        if (
            self.token_consumer._stored.in_cluster
            and not self.model.get_relation(OVSDBCMD_RELATION)
            and not self._microovn_central_exists()
        ):
            self.unit.status = ops.BlockedStatus(
                "microovn has no central nodes, this could either be due to a "
                + "recently broken ovsdb-cms relation or a configuration issue"
            )

    def _on_ovsdbcms_broken(self, _: ops.EventBase):
        err, output = call_microovn_command("config", "delete", "ovn.central-ips")
        self._update_status(None)
        if err:
            logger.error("microovn config delete failed with error code {0}".format(err))

    def _on_ovsdbcms_ready(self, _: ops.EventBase):
        self._dataplane_mode()

    def _on_certificates_available(self, event: ops.EventBase):
        """Check if the certificate or private key needs an update and perform the update.

        This method retrieves the currently assigned certificate and private key associated with
        the charm's TLS relation. It checks whether the certificate or private key has changed
        or needs to be updated. If an update is necessary, the new certificate or private key is
        stored.
        """
        if not self.token_consumer._stored.in_cluster:
            event.defer()
            return False

        provider_certificate, private_key = self.certificates.get_assigned_certificate(
            certificate_request=CSR_ATTRIBUTES
        )
        if not provider_certificate or not private_key:
            logger.debug("Certificate or private key is not available")
            return False
        combined_cert = str(provider_certificate.certificate) + "\n" + str(provider_certificate.ca)
        combined_input = combined_cert + "\n" + str(private_key)
        err, output = call_microovn_command(
            "certificates", "set-ca", "--combined", stdin=combined_input
        )
        if err:
            logger.error("microovn certificates set-ca failed with error code {0}".format(err))
            raise RuntimeError("Updating certificates failed with error code {0}".format(err))
        if "New CA certificate: Issued" in output:
            logger.info("CA certificate updated, new certificates issued")
            return True

        return False

    def _on_install(self, event: ops.InstallEvent):
        self.unit.status = ops.MaintenanceStatus("Installing microovn snap")
        while retries := 3:
            try:
                subprocess.run(["snap", "wait", "system", "seed.loaded"], check=True)
                subprocess.run(
                    ["snap", "install", "microovn", "--channel", MICROOVN_CHANNEL], check=True
                )
                break
            except subprocess.CalledProcessError as e:
                if retries:
                    retries -= 1
                    self.unit.status = ops.MaintenanceStatus(
                        f"Snap install failed, {retries} retries left"
                    )
                    time.sleep(1)
                    continue
                raise e

        self.unit.status = ops.MaintenanceStatus("Waiting for microovn ready")
        retries = 0
        while code := call_microovn_command("waitready")[0]:
            retries += 1
            if retries > 3:
                logger.error("microovn waitready failed with error code {0}".format(code))
                raise RuntimeError("microovn waitready failed 3 times")
            self.unit.status = ops.MaintenanceStatus(
                "Microovn waitready failed, retry {0}".format(retries)
            )
            time.sleep(1)

    def _on_cluster_changed(self, event: ops.RelationChangedEvent):
        if self.token_consumer._stored.in_cluster:
            self.ovsdb_provides.update_relation_data()
            self._dataplane_mode()


if __name__ == "__main__":  # pragma: nocover
    ops.main(MicroovnCharm)
