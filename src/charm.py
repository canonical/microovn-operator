#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Microovn Charm.

This charm provides logic for managing a microovn cluster and any relations with
other charms it may need
"""

import logging
import socket
from functools import cached_property

import ops
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.microcluster_token_distributor.v0.token_distributor import TokenConsumer
from charms.microovn.v0.ovsdb import CERT_UPDATE_KEY, OVSDBProvides
from charms.ovn_central_k8s.v0.ovsdb import OVSDBCMSRequires
from charms.tls_certificates_interface.v4.tls_certificates import Mode, TLSCertificatesRequiresV4

from constants import (
    ALERT_RULES_DIR,
    CERTIFICATES_RELATION,
    CSR_ATTRIBUTES,
    DASHBOARDS_DIR,
    MICROOVN_CHANNEL,
    OVN_EXPORTER_CHANNEL,
    OVN_EXPORTER_METRICS_ENDPOINT,
    OVN_EXPORTER_METRICS_PATH,
    OVN_EXPORTER_PLUGS,
    OVN_EXPORTER_PORT,
    OVSDB_RELATION,
    OVSDBCMD_RELATION,
    WORKER_RELATION,
)
from snap_manager import SnapManager
from utils import (
    call_microovn_command,
    check_metrics_endpoint,
    microovn_central_exists,
    wait_for_microovn_ready,
)

logger = logging.getLogger(__name__)


class MicroovnCharm(ops.CharmBase):
    """The implementation of the majority of the charms logic."""

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

        self.cos = COSAgentProvider(
            self,
            scrape_configs=[
                {
                    "metrics_path": OVN_EXPORTER_METRICS_PATH,
                    "static_configs": [
                        {
                            "targets": [f"localhost:{OVN_EXPORTER_PORT}"],
                            "labels": {"instance": socket.getfqdn()},
                        }
                    ],
                }
            ],
            metrics_rules_dir=ALERT_RULES_DIR,
            dashboard_dirs=[DASHBOARDS_DIR],
            refresh_events=[self.on.config_changed],
        )

        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on[WORKER_RELATION].relation_changed, self._on_cluster_changed)
        framework.observe(self.on.update_status, self._on_update_status)
        framework.observe(self.on.remove, self._on_remove)

        framework.observe(
            self.certificates.on.certificate_available, self._on_certificates_available
        )
        framework.observe(self.ovsdbcms_requires.on.ready, self._on_ovsdbcms_ready)
        framework.observe(self.ovsdbcms_requires.on.goneaway, self._on_ovsdbcms_broken)
        framework.observe(self.token_consumer.on.bootstrapped, self._on_bootstrapped_or_joined)
        framework.observe(self.token_consumer.on.joined, self._on_bootstrapped_or_joined)

    # PROPERTIES

    @cached_property
    def microovn_snap_client(self) -> SnapManager:  # pragma: nocover
        """Return the snap client."""
        return SnapManager("microovn", MICROOVN_CHANNEL)

    @cached_property
    def ovn_exporter_snap_client(self) -> SnapManager:  # pragma: nocover
        """Return the snap client."""
        return SnapManager("ovn-exporter", OVN_EXPORTER_CHANNEL)

    @property
    def is_in_cluster(self) -> bool:
        """Return whether the unit is in a microovn cluster."""
        return self.token_consumer._stored.in_cluster

    @property
    def has_ovsdbcmd_relation(self) -> bool:
        """Return whether the ovsdb relation exists."""
        return self.model.get_relation(OVSDBCMD_RELATION) is not None

    # HANDLERS

    def _on_update_status(self, _: ops.EventBase) -> None:
        """Update the unit status."""
        if not self.is_in_cluster:
            self.unit.status = ops.BlockedStatus(
                "Not in cluster. Waiting for token distrbutor relation"
            )
            return

        if self.is_in_cluster and not self.has_ovsdbcmd_relation and not microovn_central_exists():
            self.unit.status = ops.BlockedStatus(
                (
                    "microovn has no central nodes, this could either be due to a "
                    "recently broken ovsdb-cms relation or a configuration issue"
                )
            )
            return

        if self.is_in_cluster and not check_metrics_endpoint(OVN_EXPORTER_METRICS_ENDPOINT):
            self.unit.status = ops.BlockedStatus(
                "ovn-exporter metrics endpoint is not responding, check snap service status"
            )
            return

        self.unit.status = ops.ActiveStatus()

    def _on_ovsdbcms_broken(self, event: ops.EventBase) -> None:
        """Handle the ovsdb-cms goneaway event."""
        res = call_microovn_command("config", "delete", "ovn.central-ips")
        if res.returncode != 0:
            logger.error(
                "microovn config delete failed with error code %s, stderr: %s",
                res.returncode,
                res.stderr,
            )

        self._on_update_status(event)

    def _on_ovsdbcms_ready(self, event: ops.EventBase) -> None:
        """Handle the ovsdb-cms ready event."""
        self.unit.status = ops.MaintenanceStatus("Checking dataplane mode")
        if not self._dataplane_mode():
            logger.error("Failed to switch to dataplane mode on ovsdb-cms ready")
            self.unit.status = ops.BlockedStatus("Failed to switch to dataplane mode")
            return

        self._on_update_status(event)

    def _on_certificates_available(self, event: ops.EventBase) -> None:
        """Check if the certificate or private key needs an update and perform the update.

        This method retrieves the currently assigned certificate and private key associated with
        the charm's TLS relation. It checks whether the certificate or private key has changed
        or needs to be updated. If an update is necessary, the new certificate or private key is
        stored.
        """
        if not self.is_in_cluster:
            logger.info("Not in cluster, deferring certificate update")
            event.defer()
            return

        provider_certificate, private_key = self.certificates.get_assigned_certificate(
            certificate_request=CSR_ATTRIBUTES
        )

        if not provider_certificate or not private_key:
            logger.info("Certificate or private key is not available")
            return

        combined_cert = str(provider_certificate.certificate) + "\n" + str(provider_certificate.ca)
        combined_input = combined_cert + "\n" + str(private_key)
        res = call_microovn_command("certificates", "set-ca", "--combined", stdin=combined_input)

        if res.returncode != 0:
            logger.error(
                "microovn certificates set-ca failed with error code %s, stderr: %s",
                res.returncode,
                res.stderr,
            )
            raise RuntimeError(f"Updating certificates failed with error code {res.returncode}")

        if "New CA certificate: Issued" in res.stdout:
            logger.info("CA certificate updated, new certificates issued")
            relation = self.model.get_relation(self.token_consumer.relation_name)
            self.token_consumer.add_to_mirror(relation, {CERT_UPDATE_KEY: "done"})

    def _on_install(self, event: ops.EventBase) -> None:
        """Handle the install event."""
        snaps = [self.ovn_exporter_snap_client, self.microovn_snap_client]

        for snap in snaps:
            self.unit.status = ops.MaintenanceStatus(f"Installing {snap.name} snap")
            if not snap.install():
                logger.error("Failed to install %s snap", snap.name)
                raise RuntimeError(f"Failed to install {snap.name} snap")

        # Stop the services until microovn is bootstrapped
        self.ovn_exporter_snap_client.disable_and_stop()
        if not self.ovn_exporter_snap_client.connect(OVN_EXPORTER_PLUGS):
            logger.error("Failed to connect ovn-exporter snap interfaces")
            raise RuntimeError("Failed to connect ovn-exporter snap interfaces")

        self.unit.status = ops.MaintenanceStatus("Waiting for microovn ready")
        if not wait_for_microovn_ready():
            logger.error("microovn waitready failed after retries")
            raise RuntimeError("microovn waitready failed after retries")
        self.unit.status = ops.MaintenanceStatus("Waiting for cluster bootstrap")

        self._on_update_status(event)

    def _on_cluster_changed(self, event: ops.EventBase) -> None:
        """Handle changes in the cluster relation."""
        if self.is_in_cluster:
            self.ovsdb_provides.update_relation_data()
            self.unit.status = ops.MaintenanceStatus("Checking dataplane mode")
            if not self._dataplane_mode():
                logger.error("Failed to switch to dataplane mode on cluster changed")
                self.unit.status = ops.BlockedStatus("Failed to switch to dataplane mode")
                return

        self._on_update_status(event)

    def _on_remove(self, _: ops.EventBase) -> None:
        """Handle the remove event."""
        self.unit.status = ops.MaintenanceStatus("Cleanup")
        snaps = [self.ovn_exporter_snap_client, self.microovn_snap_client]

        for snap in snaps:
            self.unit.status = ops.MaintenanceStatus(f"Removing {snap.name} snap")
            if not snap.remove():
                logger.error("Remove failed for %s", snap.name)
                raise RuntimeError(f"Failed to remove {snap.name} snap")

    def _on_bootstrapped_or_joined(self, _: ops.EventBase):
        """Handle bootstrapped event."""
        logger.info("microovn cluster was bootstrapped or joined, enabling the exporter")
        self.ovn_exporter_snap_client.enable_and_start()

    # HELPERS

    def _set_central_ips_config(self) -> bool:
        """Set the ovn.central-ips config in microovn."""
        address = self.ovsdbcms_requires.loadbalancer_address()
        if not address:
            # Note(gboutry): This should not happen as caller is calling `remote_ready` first
            logger.error("No loadbalancer address provided by ovsdb-cms")
            return False
        res = call_microovn_command("config", "set", "ovn.central-ips", address)
        if res.returncode != 0:
            logger.error(
                "Calling config set failed with code %s, stderr: %s", res.returncode, res.stderr
            )
            return False
        return True

    def _dataplane_mode(self) -> bool:
        """Try to switch microovn to dataplane mode."""
        logger.info("Checking dataplane mode")
        remote_ready = self.ovsdbcms_requires.remote_ready()

        if not self.is_in_cluster or not self.has_ovsdbcmd_relation or not remote_ready:
            logger.info(
                "Not going into dataplane mode, one of these is false in_cluster: "
                "%s, relation_exists: %s, remote_ready: %s",
                self.is_in_cluster,
                self.has_ovsdbcmd_relation,
                remote_ready,
            )
            return True

        res = call_microovn_command("disable", "central", "--allow-disable-last-central")
        if res.returncode != 0:
            if "this service is not enabled" in res.stdout:
                logger.info("Central service already disabled")
                return True
            else:
                logger.error(
                    "Disabling central failed with error code %s, stderr: %s",
                    res.returncode,
                    res.stderr,
                )
                raise RuntimeError(f"Disabling central failed with error code {res.returncode}")
        if self.unit.is_leader():
            if not self._set_central_ips_config():
                return False

        logger.info("Successfully switched to dataplane mode")
        return True


if __name__ == "__main__":  # pragma: nocover
    ops.main(MicroovnCharm)
