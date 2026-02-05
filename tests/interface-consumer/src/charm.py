#!/usr/bin/env python3
# Copyright 2025 Ubuntu
# See LICENSE file for licensing details.

import logging
import os
from pathlib import Path

import ops
from charms.microovn.v0.ovsdb import OVSDBRequires
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)

logger = logging.getLogger(__name__)
CERTIFICATES_RELATION = "certificates"
PRIVATE_KEY_NAME = "consumer.key"
CERTIFICATE_NAME = "consumer.pem"
CA_NAME = "ca.pem"
CSR_ATTRIBUTES = CertificateRequestAttributes(
    common_name="interface consumer",
    is_ca=False,
)


class InterfaceConsumerCharm(ops.CharmBase):
    ovsdb_requires = None

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.ovsdb_relation_created, self._on_ovsdb_created)
        framework.observe(self.on.ovsdb_relation_changed, self._on_ovsdb_changed)
        self.ovsdb_requires = OVSDBRequires(
            charm=self,
            relation_name="ovsdb",
        )
        self.ca_dir = Path("/root/pki")
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=CERTIFICATES_RELATION,
            certificate_requests=[CSR_ATTRIBUTES],
            mode=Mode.UNIT,
        )
        framework.observe(
            self.certificates.on.certificate_available, self._on_certificates_available
        )
        os.system("mkdir -p /root/pki")

    def _on_ovsdb_created(self, _: ops.EventBase):
        self.unit.status = ops.MaintenanceStatus("connected to ovsdb")

    def _on_ovsdb_changed(self, event: ops.RelationChangedEvent):
        if self.ovsdb_requires.get_connection_strings():
            self.unit.status = ops.ActiveStatus("got string")

    def _on_certificates_available(self, _: ops.EventBase):
        provider_certificate, private_key = self.certificates.get_assigned_certificate(
            certificate_request=CSR_ATTRIBUTES
        )
        if not provider_certificate or not private_key:
            logger.debug("Certificate or private key is not available")
            return
        cert_updated = self._store_certificate(certificate=provider_certificate.certificate)
        ca_updated = self._store_ca(certificate=provider_certificate.ca)
        key_updated = self._store_private_key(private_key=private_key)
        return key_updated or cert_updated or ca_updated

    def _store_ca(self, certificate: Certificate) -> bool:
        """Store ca certificate in workload."""
        with open(self.ca_dir / CA_NAME, "w") as cert_file:
            cert_file.write(str(certificate))
        logger.info("Pushed CA certificate pushed to workload")
        return True

    def _store_certificate(self, certificate: Certificate) -> bool:
        """Store certificate in workload."""
        with open(self.ca_dir / CERTIFICATE_NAME, "w") as cert_file:
            cert_file.write(str(certificate))
        logger.info("Pushed certificate pushed to workload")
        return True

    def _store_private_key(self, private_key: PrivateKey) -> bool:
        with open(self.ca_dir / PRIVATE_KEY_NAME, "w") as key_file:
            key_file.write(str(private_key))
        logger.info("Pushed private key to workload")
        return True


if __name__ == "__main__":  # pragma: nocover
    ops.main(InterfaceConsumerCharm)
