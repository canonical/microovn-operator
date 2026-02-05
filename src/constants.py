# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing constants."""

from charms.tls_certificates_interface.v4.tls_certificates import CertificateRequestAttributes

OVSDB_RELATION = "ovsdb"
WORKER_RELATION = "cluster"
CERTIFICATES_RELATION = "certificates"
OVSDBCMD_RELATION = "ovsdb-external"
MICROOVN_CHANNEL = "latest/edge"
DASHBOARDS_DIR = "./src/dashboards"
ALERT_RULES_DIR = "./src/alert_rules"


CSR_ATTRIBUTES = CertificateRequestAttributes(
    common_name="Charmed MicroOVN",
    is_ca=True,
)
