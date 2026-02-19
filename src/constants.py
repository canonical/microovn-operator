# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing constants."""

from typing import List, Tuple

from charms.tls_certificates_interface.v4.tls_certificates import CertificateRequestAttributes

OVSDB_RELATION = "ovsdb"
WORKER_RELATION = "cluster"
CERTIFICATES_RELATION = "certificates"
OVSDBCMD_RELATION = "ovsdb-external"
MICROOVN_CHANNEL = "latest/edge"
DASHBOARDS_DIR = "./src/dashboards"
ALERT_RULES_DIR = "./src/prometheus_alert_rules"
OVN_EXPORTER_METRICS_PATH = "/metrics"
OVN_EXPORTER_PORT = 9310
OVN_EXPORTER_CHANNEL = "latest/edge"

OVN_EXPORTER_PLUGS: List[Tuple[str, str | None]] = [
    ("ovn-chassis", "microovn:ovn-chassis"),
    ("ovn-central-data", "microovn:ovn-central-data"),
]

OVN_EXPORTER_METRICS_ENDPOINT = f"http://localhost:{OVN_EXPORTER_PORT}{OVN_EXPORTER_METRICS_PATH}"


CSR_ATTRIBUTES = CertificateRequestAttributes(
    common_name="Charmed MicroOVN",
    is_ca=True,
)
