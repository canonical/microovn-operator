# Security Process

# What is a vulnerability?

All vulnerabilities are bugs, but not every bug is a vulnerability.
Vulnerabilities compromise one or more of:

* Confidentiality (personal or corporate confidential data).
* Integrity (trustworthiness and correctness).
* Availability (uptime and service).

If in doubt, please use the process for [reporting a vulnerability][reporting-vulnerability],
and we will assess whether your report is in fact a security vulnerability,
or if it should be [reported as a bug][bug-report]
using the normal bug process.

# Reporting a vulnerability

To report a security issue, file a [Private Security Report][private-security-report]
with a description of the issue, the steps you took to create the issue, affected versions, and, if known,
mitigations for the issue.

The [Ubuntu Security disclosure and embargo policy][ubuntu-disclosure]
contains more information about what you can expect when you contact us and what we expect from you.

# Product lifetime

The main components of MicroOVN Operator, Open vSwitch (OVS) and Open Virtual Network
(OVN), comes from the Ubuntu distribution.

Releases of MicroOVN Operator in [charmhub][charmhub] that align with Ubuntu Long Term Support (LTS) releases,
receive the same level of support throughout the lifetime of the corresponding Ubuntu LTS release.

Please refer to the [Ubuntu lifecycle and release cadence][ubuntu-lifecycle] documentation for more information.

# Tracking vulnerabilities

Vulnerabilities, their status, and the state of the analysis or response will
all be tracked through the [Ubuntu CVE tracker][ubuntu-cve].

# Responding to vulnerabilities

Vulnerabilities are classified by [priority][cve-priority],
and the MicroOVN Operator project guarantees response to all High and Critical severity vulnerabilities,
as well as any [Known Exploited Vulnerability][known-exploited].

Security updates and will be made available to consumers of latest [charmhub][charmhub]
releases that align with supported Ubuntu Long Term Support (LTS) releases.

# Responsible disclosure

We follow the [Ubuntu Security disclosure and embargo policy][ubuntu-disclosure].

Please refer to the section on [reporting a vulnerability][reporting-vulnerability].

[reporting-vulnerability]: #reporting-a-vulnerability
[bug-report]: https://bugs.launchpad.net/microovn/+filebug
[private-security-report]: https://github.com/Canonical/microovn-operator/security/advisories/new
[ubuntu-disclosure]: https://ubuntu.com/security/disclosure-policy
[charmhub]: https://charmhub.io/microovn
[ubuntu-lifecycle]: https://ubuntu.com/about/release-cycle
[ubuntu-cve]: https://ubuntu.com/security/cves
[cve-priority]: https://ubuntu.com/security/cves/about#priority
[known-exploited]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
