#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import Path
from typing import Callable

import jubilant
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

TOKEN_DISTRIBUTOR_CHARM = "microcluster-token-distributor"
TOKEN_DISTRIBUTOR_CHANNEL = "latest/edge"
OTCOL_CHARM = "opentelemetry-collector"
OTCOL_CHANNEL = "2/stable"
SELF_SIGNED_CERTIFICATES_CHARM = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_CHANNEL = "1/stable"
OVN_CENTRAL_K8S_CHARM = "ovn-central-k8s"
OVN_CENTRAL_K8S_CHANNEL = "24.03/stable"
OVN_RELAY_K8S_CHARM = "ovn-relay-k8s"
OVN_RELAY_K8S_CHANNEL = "24.03/stable"


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(5),
    retry=retry_if_exception_type(jubilant._juju.CLIError),
    reraise=True,
)
def wait_with_retry(
    juju_env: jubilant.Juju, condition: Callable[[jubilant.Status], bool], timeout=300
):
    """Wait for all agents to be idle, with retry on CLIError."""
    juju_env.wait(condition, timeout=timeout)


def is_command_passing(juju, commandstring, unitname):
    try:
        juju.exec(commandstring, unit=unitname)
        return True
    except Exception as e:
        print(e)
        return False


def test_integrate(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    juju_lxd.deploy(charm_path, app=app_name)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)
    juju_lxd.exec("microovn status", unit=f"{app_name}/1")


def test_integrate_post_start(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    juju_lxd.deploy(charm_path)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.wait(lambda status: jubilant.all_active(status, TOKEN_DISTRIBUTOR_CHARM))
    juju_lxd.wait(lambda status: jubilant.all_maintenance(status, app_name))
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.add_unit(app_name)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)
    juju_lxd.exec("microovn status", unit=f"{app_name}/1")


def test_token_distributor_down(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    juju_lxd.deploy(charm_path)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.add_unit(app_name)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.remove_unit(f"{TOKEN_DISTRIBUTOR_CHARM}/0")
    juju_lxd.add_unit(TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.add_unit(app_name)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)
    juju_lxd.exec("microovn status", unit=f"{app_name}/2")


def test_microcluster_leader_down(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(jubilant.all_agents_idle)
    output = juju_lxd.exec("microovn cluster list -f json", unit=f"{app_name}/0").stdout
    json_output = json.loads(output)
    voter_names = [
        x["name"]
        for x in json_output
        if (x["role"] in ["voter", "PENDING"]) and (x["status"] == "ONLINE")
    ]
    voter_name = min(voter_names)
    hostname = juju_lxd.exec("hostname -s", unit=f"{app_name}/0").stdout[:-1]
    if hostname == voter_name:
        juju_lxd.remove_unit(f"{app_name}/0")
    else:
        juju_lxd.remove_unit(f"{app_name}/1")
    juju_lxd.add_unit(app_name)
    juju_lxd.wait(jubilant.all_active)


def test_integrate_ovsdb(
    juju_lxd: jubilant.Juju,
    charm_path: Path,
    interface_consumer_charm_path: Path,
    app_name: str,
    interface_consumer_app_name: str,
):
    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.deploy(SELF_SIGNED_CERTIFICATES_CHARM, channel=SELF_SIGNED_CERTIFICATES_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.integrate(app_name, SELF_SIGNED_CERTIFICATES_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.deploy(interface_consumer_charm_path, app=interface_consumer_app_name)
    juju_lxd.integrate(app_name, interface_consumer_app_name)
    juju_lxd.wait(jubilant.all_active)
    output = juju_lxd.cli(
        "show-unit", f"{interface_consumer_app_name}/0", "--format", "json", "--endpoint", "ovsdb"
    )
    json_output = json.loads(output)
    data = json_output[f"{interface_consumer_app_name}/0"]["relation-info"][0]["application-data"]
    assert data.get("db_nb_connection_str")
    assert data.get("db_sb_connection_str")


def test_certificates_integration(
    juju_lxd: jubilant.Juju,
    charm_path: Path,
    interface_consumer_charm_path: Path,
    app_name: str,
    interface_consumer_app_name: str,
):
    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.deploy(SELF_SIGNED_CERTIFICATES_CHARM, channel=SELF_SIGNED_CERTIFICATES_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.integrate(app_name, SELF_SIGNED_CERTIFICATES_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(
        lambda _: "CA certificate updated, new certificates issued" in juju_lxd.debug_log()
    )
    destination = juju_lxd.status().apps[app_name].units[f"{app_name}/1"].public_address
    destination = destination + ":6643"
    command_str = "openssl s_client -connect {0}".format(destination)
    output = juju_lxd.exec(command_str + "|| true", unit=f"{SELF_SIGNED_CERTIFICATES_CHARM}/0")
    assert "Verification: OK" not in output.stdout

    # this check is checking if the certificate chain is intact and as we expect,
    # the command will return with a nonzero exit code due to not having a actual
    # certificate and private key therefore the connection cannot be fully done,
    # causing the error. However we can still check it is as we expect.
    #
    # https://github.com/openssl/openssl/blob/2d978786f3e97a2701d5f62c26a4baab4a224e69/apps/lib/s_cb.c#L1265
    command_str = "openssl s_client -connect {0} -CAfile /tmp/ca-cert.pem || true".format(
        destination
    )
    output = juju_lxd.exec(command_str, unit=f"{SELF_SIGNED_CERTIFICATES_CHARM}/0")
    assert "Verification: OK" in output.stdout
    # this checks the full certificate chain works and will work in the standard
    # use case.
    juju_lxd.deploy(interface_consumer_charm_path, app=interface_consumer_app_name)
    juju_lxd.integrate(SELF_SIGNED_CERTIFICATES_CHARM, interface_consumer_app_name)
    juju_lxd.integrate(app_name, interface_consumer_app_name)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(
        lambda _: is_command_passing(
            juju_lxd, "ls /root/pki/consumer.pem", f"{interface_consumer_app_name}/0"
        )
    )
    command_str = (
        "openssl s_client -connect {0} "
        "-CAfile /root/pki/ca.pem "
        "-cert /root/pki/consumer.pem "
        "-key /root/pki/consumer.key "
        "-verify_return_error"
    ).format(destination)
    output = juju_lxd.exec(command_str, unit=f"{interface_consumer_app_name}/0")


def test_ovn_k8s_integration(
    juju_lxd: jubilant.Juju,
    juju_k8s: jubilant.Juju,
    charm_path: Path,
    app_name: str,
    lxd_controller_name: str,
    k8s_controller_name: str,
):
    certs_offer_name = "certs"
    cms_relay_offer_name = "cms-relay"
    lxd_model_name = juju_lxd.show_model().name
    k8s_model_name = juju_k8s.show_model().name

    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.deploy(SELF_SIGNED_CERTIFICATES_CHARM, channel=SELF_SIGNED_CERTIFICATES_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.integrate(app_name, SELF_SIGNED_CERTIFICATES_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.offer(
        f"{lxd_model_name}.{SELF_SIGNED_CERTIFICATES_CHARM}",
        endpoint="certificates",
        name=certs_offer_name,
        controller=lxd_controller_name,
    )

    # setup ovn-central-k8s and its relations
    juju_k8s.deploy(OVN_CENTRAL_K8S_CHARM, channel=OVN_CENTRAL_K8S_CHANNEL, num_units=3)
    juju_k8s.deploy(OVN_RELAY_K8S_CHARM, channel=OVN_RELAY_K8S_CHANNEL, num_units=3, trust=True)
    juju_k8s.integrate(OVN_CENTRAL_K8S_CHARM, OVN_RELAY_K8S_CHARM)
    juju_k8s.integrate(OVN_CENTRAL_K8S_CHARM, f"{juju_lxd.model}.{certs_offer_name}")
    juju_k8s.integrate(OVN_RELAY_K8S_CHARM, f"{juju_lxd.model}.{certs_offer_name}")
    wait_with_retry(juju_k8s, jubilant.all_agents_idle)

    # integrate microovn with ovn-relay-k8s
    juju_k8s.offer(
        f"{k8s_model_name}.{OVN_RELAY_K8S_CHARM}",
        endpoint="ovsdb-cms-relay",
        name=cms_relay_offer_name,
        controller=k8s_controller_name,
    )
    juju_lxd.integrate(app_name, f"{juju_k8s.model}.{cms_relay_offer_name}")
    wait_with_retry(juju_lxd, jubilant.all_active)
    wait_with_retry(juju_lxd, jubilant.all_agents_idle)
    wait_with_retry(juju_k8s, jubilant.all_active)

    # ensure microovn central is down
    output = juju_lxd.exec("microovn status", unit=f"{app_name}/0")
    assert "central" not in output.stdout
    # test ovn-sbctl still works which means its using ovn-relay-k8s
    juju_lxd.exec("microovn.ovn-sbctl --no-leader-only show", unit=f"{app_name}/0")
    output = juju_lxd.exec("microovn.ovn-sbctl --no-leader-only show", unit=f"{app_name}/1")
    assert output.stdout.count("Chassis") == 2  # We have 2 microovn units


def test_certificates_before_token_distributor(
    juju_lxd: jubilant.Juju, charm_path: Path, app_name: str
):
    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(SELF_SIGNED_CERTIFICATES_CHARM, channel=SELF_SIGNED_CERTIFICATES_CHANNEL)
    juju_lxd.integrate(app_name, SELF_SIGNED_CERTIFICATES_CHARM)
    juju_lxd.wait(lambda status: jubilant.all_active(status, SELF_SIGNED_CERTIFICATES_CHARM))
    juju_lxd.wait(lambda status: jubilant.all_blocked(status, app_name))
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.wait(jubilant.all_active)
    juju_lxd.wait(
        lambda _: "CA certificate updated, new certificates issued" in juju_lxd.debug_log()
    )
    destination = juju_lxd.status().apps[app_name].units[f"{app_name}/1"].public_address
    destination = destination + ":6643"
    command_str = "openssl s_client -connect {0} -CAfile /tmp/ca-cert.pem || true".format(
        destination
    )
    output = juju_lxd.exec(command_str, unit=f"{SELF_SIGNED_CERTIFICATES_CHARM}/0")
    assert "Verification: OK" in output.stdout


def test_cos_relation(juju_lxd: jubilant.Juju, charm_path: Path, app_name: str):
    """Test that the COS relation works correctly with Opentelemetry Collector."""
    cos_endpoint = "cos-agent"

    # deploy microovn and token-distributor to get microovn into active state
    juju_lxd.deploy(charm_path)
    juju_lxd.add_unit(app_name)
    juju_lxd.deploy(TOKEN_DISTRIBUTOR_CHARM, channel=TOKEN_DISTRIBUTOR_CHANNEL)
    juju_lxd.integrate(app_name, TOKEN_DISTRIBUTOR_CHARM)
    juju_lxd.wait(jubilant.all_active)

    # deploy opentelemetry-collector
    juju_lxd.deploy(OTCOL_CHARM, channel=OTCOL_CHANNEL)
    juju_lxd.integrate(f"{app_name}:{cos_endpoint}", f"{OTCOL_CHARM}:{cos_endpoint}")
    juju_lxd.wait(lambda status: jubilant.all_blocked(status, OTCOL_CHARM))

    # verify the relation data is correctly set
    output = juju_lxd.cli(
        "show-unit",
        f"{OTCOL_CHARM}/0",
        "--format",
        "json",
        "--related-unit",
        f"{app_name}/0",
    )
    json_output = json.loads(output)
    relation_info = json_output.get(f"{OTCOL_CHARM}/0", {}).get("relation-info", [])

    # find the cos-agent relation
    cos_relation = None
    for relation in relation_info:
        if relation.get("endpoint") == cos_endpoint:
            cos_relation = relation
            break

    assert cos_relation is not None, "cos-agent relation not found"

    # check that microovn is providing data to opentelemetry-collector
    related_units = cos_relation.get("related-units", {})
    assert f"{app_name}/0" in related_units, f"{app_name}/0 not found in related units"

    microovn_data = related_units[f"{app_name}/0"].get("data", {})
    assert "config" in microovn_data, "config not found in relation data"

    config = json.loads(microovn_data["config"])
    assert "metrics_scrape_jobs" in config, "metrics_scrape_jobs not found in config"
    assert "dashboards" in config, "dashboards not found in config"

    # verify scrape job configuration
    scrape_jobs = config["metrics_scrape_jobs"]
    assert len(scrape_jobs) > 0, "No scrape jobs configured"
    scrape_job = scrape_jobs[0]
    assert scrape_job.get("metrics_path") == "/metrics", "Unexpected metrics path"

    static_configs = scrape_job.get("static_configs", [])
    assert len(static_configs) > 0, "No static configs in scrape job"
    targets = static_configs[0].get("targets", [])
    assert any("9310" in target for target in targets), "OVN exporter port not in targets"

    # verify dashboards are provided
    dashboards = config.get("dashboards", [])
    assert len(dashboards) == 0, "Dashboards provided, not expected"

    # verify alert rules are provided
    alert_rule_groups = config.get("metrics_alert_rules", {}).get("groups", {})
    assert len(alert_rule_groups) == 1, "Alerts were provided, not expected"

    # test metrics endpoint is accessible
    output = juju_lxd.exec(
        "curl -s http://localhost:9310/metrics || echo 'failed'",
        unit=f"{OTCOL_CHARM}/0",
    )
