import json
import os
import time

import jubilant


def get_charm_from_env(env):
    charm_path = "./" + os.environ.get(env)
    if charm_path is None:
        raise EnvironmentError("{0} is not set".format(env))
    return charm_path


def is_command_passing(juju, commandstring, unitname):
    try:
        juju.exec(commandstring, unit=unitname)
        return True
    except Exception as e:
        print(e)
        return False


microovn_charm_path = get_charm_from_env("MICROOVN_CHARM_PATH")
dummy_charm_path = get_charm_from_env("INTERFACE_CONSUMER_CHARM_PATH")

token_distributor_charm = "microcluster-token-distributor"
tdist_channel = "latest/edge"


def test_integrate(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.integrate("microovn", token_distributor_charm)
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/1")
    juju.model_config({"update-status-hook-interval": "1s"})
    time.sleep(2)
    juju.wait(jubilant.all_active)


def test_integrate_post_start(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.wait(lambda status: jubilant.all_active(status, token_distributor_charm))
    juju.wait(lambda status: jubilant.all_maintenance(status, "microovn"))
    juju.integrate("microovn", token_distributor_charm)
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/1")


def test_token_distributor_down(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.integrate("microovn", token_distributor_charm)
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.remove_unit("microcluster-token-distributor/0")
    juju.add_unit(token_distributor_charm)
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/2")


def test_microcluster_leader_down(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.integrate("microovn", token_distributor_charm)
    juju.wait(jubilant.all_active)
    output = juju.exec("microovn cluster list -f json", unit="microovn/0").stdout
    json_output = json.loads(output)
    voter_names = [
        x["name"]
        for x in json_output
        if (x["role"] in ["voter", "PENDING"]) and (x["status"] == "ONLINE")
    ]
    voter_name = min(voter_names)
    hostname = juju.exec("hostname -s", unit="microovn/0").stdout[:-1]
    if hostname == voter_name:
        juju.remove_unit("microovn/0")
    else:
        juju.remove_unit("microovn/1")
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)


def test_integrate_ovsdb(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.integrate("microovn", token_distributor_charm)
    juju.wait(jubilant.all_active)
    juju.deploy(dummy_charm_path)
    juju.integrate("microovn", "interface-consumer")
    juju.wait(jubilant.all_active)
    output = juju.cli(
        "show-unit", "interface-consumer/0", "--format", "json", "--endpoint", "ovsdb"
    )
    json_output = json.loads(output)
    data = json_output["interface-consumer/0"]["relation-info"][0]["application-data"]
    assert data.get("db_nb_connection_str")
    assert data.get("db_sb_connection_str")


def test_certificates_integration(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.deploy("self-signed-certificates")
    juju.integrate("microovn", token_distributor_charm)
    juju.integrate("microovn", "self-signed-certificates")
    juju.wait(jubilant.all_active)
    juju.wait(lambda _: "CA certificate updated, new certificates issued" in juju.debug_log())
    destination = juju.status().apps["microovn"].units["microovn/1"].public_address
    destination = destination + ":6643"
    command_str = "openssl s_client -connect {0}".format(destination)
    output = juju.exec(command_str + "|| true", unit="self-signed-certificates/0")
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
    output = juju.exec(command_str, unit="self-signed-certificates/0")
    assert "Verification: OK" in output.stdout
    # this checks the full certificate chain works and will work in the standard
    # use case.
    juju.deploy(dummy_charm_path)
    juju.integrate("self-signed-certificates", "interface-consumer")
    juju.integrate("microovn", "interface-consumer")
    juju.wait(jubilant.all_active)
    juju.wait(
        lambda _: is_command_passing(juju, "ls /root/pki/consumer.pem", "interface-consumer/0")
    )
    command_str = (
        "openssl s_client -connect {0} "
        "-CAfile /root/pki/ca.pem "
        "-cert /root/pki/consumer.pem "
        "-key /root/pki/consumer.key "
        "-verify_return_error"
    ).format(destination)
    output = juju.exec(command_str, unit="interface-consumer/0")


def test_ovn_k8s_integration(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.deploy("self-signed-certificates")
    juju.integrate("microovn", token_distributor_charm)
    juju.integrate("microovn", "self-signed-certificates")
    juju.wait(jubilant.all_active)
    juju_lxd_model = juju.model
    # I really do not like the usage of juju.cli switch here, but it is needed
    # due to https://github.com/canonical/jubilant/issues/170
    juju.cli("switch", juju_lxd_model, include_model=False)
    juju.offer("self-signed-certificates", endpoint="certificates")

    # setup ovn-central-k8s and its relations
    juju_k8s_model = "ovn-k8s"
    juju_k8s = jubilant.Juju()
    juju_k8s.add_model(juju_k8s_model, cloud="mk8s")
    # just to ensure the juju variable is the right model, due to weird jubilant behavior
    juju_lxd = jubilant.Juju(model=juju_lxd_model)
    juju_k8s.deploy("ovn-central-k8s", channel="24.03/stable", num_units=3)
    juju_k8s.deploy("ovn-relay-k8s", channel="24.03/stable", num_units=3, trust=True)
    juju_k8s.integrate("ovn-central-k8s", "ovn-relay-k8s")
    juju_k8s.cli("switch", juju_k8s_model, include_model=False)
    juju_k8s.offer("ovn-relay-k8s", endpoint="ovsdb-cms-relay")
    juju_k8s.integrate("ovn-central-k8s", "{}.self-signed-certificates".format(juju.model))
    juju_k8s.integrate("ovn-relay-k8s", "{}.self-signed-certificates".format(juju.model))
    juju_lxd.cli("switch", juju_lxd_model, include_model=False)
    juju_lxd.integrate("microovn", "{}.ovn-relay-k8s".format(juju_k8s.model))
    juju_k8s.wait(jubilant.all_active, timeout=300)
    juju_lxd.wait(jubilant.all_active, timeout=300)

    # ensure microovn central is down
    output = juju_lxd.exec("microovn status", unit="microovn/0")
    assert "central" not in output.stdout
    # test ovn-sbctl still works which means its using ovn-relay-k8s
    juju_lxd.exec("microovn.ovn-sbctl --no-leader-only show", unit="microovn/0")
    output = juju_lxd.exec("microovn.ovn-sbctl --no-leader-only show", unit="microovn/1")
    assert output.stdout.count("Chassis") == 2  # We have 2 microovn units

    juju_k8s.cli("switch", juju_k8s_model, include_model=False)
    juju_k8s.destroy_model(juju_k8s.model, destroy_storage=True, force=True)


def test_certificates_before_token_distributor(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy("self-signed-certificates")
    juju.integrate("microovn", "self-signed-certificates")
    juju.wait(lambda status: jubilant.all_active(status, "self-signed-certificates"))
    juju.wait(lambda status: jubilant.all_maintenance(status, "microovn"))
    juju.deploy(token_distributor_charm, channel=tdist_channel)
    juju.integrate("microovn", token_distributor_charm)
    juju.wait(jubilant.all_active)
    juju.wait(lambda _: "CA certificate updated, new certificates issued" in juju.debug_log())
    destination = juju.status().apps["microovn"].units["microovn/1"].public_address
    destination = destination + ":6643"
    command_str = "openssl s_client -connect {0} -CAfile /tmp/ca-cert.pem || true".format(
        destination
    )
    output = juju.exec(command_str, unit="self-signed-certificates/0")
    assert "Verification: OK" in output.stdout
