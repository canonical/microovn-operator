import json
import os

import jubilant

def get_charm_from_env(env):
    charm_path = "./" + os.environ.get(env)
    if charm_path is None:
        raise EnvironmentError("{0} is not set".format(env))
    return charm_path

microovn_charm_path = get_charm_from_env("MICROOVN_CHARM_PATH")
token_distributor_charm_path = get_charm_from_env("TOKEN_DISTRIBUTOR_CHARM_PATH")
dummy_charm_path = get_charm_from_env("INTERFACE_CONSUMER_CHARM_PATH")

def test_integrate(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm_path)
    juju.integrate("microovn","microcluster-token-distributor")
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/1")

def test_integrate_post_start(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.deploy(token_distributor_charm_path)
    juju.wait(lambda status: jubilant.all_active(status, "microcluster-token-distributor"))
    juju.wait(lambda status: jubilant.all_maintenance(status, "microovn"))
    juju.integrate("microovn","microcluster-token-distributor")
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/1")

def test_token_distributor_down(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.deploy(token_distributor_charm_path)
    juju.integrate("microovn","microcluster-token-distributor")
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.remove_unit("microcluster-token-distributor/0")
    juju.add_unit("microcluster-token-distributor")
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)
    juju.exec("microovn status", unit="microovn/2")

def test_microcluster_leader_down(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm_path)
    juju.integrate("microovn","microcluster-token-distributor")
    juju.wait(jubilant.all_active)
    output = juju.exec("microovn cluster list -f json", unit="microovn/0").stdout
    json_output = json.loads(output)
    voter_names = [ x["name"] for x in json_output
                    if (x["role"] in ["voter", "PENDING"]) and (x["status"] == "ONLINE") ]
    voter_name = min(voter_names)
    hostname = juju.exec("hostname -s",unit="microovn/0").stdout[:-1]
    if hostname == voter_name:
        juju.remove_unit("microovn/0")
    else:
        juju.remove_unit("microovn/1")
    juju.add_unit("microovn")
    juju.wait(jubilant.all_active)

def test_integrate(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm_path)
    juju.integrate("microovn","microcluster-token-distributor")
    juju.wait(jubilant.all_active)
    juju.deploy(dummy_charm_path)
    juju.integrate("microovn","interface-consumer")
    juju.wait(jubilant.all_active)
    output = juju.cli("show-unit","interface-consumer/0", "--format", "json", "--endpoint", "ovsdb")
    json_output = json.loads(output)
    data = json_output["interface-consumer/0"]["relation-info"][0]["application-data"]
    assert(data.get("db_nb_connection_str"))
    assert(data.get("db_sb_connection_str"))
