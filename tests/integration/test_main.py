import json
import os

import jubilant

microovn_charm_path = "./" + os.environ.get("MICROOVN_CHARM_PATH")
if microovn_charm_path is None:
    raise EnvironmentError("MICROOVN_CHARM_PATH is not set")

token_distributor_charm_path = "./" + os.environ.get("TOKEN_DISTRIBUTOR_CHARM_PATH")
if token_distributor_charm_path is None:
    raise EnvironmentError("TOKEN_DISTRIBUTOR_CHARM_PATH is not set")

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

def test_certificates_integration(juju: jubilant.Juju):
    juju.deploy(microovn_charm_path)
    juju.add_unit("microovn")
    juju.deploy(token_distributor_charm_path)
    juju.deploy("self-signed-certificates")
    juju.integrate("microovn","microcluster-token-distributor")
    juju.integrate("microovn","self-signed-certificates")
    juju.wait(jubilant.all_active)
    juju.wait(lambda _: "Pushed certificate to workload" in juju.debug_log())
    destination = juju.status().apps["microovn"].units["microovn/1"].public_address
    destination = destination + ":6643"
    try:
        juju.exec("openssl s_client -connect {0} -verify_return_error".format(destination), unit="self-signed-certificates/0")
        assert False, "Expected to fail, somehow passed"
    except:
        pass
    output = juju.exec("openssl s_client -connect {0} -CAfile /tmp/ca-cert.pem -verify_return_error".format(destination), unit="self-signed-certificates/0")
    assert("Verification: OK" in output.stdout)
