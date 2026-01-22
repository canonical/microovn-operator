import time

import jubilant
from helpers import get_charm_from_env, tdist_channel, token_distributor_charm

microovn_charm_path = get_charm_from_env("MICROOVN_CHARM_PATH")
dummy_charm_path = get_charm_from_env("INTERFACE_CONSUMER_CHARM_PATH")


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
