import os

token_distributor_charm = "microcluster-token-distributor"
tdist_channel = "latest/edge"


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
