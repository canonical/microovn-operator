# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from pathlib import Path
from typing import Generator

import jubilant
import pytest
import yaml
from tenacity import Retrying, retry_if_exception, stop_after_attempt, wait_fixed

LXD_CONTROLLER_ENV = "LXD_CONTROLLER"
K8S_CONTROLLER_ENV = "K8S_CONTROLLER"
MICROOVN_CHARM_PATH_ENV = "MICROOVN_CHARM_PATH"
INTERFACE_CONSUMER_CHARM_PATH_ENV = "INTERFACE_CONSUMER_CHARM_PATH"


def pytest_addoption(parser: pytest.OptionGroup):
    parser.addoption(
        "--keep-models",
        action="store_true",
        default=False,
        help="Keep temporarily created models.",
    )


@pytest.fixture(scope="module")
def lxd_controller_name() -> str:
    return os.environ.get(LXD_CONTROLLER_ENV) or "concierge-lxd"


@pytest.fixture(scope="module")
def k8s_controller_name() -> str:
    return os.environ.get(K8S_CONTROLLER_ENV) or "concierge-microk8s"


def _juju_fixture(
    request: pytest.FixtureRequest, controller_name: str
) -> Generator[jubilant.Juju, None, None]:
    """Juju controller fixture with retry for transaction aborted errors."""
    keep_models = bool(request.config.getoption("--keep-models"))

    def _is_transaction_aborted_error(exc: BaseException) -> bool:
        return (
            isinstance(exc, jubilant._juju.CLIError)
            and hasattr(exc, "stderr")
            and "transaction aborted" in exc.stderr
        )

    # NOTE workaround for juju add-model leading to transaction aborted
    # error when running in parallel (LP#2053270)
    retrying = Retrying(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_fixed(1),
        retry=retry_if_exception(_is_transaction_aborted_error),
    )

    for attempt in retrying:
        with attempt:
            with jubilant.temp_model(
                controller=controller_name,
                keep=keep_models,
                config={
                    # "update-status-hook-interval": "30s",
                    "image-stream": "daily",
                    "enable-os-upgrade": "false",
                },
            ) as juju:
                juju.wait_timeout = 15 * 60

                yield juju  # run the test

                if request.session.testsfailed:
                    log = juju.debug_log(limit=300)
                    print(log, end="")
                return


@pytest.fixture(scope="function")
def juju_lxd(
    request: pytest.FixtureRequest, lxd_controller_name: str
) -> Generator[jubilant.Juju, None, None]:
    yield from _juju_fixture(request, lxd_controller_name)


@pytest.fixture(scope="function")
def juju_k8s(
    request: pytest.FixtureRequest, k8s_controller_name: str
) -> Generator[jubilant.Juju, None, None]:
    yield from _juju_fixture(request, k8s_controller_name)


def _get_charm_from_env(env: str) -> str | None:
    """Get charm path from environment variable."""
    if env_value := os.environ.get(env):
        return env_value
    return None


def _get_charm_from_dir(dir: Path) -> Path | None:
    """Path to the packed charm."""
    if not (path := next(iter(dir.glob("*.charm")), None)):
        return None
    return path


@pytest.fixture(scope="module")
def app_name() -> str:
    """Get the charm application name from charmcraft.yaml."""
    metadata = yaml.safe_load(Path("./charmcraft.yaml").read_text())
    return metadata["name"]


@pytest.fixture(scope="module")
def interface_consumer_app_name() -> str:
    """Get the interface-consumer charm application name from charmcraft.yaml."""
    metadata = yaml.safe_load(Path("./tests/interface-consumer/charmcraft.yaml").read_text())
    return metadata["name"]


@pytest.fixture(scope="module")
def charm_path() -> Path | str:
    """Return the path to the microovn charm."""
    if from_env := _get_charm_from_env(MICROOVN_CHARM_PATH_ENV):
        return from_env
    if from_path := _get_charm_from_dir(Path.cwd()):
        return from_path

    raise EnvironmentError(f"{MICROOVN_CHARM_PATH_ENV} is not set and charm not found in cwd")


@pytest.fixture(scope="module")
def interface_consumer_charm_path() -> Path | str:
    """Return the path to the interface-consumer charm."""
    if from_env := _get_charm_from_env(INTERFACE_CONSUMER_CHARM_PATH_ENV):
        return from_env
    if from_path := _get_charm_from_dir(Path.cwd() / "tests" / "interface-consumer"):
        return from_path

    raise EnvironmentError(
        f"{INTERFACE_CONSUMER_CHARM_PATH_ENV} is not set and charm not found in cwd"
    )
