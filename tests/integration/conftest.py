import contextlib
import functools
import secrets
import time
from typing import Generator

import jubilant
import pytest



def pytest_addoption(parser: pytest.OptionGroup):
    parser.addoption(
        "--keep-models",
        action="store_true",
        default=False,
        help="Keep temporarily created models.",
    )

@contextlib.contextmanager
def temp_model(keep: bool = False,
               controller: str | None = None,
               cloud: str | None = None) -> Generator[jubilant.Juju, None, None]:
    """Context manager to create a temporary model for running tests in.

    This creates a new model with a random name in the format ``jubilant-abcd1234``, and destroys
    it and its storage when the context manager exits.

    Provides a :class:`Juju` instance to operate on.

    Args:
        keep: If true, keep the created model around when the context manager exits.
        controller: Name of controller where the temporary model will be added.
        cloud: Name of cloud where the temporary model will be added.
    """
    juju = jubilant.Juju()
    model = 'jubilant-' + secrets.token_hex(4)  # 4 bytes (8 hex digits) should be plenty
    juju.add_model(model, controller=controller,cloud=cloud)
    try:
        yield juju
    finally:
        if not keep:
            juju.destroy_model(model, destroy_storage=True, force=True)

@pytest.fixture
def juju(request: pytest.FixtureRequest):
    keep_models = request.config.getoption('--keep-models')
    # NOTE workaround for juju add-model leading to transaction aborted
    #      error when running in parallel (LP: #2053270).
    while (retry_count := 3):
        try:
            with temp_model(keep=keep_models,cloud="localhost") as juju:
                juju.wait_timeout = 15 * 60
                juju.wait = functools.partial(juju.wait,
                                              error=jubilant.any_error)
                juju.model_config({
                    'image-stream': 'daily',
                    'enable-os-upgrade': 'false',
                })

                yield juju

                if request.session.testsfailed:
                    print(juju.debug_log(limit=1000))
                break
        except (jubilant._juju.CLIError) as e:
            if retry_count and "transaction aborted" in e.stderr:
                retry_count -= 1
                time.sleep(0.1)
                continue
            raise e
