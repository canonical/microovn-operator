import functools
import time

import jubilant
import pytest


def pytest_addoption(parser: pytest.OptionGroup):
    parser.addoption(
        "--keep-models",
        action="store_true",
        default=False,
        help="Keep temporarily created models.",
    )


@pytest.fixture
def juju(request: pytest.FixtureRequest):
    keep_models = request.config.getoption('--keep-models')
    # NOTE workaround for juju add-model leading to transaction aborted
    #      error when running in parallel (LP: #2053270).
    while (retry_count := 3):
        try:
            with jubilant.temp_model(keep=keep_models) as juju:
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
