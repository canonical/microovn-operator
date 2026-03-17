# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for the charm."""

import logging
import subprocess

import requests
from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)


def call_microovn_command(*args, stdin=None) -> subprocess.CompletedProcess[str]:
    """Call the command microovn with the given arguments."""
    result = subprocess.run(
        ["microovn", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=stdin,
        text=True,
    )
    logger.info("Called microovn %s, return code: %d", args, result.returncode)
    return result


@retry(
    stop=stop_after_attempt(10),
    wait=wait_fixed(1),
    retry=retry_if_result(lambda x: x is False),
    retry_error_callback=(lambda state: state.outcome.result()),  # type: ignore
)
def wait_for_microovn_ready():
    """Wait for microovn to be ready."""
    return call_microovn_command("waitready").returncode == 0


def microovn_central_exists() -> bool:
    """Check if there is any microovn central node in the cluster."""
    result = call_microovn_command("status")
    if result.returncode != 0:
        logger.error(
            "microovn status failed with error code %s, strerr: %s",
            result.returncode,
            result.stderr,
        )
        raise subprocess.CalledProcessError(
            result.returncode, "microovn status", result.stdout, result.stderr
        )
    return "central" in result.stdout


@retry(
    stop=stop_after_attempt(5),
    wait=wait_fixed(2),
    retry=retry_if_result(lambda x: x is False),
    retry_error_callback=(lambda state: state.outcome.result()),  # type: ignore
)
def check_metrics_endpoint(url: str) -> bool:
    """Check if the metrics endpoint is reachable.

    Returns:
        bool: True if the metrics endpoint is reachable, False otherwise.
    """
    try:
        response = requests.get(url, timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        logger.warning("Metrics endpoint %s is not reachable yet.", url)
        return False
