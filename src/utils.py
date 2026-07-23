# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for the charm."""

import json
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
        return False
    return "central" in result.stdout


def count_microovn_cluster_members() -> int:
    """Return the number of members in the (potentially shared) microovn cluster.

    Uses microovn cluster list --format json output, which returns one entry per
    cluster member. Returns 0 when the command fails or its output cannot be parsed.

    This is used to distinguish a genuinely last central node from a transient
    last-central condition in a cluster shared across multiple juju applications.
    """
    result = call_microovn_command("cluster", "list", "--format", "json")
    if result.returncode != 0:
        logger.error(
            "microovn cluster list failed with error code %s, strerr: %s",
            result.returncode,
            result.stderr,
        )
        return 0
    try:
        members = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        logger.error("Could not parse microovn cluster list output: %r", result.stdout)
        return 0
    if not isinstance(members, list):
        logger.error("Unexpected microovn cluster list output: %r", result.stdout)
        return 0
    return len(members)


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
