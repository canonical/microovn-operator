# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The snap management class."""

import logging
import re
from typing import List, Tuple

from charms.operator_libs_linux.v2 import snap
from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)


class SnapManager:
    """A manager class for a snap."""

    name: str
    channel: str

    def __init__(self, name: str, channel: str):
        self.name = name
        self.channel = channel

    @property
    def snap_client(self) -> snap.Snap:
        """Return the snap client."""
        return snap.SnapCache()[self.name]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(1),
        retry=retry_if_result(lambda x: x is False),
        retry_error_callback=(lambda state: state.outcome.result()),  # type: ignore
    )
    def install(self) -> bool:
        """Install the snap exporter and required base if needed."""
        try:
            snap.add(self.name, channel=self.channel)
            logger.info(
                "Installed snap %s from channel: %s",
                self.name,
                self.channel,
            )
        except snap.SnapError as err:
            err_msg = err.message
            logger.error(
                "Failed to install %s from channel: %s '%s'", self.name, self.channel, err_msg
            )

            # Snaps sometimes are built on an edge base, ie microovn with core26,
            # this cannot be automatically installed as a dependacy due to its
            # non stable status so we must detect and manually install it in
            # these cases. We do this by checking for expected bases in the
            # error message and then retrying installation with the new base.
            regmatch = re.search(r'cannot install snap base "(core\d\d)"', err_msg)
            if regmatch:
                snap_base = regmatch.group(1)
                logger.info(
                    "Detected required base '%s', retrying installation with it", snap_base
                )
                try:
                    snap.add(snap_base, channel="latest/edge")
                    snap.add(self.name, channel=self.channel)
                except snap.SnapError as err:
                    logger.error("Retry with base %s failed: %s", snap_base, err)
                    return False

        # Hold the snap after successful install
        self.snap_client.hold()
        return self.snap_client.present is True

    def enable_and_start(self) -> bool:
        """Enable and start the snap services."""
        try:
            self.snap_client.start(enable=True)
            logger.info("Enabled and started services for %s", self.name)
            return True
        except snap.SnapError as err:
            logger.error("Failed to enable and start services for %s: %s", self.name, err)
        return False

    def disable_and_stop(self) -> bool:
        """Disable and stop the snap services."""
        try:
            self.snap_client.stop(disable=True)
            logger.info("Disabled and stopped services for %s", self.name)
            return True
        except snap.SnapError as err:
            logger.error("Failed to disable and stop services for %s: %s", self.name, err)
        return False

    def remove(self) -> bool:
        """Remove the snap exporter."""
        try:
            snap.remove(self.name)
            logger.info("Removed %s", self.name)
            return self.snap_client.present is False
        except snap.SnapError as err:
            logger.error("Failed to remove %s: %s", self.name, err)
        return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(1),
        retry=retry_if_result(lambda x: x is False),
        retry_error_callback=(lambda state: state.outcome.result()),  # type: ignore
    )
    def connect(self, connections: List[Tuple[str, str | None]]) -> bool:
        """Connect the specified interfaces for the snap exporter.

        Args:
            connections: A list of tuples where each tuple contains
                         (plug, slot) to connect.
        """
        for connection in connections:
            plug, slot = connection
            full_plug = f"{self.name}:{plug}"

            try:
                self.snap_client.connect(plug, slot=slot)
                logger.info("Connected plug %s for %s", full_plug, self.name)
            except snap.SnapError as err:
                logger.error(
                    "Failed to connect plug %s for %s snap: %s",
                    full_plug,
                    self.name,
                    err,
                )
                return False
        return True
