# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The snap management class."""

import logging
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
        """Install the snap exporter."""
        try:
            snap.add(self.name, channel=self.channel)
            logger.info(
                "Installed snap %s from channel: %s",
                self.name,
                self.channel,
            )
            self.snap_client.hold()
            return self.snap_client.present is True
        except snap.SnapError as err:
            logger.error("Failed to install %s from channel: %s %s", self.name, self.channel, err)
        return False

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
