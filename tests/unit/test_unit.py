#!/usr/bin/env python3

from unittest.mock import patch

import charm


def test_call_microovn_command():
    with patch("microovn.src.charm.subprocess.run") as mock_run:
        charm.call_microovn_command("status")
        args, kwargs = mock_run.call_args
        assert args[0] == ["microovn", "status"]

        addresses = ["192.168.0.16", "8.8.8.8", "4.13.6.12"]
        charm.call_microovn_command("config", "set", "ovn.central-ips", ",".join(addresses))
        args, kwargs = mock_run.call_args
        assert args[0] == [
            "microovn",
            "config",
            "set",
            "ovn.central-ips",
            "192.168.0.16,8.8.8.8,4.13.6.12",
        ]
