# SPDX-License-Identifier: GPL-2.0-or-later
"""DJLINK=1 on an older player: the segment its single window joins."""

import os
import sys

EMU = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMU not in sys.path:
    sys.path.insert(0, EMU)

from launcher import deck, host  # noqa: E402


def test_link_is_off_unless_asked_for():
    assert deck.link_group({}) == ""
    assert deck.link_group({"DJLINK": "0", "GROUP": "239.77.77.1:45000"}) == ""


def test_group_comes_from_the_settings(monkeypatch):
    monkeypatch.setattr(host, "pick_udp_port", lambda port: port)
    assert deck.link_group({"DJLINK": "1", "GROUP": "239.77.77.9:44990"}) == "239.77.77.9:44990"
    assert deck.link_group({"DJLINK": "1"}) == deck.DEFAULT_GROUP


def test_reserved_port_is_replaced(monkeypatch):
    monkeypatch.setattr(host, "pick_udp_port", lambda port: port + 3)
    assert deck.link_group({"DJLINK": "1", "GROUP": "239.77.77.1:44000"}) == "239.77.77.1:44003"
