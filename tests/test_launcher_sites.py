# SPDX-License-Identifier: GPL-2.0-or-later
"""launcher/sites.py: the firmware addresses the launcher pokes are the
supported update's constants on that update, are looked up in any other MAIN
image, and the poke that needs a site that is not found is left out."""

import os
import sys
from types import SimpleNamespace

import pytest

EMU = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMU not in sys.path:
    sys.path.insert(0, EMU)

from launcher import instrumented_batch, model, play_real_dsp, sites  # noqa: E402

REAL_MAIN = os.path.join(EMU, "..", "extract", "main_unpacked.bin")
needs_real_main = pytest.mark.skipif(not os.path.exists(REAL_MAIN), reason="extract/main_unpacked.bin not present")


def layout_with(tmp_path, main=None):
    extract = tmp_path / "extract"
    extract.mkdir()
    if main is not None:
        (extract / "main_unpacked.bin").write_bytes(main)
    return SimpleNamespace(root=str(tmp_path), extract=str(extract), emu=EMU)


def test_no_installed_image_is_the_supported_update(tmp_path):
    found = sites.find(layout_with(tmp_path))
    assert found.supported and found.get("load_poke_pc") == 0x082F04D8
    assert found.switched_off(model.load()) == []


def test_an_image_without_the_sites_leaves_every_poke_out(tmp_path):
    found = sites.find(layout_with(tmp_path, bytes(0x40000)))
    assert not found.supported
    assert all(found.get(name) is None for name in sites.STOCK)
    off = found.switched_off(model.load())
    assert len(off) == len(sites.OFF) + 1 + len(sites.UNPINNED)
    assert any("load poke" in line for line in off)


def test_the_load_poke_needs_both_its_sites(tmp_path):
    env = {}
    instrumented_batch.batch_env(env, sites.Sites({}, False))
    assert env["CDJ_PPOKE"] == ""
    assert "CDJ_FWTRACE" not in env and "CDJ_FWLOG" not in env
    env = {}
    instrumented_batch.batch_env(env, sites.Sites(dict(sites.STOCK), True))
    assert env["CDJ_PPOKE"] == "0x082f04d8:0x0994CC18:1:0"
    assert env["CDJ_FWLOG"] == "0x0853410C,0x084933F4"
    env = {"TAPS": "0x08000100"}
    instrumented_batch.batch_env(env, sites.Sites({}, False))
    assert env["CDJ_FWTRACE"] == "0x08000100"


def test_a_found_site_replaces_the_supported_address():
    found = sites.Sites(dict(sites.STOCK, load_poke_pc=0x082F0238, colour_capability=0x0A35F9AA), False)
    env = {}
    instrumented_batch.batch_env(env, found)
    assert env["CDJ_PPOKE"].startswith("0x082f0238:0x0994CC18:")
    env = {}
    play_real_dsp.batch_env(env, found)
    assert env["MPOKE"] == "0x0A35F9AA:3:1"
    assert "TAPS" not in env and "CDJ_PPOKE_ARM" not in env


def test_the_supported_update_keeps_its_pokes():
    env = {"LADDER": "0"}
    play_real_dsp.batch_env(env, sites.Sites(dict(sites.STOCK), True))
    assert env["MPOKE"] == "0x0A35FAAA:3:1"
    assert env["TAPS"] == "0x08443252,0x08443276,0x0842A160,0x084E294E"


@needs_real_main
def test_the_signatures_find_the_supported_addresses_in_the_supported_image(tmp_path):
    values = sites._found(os.path.abspath(REAL_MAIN), 0, 0, EMU)
    assert values == sites.STOCK
