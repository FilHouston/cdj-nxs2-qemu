# SPDX-License-Identifier: GPL-2.0-or-later
"""The firmware addresses the launcher pokes while it runs a player.

On the supported update they are the constants below. On any other MAIN image
(another version, a modded update installed with --any-firmware) each one is
looked up in the image by the instructions around it
(mods/players/cdj2000nxs2.py) and a site that is not found exactly once stays
unset, so the launcher leaves out the poke that needed it and start says so.
"""

import functools
import os
import sys

from . import firmware, model

# Where a poke would go on the supported update (CDJ-2000NXS2 MAIN 1.87), by
# the name of the anchor that finds the same place in another image.
STOCK = {
    "load_poke_pc": 0x082F04D8,
    "load_poke_addr": 0x0994CC18,
    "pcall_pc": 0x08345574,
    "set_flag": 0x08516448,
    "own_mac": 0x0A35F754,
    "deck_ready": 0x0B5125B8,
    "colour_capability": 0x0A35FAAA,
    "sr_save_slot": 0x0AB87D8C,
}

# What is lost when the site (or one of the sites, for a poke that needs two)
# is missing.
OFF = (
    (("load_poke_pc", "load_poke_addr"), "the load poke: the loader may stall waiting for the file layer"),
    (("pcall_pc", "set_flag"), "the Pro DJ Link start call: the player may not announce itself"),
    (("own_mac",), "the firmware's own MAC hold: two decks may not settle their device numbers"),
    (("colour_capability",), "the colour capability byte: the display may stay in its monochrome mode"),
    (("deck_ready",), "the wait for the deck-ready word before the first key"),
)

# Switched off whenever the image is not the supported one: they are tied to
# addresses in it with nothing to look up or to check them by.
UNPINNED = (
    "the firmware log and trace taps, and the play-key holds and edge pokes of the lab runs",
    "the native memcmp/strlen/memcpy speed-ups (the machine runs the firmware's own code: slower)",
)
UNPINNED_DSP_IDLE = "the DSP idle-loop skip (the DSP program is run in full: slower)"
UNPINNED_GUI = "the display board's idle-loop halt (it keeps a host core busy)"


class Sites:
    def __init__(self, values, supported, gui_supported=True):
        self.values = values
        self.supported = supported
        self.gui_supported = gui_supported

    def get(self, name):
        return self.values.get(name)

    def has(self, *names):
        return all(self.values.get(n) is not None for n in names)

    def switched_off(self, m):
        """What the launcher leaves out of a start of model `m` on this image,
        one line each."""
        lines = [] if self.gui_supported else [UNPINNED_GUI]
        if self.supported:
            return lines
        lines += [what for names, what in OFF if self.values and not self.has(*names)]
        if self.values.get("sr_save_slot") is None:
            lines.append("the status-register seed: the firmware may fault in its first interrupt")
        return lines + list(UNPINNED) + ([UNPINNED_DSP_IDLE] if m.dsp_idle else [])


@functools.lru_cache(maxsize=None)
def _found(path, mtime_ns, size, emu):
    """The anchor values in the MAIN image at `path`; None for a site that is
    not found exactly once."""
    folder = os.path.join(emu, "mods")
    if folder not in sys.path:
        sys.path.insert(0, folder)
    import sigpatch
    from players import cdj2000nxs2 as player
    with open(path, "rb") as f:
        img = sigpatch.Image(player.MAIN_PROFILE, f.read())
    values = {}
    for name in STOCK:
        try:
            values[name] = sigpatch.anchor_value(img, getattr(player, name))
        except (sigpatch.NotApplied, SystemExit):
            values[name] = None
    return values


def find(lay, m=None):
    """The sites for the MAIN image installed for model `m` (the selected one
    when None). A player whose model finds nothing by signature (not the
    CDJ-2000NXS2 platform) has none beyond the supported update's."""
    m = m or model.load()
    differ = firmware.differing_images(model.extract_dir(lay, m), m)
    gui_ok = "gui_unpacked.bin" not in differ
    if "main_unpacked.bin" not in differ:
        return Sites(dict(STOCK), True, gui_ok)
    if not m.is_rig:
        return Sites({}, False, gui_ok)
    path = os.path.join(model.extract_dir(lay, m), "main_unpacked.bin")
    st = os.stat(path)
    return Sites(dict(_found(path, st.st_mtime_ns, st.st_size, lay.emu)), False, gui_ok)
