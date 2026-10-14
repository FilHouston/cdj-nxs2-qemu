# SPDX-License-Identifier: GPL-2.0-or-later
"""What the mod tools need to know about one model's firmware, read from its
profile (models/<id>.conf): which sections of its update hold the images a mod
can patch, and where the packed MAIN application starts in the update's
address space. The default model is the one whose patches sit directly in
each mod's folder; any other model's sit in mods/<mod>/<model>/.
"""
import collections
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from launcher import model as cdj_model

DEFAULT_MODEL = cdj_model.DEFAULT

# The SH7763 players (CDJ-2000 family) unpack MAIN to DRAM at physical
# 0x04000000; every SH7724 player's image starts at 0x08000000.
SH7763_MAIN_BASE = 0x04000000
MAIN_BASE = 0x08000000
SH7763_MODELS = ('cdj2000nxs', 'cdj2000', 'cdj900')

# Where the updater of each player stops erasing and programming the MAIN
# region of a public update (label byte 31 = 0). Each end is the first sector
# the updater's erase routine does not reach: it loops over a table of sector
# offsets in the flash driver, starting at the entry of the packed image
# (main_lzss - 4), for a fixed count, and the count is a "mov #n" in front of
# the table pointer. 64 KiB sectors, except the XDJ-1000 and MK2 (128 KiB):
#   cdj2000nxs2, cdjtour1   0x50000 + 121 * 0x10000
#   xdj700, cdj900nxs       0x40000 + 122 * 0x10000
#   xdj1000, xdj1000mk2     0x40000 + 118 * 0x20000
#   cdj2000nxs, cdj2000, cdj900   0x40000 + 58 * 0x10000
# A player missing here has not been read.
UPDATE_WINDOW_END = {
    'cdj2000nxs2': 0x7E0000, 'cdjtour1': 0x7E0000,
    'xdj700': 0x7E0000, 'cdj900nxs': 0x7E0000,
    'xdj1000': 0xF00000, 'xdj1000mk2': 0xF00000,
    'cdj2000nxs': 0x3E0000, 'cdj2000': 0x3E0000, 'cdj900': 0x3E0000,
}

Firmware = collections.namedtuple('Firmware', 'sections main_off bare', defaults=(False,))


def parse_manifest(data):
    """(section sizes, header length) of an update file: the manifest is one CRLF
    decimal per section, giving its size."""
    sizes, pos = [], 0
    while True:
        m = re.match(rb'(\d+)\r\n', data[pos:pos + 32])
        if not m:
            break
        sizes.append(int(m.group(1)))
        pos += m.end()
    return sizes, pos


def model_id(args):
    """(model id, args without --model <id>)."""
    if '--model' not in args:
        return DEFAULT_MODEL, args
    i = args.index('--model')
    if i + 1 >= len(args):
        raise SystemExit('--model needs a model id')
    return args[i + 1], args[:i] + args[i + 2:]


def main_base(model):
    """Address the unpacked MAIN image of `model` starts at."""
    return SH7763_MAIN_BASE if model in SH7763_MODELS else MAIN_BASE


def other_files(model):
    """[(file name, sha256)] of the files a one-file-per-section update has
    besides MAIN's; none for a player whose update is one file."""
    m = cdj_model.load(model)
    if len(m.upd) < 2:
        return []
    main = int(m.main_section) - 1
    return [(name, digest) for k, (name, digest) in enumerate(zip(m.upd, m.upd_sha256)) if k != main]


def main_file(model):
    """(file name, sha256) of the official file that holds MAIN."""
    m = cdj_model.load(model)
    k = int(m.main_section) - 1 if len(m.upd) > 1 else 0
    return m.upd[k], m.upd_sha256[k]


def load(model):
    """Firmware of `model`. A GUI section is listed only for a model whose
    display firmware runs on its own board. A model whose update is one file
    per section (the CDJ-2000 and CDJ-900) is `bare`: the MAIN file is a
    single section with no manifest in front of it."""
    try:
        m = cdj_model.load(model)
    except cdj_model.ModelError as e:
        raise SystemExit(str(e))
    if len(m.upd) > 1:
        return Firmware({'main': 1}, int(m.main_lzss, 0) - 4, bare=True)
    sections = {'main': int(m.main_section)}
    if m.gui_machine:
        sections['gui'] = int(m.gui_section)
    return Firmware(sections, int(m.main_lzss, 0) - 4)


def routine_source(prefix, name, model):
    """The assembly of one mod's routine for `model`: mods/<mod>/<prefix>_<name>.s
    for the default model, mods/<mod>/<model>/<prefix>_<name>.s for another."""
    sub = '' if model == DEFAULT_MODEL else model
    return glob.glob(os.path.join(HERE, '*', sub, '%s_%s.s' % (prefix, name)))[0]
