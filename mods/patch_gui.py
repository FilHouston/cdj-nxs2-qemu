#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Apply code mods to the unpacked display (GUI) firmware image.

    usage: patch_gui.py [--model <id>] <gui_unpacked.bin> <patched.bin> <mod> [<mod>...]
           patch_gui.py --assemble     rebuild every mod's .bin from its .s
           patch_gui.py --check        fail if a committed .bin is not its .s assembled
           patch_gui.py --list

Each mod is a routine written in SH-2A assembly (gui_<mod>.s, assembled to
gui_<mod>.bin, which is kept next to it so patching needs no cross tools) and
a stretch of firmware code it replaces with a call to that routine. The patch
is made to the image, the way a firmware update would carry it:

  1. The routines go into the erased flash right after the on-chip RAM
     segments' source, and one new load-table record copies them to on-chip
     RAM past the end of the zero-filled area, where nothing in the image
     points.
  2. Each mod's call site is found by its instructions, not its address, and
     the image is left alone unless every site occurs exactly once.

A mod whose site is not found, or whose space is taken, is left out and
reported; the rest still go in, and an image that already carries a mod gets
it left as it is. --model picks the player (default cdj2000nxs2); a model
with no patch of a mod reports it as not applied.

Naming several mods patches all of them in one pass, sharing one load-table
record between them: pass every mod you want in a single call. Patching them
one at a time and combining the results is not supported.

The load table at 0x10 is twenty 12-byte records in groups of four (that
shape, and everything else about how a call site is found and spliced in, is
generic -- see sigpatch.py). That reading fits every record of v1.80 and
v1.81, but the boot loader that walks the table is not in the image, so it is
inferred, not read.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import anchors as A
import modelfw
import sigpatch
from sigpatch import Anchor, Mod

GUI_PROFILE = sigpatch.ImageProfile(
    flash_base=0x30000, loadtab_off=0x10, loadtab_n=20,
    ram_base=0x1C000000, ram_end=0x1C280000)

# The phrase mod's merge point and the context around it (see its entry below).
PHRASE_SITE = [
    0xE627, 0x60F2, 0x3658, 0x59F1, 0x4680, 0x4600, 0x36BC, 0x369C,
    0x2611, 0x52F2, 0x7801, 0x72FF, 0x2228, 0x8D02, 0x1F22, 0xAECE,
    0x0009, 0xDB34, 0x6DB3,
]

# What each routine imports: its stock (v1.81) value and where the image being
# patched has it. The two code addresses are fixed distances from the phrase
# site (the loop top 0x242 bytes before the signature, the renderer's marker
# pass where the replaced pair ends) because the loop top has no unique
# signature of its own that stays clear of the replaced span.
PHRASE_IMPORTS = (
    (0x0E5BB45C, A.records),
    (0x1C007B82, Anchor(PHRASE_SITE, 0, False, None, -0x242)),
    (0x1C007DE6, Anchor(PHRASE_SITE, 17, False)),
)

MODS = {
    # The RGB branch of the centre-waveform renderer, from the height clamp to
    # the end of the column fill. r5 = peak sample index, r8 = PWV5 array,
    # r12 = height, @(44,r15) = screen column; the canvas is the literal.
    'wave3': Mod(
        what='3-band centre waveform',
        target='gui',
        fw_versions=('1.81',),
        sig=[
            0x2CC8, 0x8B00, 0xEC01, 0x4500, 0xEB07, 0x6053, 0x058D, 0x0A00,
            0xE000, 0x4B18, 0x605D, 0xE9FB, 0x6103, 0xE400, 0x4121, 0x4121,
            0x21B9, 0x6603, 0x26A9, 0x409C, 0x67C3, 0x77FF, 0x316C, 0xC91C,
            0x3C77, 0x8F22, 0x310C, 0x4715, 0x8B12, 0x56FB, 0xD28A, 0x4600,
            0x0510, 0x9E00, 0x0910, 0xA400, 0x362C, 0x356C, 0x369C, 0x7402,
            0xE2F4, 0x4218, 0x3473, 0x2611, 0x362C, 0x2511, 0x8FF7, 0x352C,
            0x34C3, 0x891A, 0x60E3, 0x0710, 0xA400, 0x4480, 0x50FB, 0xD27E,
            0x4000, 0x3748, 0x307C, 0xA010, 0x0215, 0x4C15, 0x8B0D, 0x52FB,
            0x66C3, 0xD479, 0x4200, 0x0710, 0xA400, 0x324C, 0x327C, 0xE7FA,
            0x4610, 0x4718, 0x2211, 0x8FFA, 0x327C, 0x5BFA, 0xE00C,
        ],
        start=3,            # `shll r5`, after the height clamp
        end=77,             # up to `mov.l @(40,r15),r11`
        # mov.l @(44,r15),r4; mov r12,r6; mov r8,r7 (r5 is already the index)
        args=[0x54FB, 0x66C3, 0x6783],
        literal=True,
    ),
    # The colour-preview strip renderer's per-column record decode (r5 = the
    # record, r8 = the column, r6 = -4): the two heights read from record
    # bytes 4-5, up to the `tst r2,r2` that tests the first. The hook decodes
    # the same way and returns, or paints a 3-band record and returns r2 = 0,
    # which sends the renderer to the end of the column.
    'wave3ov': Mod(
        what='3-band overview strip',
        target='gui',
        fw_versions=('1.81',),
        sig=[
            0xE006, 0x6583, 0x4580, 0xD421, 0xE6FC, 0x354C, 0x3751, 0x8004,
            0x3051, 0x9002, 0x4709, 0x406D, 0x627C, 0xC93F, 0x2228, 0x8F02,
        ],
        start=6,            # `movu.b @(4,r5),r7`
        end=14,             # up to `tst r2,r2`
        args=[],
        literal=False,
    ),
    # The colour-preview overview strip's per-column loop-bottom merge point:
    # every fill style the renderer can take for one column rejoins here,
    # right before the column counter is bumped (r8 = the just-finished
    # column, 0..599). Hooking here instead of the colour lookup means the
    # waveform's own fill is already painted before this call runs, so
    # gui_phrase.s draws its band on top rather than the fill overwriting it,
    # and the waveform's own colours are never touched by this mod at all.
    #
    # sig carries 9 words of context before the replaced pair and 2 after
    # (neither replaced) purely so this site matches uniquely; the two
    # replaced words are sig[9] (the counter load) and sig[10] (the column
    # increment). gui_phrase.s reproduces both, then the branch they lead
    # into, itself -- see that file for why (sigpatch's own auto-resume can
    # only express one target, and this merge point has two).
    'phrase': Mod(
        what='overview strip phrase band',
        target='gui',
        fw_versions=('1.81',),
        sig=PHRASE_SITE,
        imports=PHRASE_IMPORTS,
        start=9,
        end=17,
        args=[],
        literal=False,
    ),
}


# The display firmware patches of each model. Only the CDJ-2000NXS2's display
# processor is covered; the older decks' displays are not.
PATCH_SETS = {modelfw.DEFAULT_MODEL: sigpatch.PatchSet(GUI_PROFILE, MODS)}


def mods_for(model):
    return PATCH_SETS[model].mods if model in PATCH_SETS else {}


def every_mod():
    return {name for patches in PATCH_SETS.values() for name in patches.mods}


def source(name, model=modelfw.DEFAULT_MODEL):
    """Each routine sits in its own mod's folder, mods/<mod>/ (mods/<mod>/<model>/
    for a model other than the default)."""
    return modelfw.routine_source('gui', name, model)


def blob_path(name, model=modelfw.DEFAULT_MODEL):
    return source(name, model)[:-2] + '.bin'


def patch(data, names, model=modelfw.DEFAULT_MODEL, report=None, spans=None):
    return sigpatch.patch_model(PATCH_SETS, blob_path, data, names, model, 'patch_gui', report, spans)


def _assemble(name, model, tmp, out):
    obj = os.path.join(tmp, name + '.o')
    subprocess.run(['sh4-linux-gnu-as', '--isa=sh2a', '-big',
                    '-o', obj, source(name, model)], check=True)
    subprocess.run(['sh4-linux-gnu-objcopy', '-O', 'binary', obj, out], check=True)


def routines():
    return [(model, name) for model, patches in PATCH_SETS.items() for name in patches.mods]


def assemble():
    with tempfile.TemporaryDirectory() as tmp:
        for model, name in routines():
            _assemble(name, model, tmp, blob_path(name, model))
            print('patch_gui: wrote %s (%d bytes)'
                  % (blob_path(name, model), os.path.getsize(blob_path(name, model))))


def check():
    """Every committed .bin is what its .s assembles to now: a .s edited
    without --assemble would otherwise ship its old routine."""
    stale = []
    with tempfile.TemporaryDirectory() as tmp:
        for model, name in routines():
            out = os.path.join(tmp, name + '.bin')
            _assemble(name, model, tmp, out)
            with open(out, 'rb') as f, open(blob_path(name, model), 'rb') as g:
                same = f.read() == g.read()
            print('patch_gui: %s %s' % (os.path.basename(blob_path(name, model)),
                                        'matches its .s' if same else 'is STALE'))
            if not same:
                stale.append(name)
    if stale:
        raise SystemExit('patch_gui: rebuild with patch_gui.py --assemble: %s' % ' '.join(stale))


def main():
    model, args = modelfw.model_id(sys.argv[1:])
    if args == ['--assemble']:
        assemble()
        return
    if args == ['--check']:
        check()
        return
    if args == ['--list']:
        for name, mod in mods_for(model).items():
            print('%-8s %s' % (name, mod.what))
        return
    if len(args) < 3 or any(n not in every_mod() for n in args[2:]):
        raise SystemExit(__doc__)
    with open(args[0], 'rb') as f:
        data = f.read()
    out = patch(data, args[2:], model)
    with open(args[1], 'wb') as f:
        f.write(out)


if __name__ == '__main__':
    main()
