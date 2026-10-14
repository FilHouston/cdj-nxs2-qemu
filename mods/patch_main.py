#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Apply code mods to the unpacked MAIN firmware image.

    usage: patch_main.py [--model <id>] <main_unpacked.bin> <patched.bin> <mod> [<mod>...]
           patch_main.py --flash <flash.bin> <patched-flash.bin> <mod> [<mod>...]
           patch_main.py --assemble     rebuild every mod's .bin from its .s
           patch_main.py --list

Same shape as patch_gui.py (see that file for the general mechanism), on the
MAIN image instead of the display one. Two differences follow from MAIN being
executed in place rather than scattered to RAM by a load table:

  1. There is no scatter-load record to add: a mod's routine is written
     directly into a run of erased flash within MAIN's own address space
     (see sigpatch.place_inplace()), which is both its storage and its
     execution address.
  2. --flash patches the MAIN application's packed image directly inside a
     flat NOR/flash buffer (extract/flash.bin, or a deck's own copy), at the
     flash offset make_flash.py places it -- for booting a patched MAIN
     through Pioneer's own bootloader (MAIN_BOOT=flash) rather than via
     -kernel. The window each update is allowed to write is erased first, the
     same way the real updater erases before it writes, so a shorter or
     longer re-encoded stream never leaves stale bytes past its own end.

MAIN is a little-endian SH-4 (the GUI's SH7269 is big-endian), so every mod's
sig/args/literal is still given as the instruction's logical value -- see
sigpatch.ImageProfile's byteorder field, which does the translation.

Most MAIN mods are hooks (Mod.hook): several of them can sit on one firmware
site, which is defined once below and shared by every mod on it. The patch
engine moves the site's span into one trampoline that runs it once and then
calls each selected mod's routine in registry order -- see
sigpatch.trampoline() for the code and the contract a hook routine follows.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIRMWARE = os.path.join(HERE, '..', 'scripts', 'firmware')
sys.path.insert(0, HERE)
sys.path.insert(0, FIRMWARE)
import anchors as A
import modelfw
import sigpatch
from sigpatch import Cave, FreeEnd, Mod
import main_decode
import main_encode

# MAIN runs in place from 0x08000000. The routines go into the largest run of
# erased flash in the image (on the v1.87 image the 938,112 bytes at
# 0x0811AF80-0x08200000, which no pc-relative load in the image reads from),
# found by sigpatch.place_inplace() rather than named here.
MAIN_PROFILE = sigpatch.ImageProfile(
    flash_base=0x08000000, loadtab_off=0, loadtab_n=0,
    ram_base=None, ram_end=None, byteorder='<')

# The XDJ-700's MAIN runs in place as well, but no run of erased flash in it is
# free: the 0xFF runs are bitmap data. Its room is four handlers of the kernel's
# debug shell (semaphore, event flag, data queue, mail box: 1,168 bytes), which
# nothing calls but the shell's command table, found by their name strings.
XDJ700_PROFILE = sigpatch.ImageProfile(
    flash_base=0x08000000, loadtab_off=0, loadtab_n=0,
    ram_base=None, ram_end=None, byteorder='<',
    cave=Cave(handlers=(b'show semaphore info', b'show event flag info',
                        b'show data queue info', b'show mail box info'),
              end=b'show mutex info',
              sha256='2e4dc6aa5e8400152e828e99fe4df3116d0c2f7dd5e24223df2dc31e6121e376'))

# The beat loop's call to the UDP send wrapper: the wrapper's literal, the
# port store into the send descriptor at r15+0x150, the descriptor pointer
# into r5 and the call itself with its delay slot. The beat packet the call
# sends stays reachable after it at *(r15+0x218), r12 still holds the
# wrapper and r10 the fpscr mask the firmware applies before every call.
BEAT_SEND = dict(
    sig=[0x0FC4, 0x7004, 0xDC2E, 0x0F26, 0xE254, 0x4208, 0x352C, 0x026A,
         0x22A9, 0x4C0B, 0x426A, 0x026A, 0xD62A],
    start=2,
    end=11,
)

# The USB-MIDI task's event loop, at its top: the task-state read, the load of
# that state's event mask into r14 and the push of the infinite timeout, all
# before the wait call. Every pass of the loop branches back to the start of
# the span; nothing after it reads r0 or r1 before the wait returns.
MIDI_TASK = dict(
    sig=[0xDAAE, 0xD1AE, 0x6012, 0xE1FF, 0x4008, 0x0E9E, 0x2F16, 0xE601,
         0x67C3, 0x55F3, 0x6452, 0x4A0B, 0xE5FF],
    start=1,
    end=7,
)

# The 1 ms timer interrupt's body (TMU unit 1 channel 1, the tick word
# 0x0B0C5258), at the first of its down-counters: the load of its base, the
# decrement unless already zero and the store. pr is saved before it, r1 is
# not read before the body next writes it and T is set again before it is
# tested.
TIMER_TICK = dict(
    sig=[0xD67E, 0x6262, 0x2228, 0x8B01, 0xA22C, 0x0009, 0xD67C, 0x5261,
         0x2228, 0x8901, 0x72FF, 0x1621, 0xD47A, 0xE5FF],
    start=6,
    end=12,
)

# The Pro DJ Link receive task, right after udp_rcv_dat has filled its 128-byte
# buffer (r10) and the call that takes a memory block for the datagram: the
# block call with its delay slot and the fpscr read that follows it. r0 still
# holds the block call's result, r14 the datagram length, *(r15) the block and
# r15+12 the sender's address; the stock test of r0 after the span loops back
# to the receive when it is non-zero, so a hook that sets r0 swallows the
# datagram.
LINK_RECEIVE = dict(
    sig=[0x26C9, 0xAFE4, 0x466A, 0xD25C, 0x65F3, 0xD75C, 0xE6FF, 0x470B,
         0x6422, 0x016A, 0x2008, 0x21C9, 0x8FD9, 0x416A, 0xD758, 0xE500,
         0x64F2, 0x470B],
    start=3,
    end=10,
)

# The Sentinel task's one call to the status serialiser: the argument offset,
# the serialiser's literal, the call with its delay slot and the two
# instructions after it (the fpscr read and the next literal load, which make
# the span long enough for the jump to the trampoline), between context
# halfwords that make the signature unique. The hooks run after the span; r11
# still holds the deck's own status record and r12 the fpscr mask the firmware
# applies around every call.
STATUS_SEND = dict(
    sig=[0x018C, 0x0B14, 0xE07E, 0x4008, 0xD33E, 0x430B, 0x04FE, 0x046A, 0xD131],
    start=2,
    end=9,
)

# The DJcont output task's loop (the task at 0x082D86AC), after the call that
# recomputes the play position word 0x09947488 from the DSP's frame: the call
# of its DSP-output step with its delay slot and the fpscr reads around it.
# The loop branches back to its wait right after the span, and nothing
# branches into it. r13 holds the DJcont record, r14 the fpscr mask; r6, the
# mask the loop applies on the way back, comes from the block.
DJCONT_PASS = dict(
    sig=[0xB015, 0x64D3, 0x056A, 0x64D3, 0x25E9, 0xD38F, 0x430B, 0x456A,
         0x066A, 0x26E9, 0xAFD2, 0x466A],
    start=2,
    end=10,
)

# The colour-preview publisher's copy of the 600 six-byte overview records
# into the link slot: the copy's call with its delay slot, then the fpscr read
# and the load after it, which make the span long enough for the jump to the
# trampoline. The hooks run after the copy, with the slot's lock still held.
OVERVIEW_PUBLISH = dict(
    sig=[0x65B3, 0xEB00, 0x2E12, 0xD14E, 0x410B, 0x1E21, 0x026A, 0xD547, 0xD644],
    start=3,
    end=8,
)

# The waveform requester's success path after the firmware has re-encoded the
# builder's PWV5 record: the free of the builder's record, then the stores of
# the new record and its size into the shared context (0x0B531EB8/0x0B531EBC).
# The hooks run after the stores and before the record is published. The only
# branch into the span is the `bf` just before it, which lands on its first
# halfword.
DETAIL_CONVERTED = dict(
    sig=[0x8B08, 0xD67E, 0x4A0B, 0x2F66, 0x096A, 0x57F7, 0x2979, 0x496A, 0xA00C,
         0x7F04, 0xD178, 0xDA7A, 0x4A0B, 0x5417, 0xD276, 0x0B6A, 0x5CF4, 0x5DF3,
         0x2BE9, 0x12C7, 0x4B6A, 0x12D8, 0x65F2, 0xD675, 0x460B],
    start=10,
    end=22,
)

# The colour-preview reader's call to the PWV4 tag reader, from the push of
# the tag's entry count to the argument setup before the call: the span has no
# branch and nothing branches into it. r13 holds the open ANLZ handle and the
# saved r5 the track's hash, both the reader's own arguments; the hooks run
# before the reader, which is before the preview is published.
PREVIEW_READ = dict(
    sig=[0x60E3, 0x8801, 0x8F0F, 0x426A, 0xE805, 0x4818, 0x78B0, 0x2F86,
         0x67F3, 0x66F3, 0x55F2, 0x7714, 0x7618, 0xB25E, 0x64D3, 0x0C6A,
         0x2CA9, 0x4C6A, 0x7F04, 0xDE7E],
    start=4,
    end=13,
)


# What each routine imports: its stock (v1.87) value and where the image being
# patched has it -- see anchors.py. The words handed from one routine to
# another sit in the last bytes of the erased run (FreeEnd), out of reach of
# the placed code.
TICK = (0x0B0C5258, A.tick)
TICK_GETTER = (0x08221D9E, A.tick_getter)
DEVICE = (0x0AB84CFA, A.device)
UDP_WRAP = (0x085113EC, A.udp_wrap)
MALLOC = (0x08344A9C, A.malloc)
FREE = (0x08344B42, A.free)
MEMSET = (0x08533D50, A.memset)
TAG_FETCH = (0x082545F8, A.anlz_tag_fetch)
TAG_HELPERS = ((0x085336DC, A.tag_helper1), (0x085341D4, A.tag_helper2))
OVERVIEW_SLOT = (0x0B569528, A.overview_slot)
LINK_COMMON = (TICK, TICK_GETTER, DEVICE)
TCNET_COMMON = (TICK, TICK_GETTER, UDP_WRAP, DEVICE)
TCNET_RECORDS = ((0x0A371D3C, A.player_records), (0x09947488, A.play_position),
                 (0x0B5125E8, A.track_length))

IMPORTS = {
    'wave3data': ((0x08289E98, A.anlz_pwv5_read), (0x0827A34E, A.anlz_close), MALLOC, FREE,
                  (0x081FFFF4, FreeEnd(-12)), TAG_FETCH, MEMSET) + TAG_HELPERS,
    'wave3detail': ((0x081FFFF4, FreeEnd(-12)), (0x0B531EB8, A.detail_record)),
    'wave3ovdata': ((0x081FFFFC, FreeEnd(-4)), OVERVIEW_SLOT),
    'wave3ovfetch': (MALLOC, FREE, (0x081FFFFC, FreeEnd(-4)), TAG_FETCH, MEMSET) + TAG_HELPERS,
    'phrasefetch': ((0x081FFFF0, FreeEnd(-16)), FREE, MALLOC, MEMSET, TAG_FETCH),
    'phrasedata': ((0x081FFFF0, FreeEnd(-16)), OVERVIEW_SLOT),
    'abletonlink': LINK_COMMON,
    'abletonlinkpong': ((0x0AB84CE8, A.link_cep), (0x0AB84CDC, A.link_pool),
                        (0x08233CF6, A.udp_snd_dat), (0x08518DA8, A.link_release)) + LINK_COMMON,
    'osc': (DEVICE, (0x0A35F39C, A.master), TICK, UDP_WRAP),
    'oscbeat': (TICK,),
    'tcnet': TCNET_COMMON,
    'tcnettime': TCNET_RECORDS + TCNET_COMMON,
    'tcnetdata': TCNET_RECORDS + TCNET_COMMON + (
        (0x0994DE40, A.title), (0x0994E040, A.artist), (0x08233A22, A.udp_vcre_cep),
        (0x0823415E, A.udp_rcv_dat), (0x08233CF6, A.udp_snd_dat)),
    'usbmidi': ((0x084F511E, A.usb_midi_fill), (0x084F5148, A.usb_midi_commit),
                (0x0BD4B0F0, A.midi_bufidx), (0x0BD4B0F4, A.midi_lens)),
    'usbmiditick': (DEVICE, (0x0A371E60, A.player1_record), (0x0BD4B0F4, A.midi_lens),
                    (0x0BD50E8C, A.midi_taskstate), (0x0BD4B0C8, A.midi_classflags),
                    (0x08516448, A.set_flag)),
}

MODS = {
    # The detail-waveform builder's own PWV5 fetch, right after it returns:
    # r15+8/+12 still hold the &out_ptr/&out_size the fetch wrote into (read
    # again a few instructions later, once this call site resumes, to fill
    # the shared ctx's own RGB fields), r10 still holds the fetch's hash
    # argument, and the ANLZ handle this call opened is at r15+16 -- all of
    # it live only in this one span, which is why the hook sits exactly
    # here rather than earlier or later in the same function. r6/r7/r10 and
    # the bsr are reproduced first, so the RGB path is untouched whether or
    # not this mod's own fetches below succeed.
    'wave3data': Mod(
        what='3-band detail waveform data fetch (PWV7)',
        target='main',
        fw_versions=('1.87',),
        sig=[0x67F3, 0x66F3, 0x7708, 0x65A3, 0x760C, 0xDA18, 0xBC7B, 0x1FE5],
        start=0,
        end=8,
        args=[],
        literal=False,
        imports=IMPORTS['wave3data'],
    ),
    # Hooks DETAIL_CONVERTED: writes the words the wave3data mod packed into the
    # re-encoded waveform record, reading its buffer through two words at fixed
    # addresses (see main_wave3data.s).
    'wave3detail': Mod(
        what='3-band detail waveform data (PWV7 in the waveform record)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['wave3detail'],
        hook=True,
        **DETAIL_CONVERTED,
    ),
    # Hooks OVERVIEW_PUBLISH: writes the PWV6 bands the wave3ovfetch mod kept
    # into the overview payload, reading that mod's buffer through a word at a
    # fixed address (see main_wave3ovfetch.s).
    'wave3ovdata': Mod(
        what='3-band overview data (PWV6 in the overview payload)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['wave3ovdata'],
        hook=True,
        **OVERVIEW_PUBLISH,
    ),
    # Hooks PREVIEW_READ: reads and packs the track's PWV6 for wave3ovdata.
    'wave3ovfetch': Mod(
        what='3-band overview data fetch (PWV6)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['wave3ovfetch'],
        hook=True,
        **PREVIEW_READ,
    ),
    # Hooks PREVIEW_READ: reads the track's PSSI and beat grid and reduces them
    # to the 600-column phrase table phrasedata writes.
    'phrasefetch': Mod(
        what='phrase analysis (PSSI) read and reduced to overview columns',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['phrasefetch'],
        hook=True,
        **PREVIEW_READ,
    ),
    # Hooks OVERVIEW_PUBLISH: writes the phrase table phrasefetch kept into the
    # overview records' spare bits (see main_phrasedata.s).
    'phrasedata': Mod(
        what='phrase colours in the overview payload',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['phrasedata'],
        hook=True,
        **OVERVIEW_PUBLISH,
    ),
    'abletonlink': Mod(
        what='Ableton Link announcements (UDP 20808)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['abletonlink'],
        hook=True,
        **BEAT_SEND,
    ),
    'abletonlinkpong': Mod(
        what='Ableton Link measurement replies (UDP 50000)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['abletonlinkpong'],
        hook=True,
        **LINK_RECEIVE,
    ),
    'osc': Mod(
        what='OSC deck state and load/play/stop/cue/loop events (UDP 50010)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['osc'],
        hook=True,
        **STATUS_SEND,
    ),
    'oscbeat': Mod(
        what='OSC per-beat output (UDP 50010)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['oscbeat'],
        hook=True,
        **BEAT_SEND,
    ),
    'tcnet': Mod(
        what='TCNet Opt-IN and Status, once a second (UDP 60000)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['tcnet'],
        hook=True,
        **STATUS_SEND,
    ),
    'tcnettime': Mod(
        what='TCNet Time packets, every 20 ms (UDP 60001)',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['tcnettime'],
        hook=True,
        **DJCONT_PASS,
    ),
    'tcnetdata': Mod(
        what='TCNet listener (UDP 65023): Metrics and MetaData to requesting nodes',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['tcnetdata'],
        hook=True,
        **DJCONT_PASS,
    ),
    'usbmidi': Mod(
        what='USB-MIDI start/stop/clock, sending',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['usbmidi'],
        hook=True,
        **MIDI_TASK,
    ),
    'usbmiditick': Mod(
        what='USB-MIDI start/stop/clock, 1 ms timing',
        target='main',
        fw_versions=('1.87',),
        args=[],
        literal=False,
        imports=IMPORTS['usbmiditick'],
        hook=True,
        **TIMER_TICK,
    ),
}


# The XDJ-700 UI task's call to the key table's initialisation (the table at
# 0x0BA39730, 16 bytes a key), with the first instructions after it: the loads of
# the init and the fpscr mask, the call with its delay slot, the first fpscr
# read and the load after it. The hook runs after the table is filled in, which
# is when the INFO key's slot can be replaced.
KEY_TABLE_INIT = dict(
    sig=[0x2FE6, 0x4F22, 0xD12F, 0xDE30, 0x410B, 0x0009, 0x046A, 0xD22F,
         0x24E9, 0x420B, 0x446A, 0x056A, 0xD72D, 0x25E9],
    start=2,
    end=8,
)

XDJ700_MODS = {
    'trackfilter': Mod(
        what='BPM filter on a long press of INFO',
        target='main',
        fw_versions=('1.15',),
        args=[],
        literal=False,
        imports=((0x0BA39730, A.key_table), (0x08DB0DF4, A.browse_mode),
                 (0x08DAB83A, A.update_list), (0x08B34CC0, A.set_filter_onoff),
                 (0x08B34D5A, A.set_filter_condition), (0x08CE4FD0, A.list_refresh_conditions),
                 (0x08CE5068, A.list_refresh_switch), (0x0B0E0E98, A.list_context),
                 (0x0960375C, A.filter_state._replace(delta=0xE8)), (0x0C0E6B74, A.deck_bpm)),
        hook=True,
        **KEY_TABLE_INIT,
    ),
}


# The MAIN patches of each model. The CDJ-2000NXS2's and the XDJ-700's SH7724
# firmware are covered so far; the other players' MAIN images have no routines yet.
PATCH_SETS = {modelfw.DEFAULT_MODEL: sigpatch.PatchSet(MAIN_PROFILE, MODS),
              'xdj700': sigpatch.PatchSet(XDJ700_PROFILE, XDJ700_MODS)}


def mods_for(model):
    return PATCH_SETS[model].mods if model in PATCH_SETS else {}


def every_mod():
    return {name for patches in PATCH_SETS.values() for name in patches.mods}


def source(name, model=modelfw.DEFAULT_MODEL):
    """Each routine sits in its own mod's folder, mods/<mod>/ (mods/<mod>/<model>/
    for a model other than the default)."""
    return modelfw.routine_source('main', name, model)


def blob_path(name, model=modelfw.DEFAULT_MODEL):
    return source(name, model)[:-2] + '.bin'


def patch(data, names, model=modelfw.DEFAULT_MODEL, report=None, spans=None):
    return sigpatch.patch_model(PATCH_SETS, blob_path, data, names, model, 'patch_main', report, spans)


def patch_flash(flash, names, model=modelfw.DEFAULT_MODEL, report=None):
    """Patch the packed MAIN application directly inside a flat flash image
    (flash.bin's own bytes, not the unpacked one -kernel loads)."""
    off = modelfw.load(model).main_off
    window_end = modelfw.UPDATE_WINDOW_END.get(model)
    if window_end is None:
        raise SystemExit('patch_main: the update window of %s is not known' % model)
    _, image = main_decode.decode_image(flash, off)
    patched = patch(image, names, model, report)
    packed = main_encode.encode_image(patched)
    if len(packed) > window_end - off:
        raise SystemExit('patch_main: patched image (%d bytes) does not fit '
                         'the flash window' % len(packed))
    out = bytearray(flash)
    lo, hi = off, window_end
    out[lo:hi] = b'\xff' * (hi - lo)      # erase the window, as the real updater does
    out[lo:lo + len(packed)] = packed
    return bytes(out)


def assemble():
    with tempfile.TemporaryDirectory() as tmp:
        for model, patches in PATCH_SETS.items():
            for name in patches.mods:
                obj = os.path.join(tmp, name + '.o')
                subprocess.run(['sh4-linux-gnu-as', '--isa=sh4', '-little',
                                '-I', os.path.dirname(source(name, model)),
                                '-o', obj, source(name, model)], check=True)
                subprocess.run(['sh4-linux-gnu-objcopy', '-O', 'binary',
                                obj, blob_path(name, model)], check=True)
                print('patch_main: wrote %s (%d bytes)'
                      % (blob_path(name, model), os.path.getsize(blob_path(name, model))))


def main():
    model, args = modelfw.model_id(sys.argv[1:])
    if args == ['--assemble']:
        assemble()
        return
    if args == ['--list']:
        for name, mod in mods_for(model).items():
            print('%-8s %s' % (name, mod.what))
        return
    if args[:1] == ['--flash']:
        args = args[1:]
        flasher = True
    else:
        flasher = False
    if len(args) < 3 or any(n not in every_mod() for n in args[2:]):
        raise SystemExit(__doc__)
    with open(args[0], 'rb') as f:
        data = f.read()
    out = patch_flash(data, args[2:], model) if flasher else patch(data, args[2:], model)
    with open(args[1], 'wb') as f:
        f.write(out)


if __name__ == '__main__':
    main()
