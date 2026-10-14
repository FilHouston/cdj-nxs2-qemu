# SPDX-License-Identifier: GPL-2.0-or-later
"""Where the routines find the firmware addresses they use: the CDJ-2000NXS2's
below, the XDJ-700's in its own section.

A routine holds the address its firmware has (MAIN 1.87, display 1.81) as a
stock value, and Mod.imports names the Anchor that finds the same thing in
whatever image is being patched. An anchor is a stretch of the firmware's own
instructions around a place that loads the address (literal=True: the value of
that mov.l @(disp,pc) literal) or that is the address (literal=False), kept
unique in the image and clear of every span a mod replaces. Data that the
firmware only reaches through a nearby base is the base's anchor plus a delta.

SoC registers (0xFFD90018 TCNT4, 0xA4D90040 USB1 INTSTS0, 0xFFE7FFFF fpscr
mask) are the chip's, not the firmware's, and stay in the routines.
"""
from sigpatch import Anchor

# -- MAIN (SH7724, little-endian) --------------------------------------------

# code
udp_wrap = Anchor(sig=[0xE01F, 0x0464, 0xE020, 0xD66B, 0x04C4, 0xEC3C], index=3, literal=True)           # 0x085113EC UDP send wrapper
tick_getter = Anchor(sig=[0x7F08, 0xDD32, 0x076A, 0xD234, 0x65F3, 0x64E3], index=3, literal=True)        # 0x08221D9E reads the tick word
udp_snd_dat = Anchor(sig=[0xE500, 0x2F56, 0x096A, 0xD150, 0x65F3, 0x56A2], index=3, literal=True)        # 0x08233CF6 udp_snd_dat
udp_vcre_cep = Anchor(sig=[0xEE03, 0xD477, 0x4E18, 0xD777, 0x7EFC, 0xE014], index=3, literal=True)       # 0x08233A22 udp_vcre_cep
udp_rcv_dat = Anchor(sig=[0x0009, 0x6EF3, 0xDD2C, 0xEA00, 0x2FA6, 0x65E3], index=2, literal=True)        # 0x0823415E udp_rcv_dat
link_release = Anchor(sig=[0x1F21, 0xDC8D, 0xDB8D, 0xDD8E, 0xDE8E, 0xD98F], index=3, literal=True)       # 0x08518DA8 frees a Pro DJ Link datagram block
anlz_pwv5_read = Anchor(sig=[0x1F12, 0xD128, 0x66F3, 0x55FC, 0xE400, 0x1F41], index=1, literal=True)    # 0x08289E98 PWV5/EXT reader
anlz_close = Anchor(sig=[0x4D0B, 0x456A, 0x076A, 0xD119, 0x64C3, 0x27E9], index=3, literal=True)         # 0x0827A34E ANLZ close-handle call
malloc = Anchor(sig=[0x22A9, 0x8D1A, 0x426A, 0xD557, 0xE101, 0xE404], index=3, literal=True)             # 0x08344A9C
free = Anchor(sig=[0x6073, 0x8D08, 0x81FF, 0xD52F, 0x450B, 0x0009], index=3, literal=True)               # 0x08344B42
anlz_tag_fetch = Anchor(sig=[0x372C, 0x2F76, 0x7004, 0xD145, 0xD746, 0x64E3], index=3, literal=True)     # 0x082545F8 generic tag fetch
tag_helper1 = Anchor(sig=[0xE0FE, 0xD777, 0x65D3, 0x64F3, 0x7504, 0x7404], index=1, literal=True)        # 0x085336DC
tag_helper2 = Anchor(sig=[0x0009, 0xD79E, 0x64B3, 0xD59E, 0x470B, 0xE604], index=1, literal=True)        # 0x085341D4
memset = Anchor(sig=[0x4F26, 0x2FE6, 0x4F22, 0x7FDC, 0xD17C, 0x64F3], index=4, literal=True)             # 0x08533D50
usb_midi_fill = Anchor(sig=[0x2521, 0xE200, 0x2420, 0xD16F, 0xDC70, 0x410B], index=3, literal=True)      # 0x084F511E
usb_midi_commit = Anchor(sig=[0x2008, 0x8D04, 0x6403, 0xD216, 0x420B, 0x4408], index=3, literal=True)    # 0x084F5148
set_flag = Anchor(sig=[0x60D3, 0xDE69, 0xE501, 0xD773, 0x2219, 0x426A], index=3, literal=True)           # 0x08516448 sets an event flag

# data
device = Anchor(sig=[0x4D0B, 0x446A, 0x056A, 0xD453, 0x25B9, 0x456A], index=3, literal=True)             # 0x0AB84CFA the device record
link_cep = Anchor(sig=[0x5BA4, 0x7B01, 0x1AB4, 0xD222, 0x22E2, 0x4F26], index=3, literal=True)           # 0x0AB84CE8 Pro DJ Link endpoint
link_pool = Anchor(sig=[0x2279, 0x8F2B, 0x426A, 0xD146, 0x65F3, 0xD746], index=3, literal=True)          # 0x0AB84CDC Pro DJ Link datagram pool
master = Anchor(sig=[0x0E24, 0x2228, 0x8906, 0xD421, 0x6640, 0x626C], index=3, literal=True)             # 0x0A35F39C sync master word
tick = Anchor(sig=[0x2FD6, 0x4F22, 0x7FFC, 0xD18A, 0xEDCE, 0x4D18], index=3, literal=True)               # 0x0B0C5258 1 ms tick word
track_length = Anchor(sig=[0x0009, 0xE200, 0x2522, 0xD55F, 0x6052, 0x88FF], index=3, literal=True)       # 0x0B5125E8
player_records = Anchor(sig=[0xE749, 0x016A, 0x4708, 0xD977, 0x07E7, 0x041A], index=3, literal=True)     # 0x0A371D3C
midi_bufidx = Anchor(sig=[0x000B, 0x0005, 0xD15A, 0xD95B, 0x410B, 0xE401], index=3, literal=True)        # 0x0BD4B0F0
midi_lens = Anchor(sig=[0x096A, 0x66F2, 0xE401, 0xD255, 0x4008, 0xD555], index=3, literal=True)          # 0x0BD4B0F4
midi_taskstate = Anchor(sig=[0xDD22, 0x056A, 0xE100, 0xDE22, 0xE614, 0xD422], index=3, literal=True)     # 0x0BD50E8C
midi_classflags = Anchor(sig=[0x4008, 0x470B, 0x02E6, 0xD71E, 0x0E6A, 0xD621], index=3, literal=True)    # 0x0BD4B0C8

# data the firmware reaches only through a base a little before it
overview_slot = Anchor(sig=[0x056A, 0x61E2, 0x52E1, 0xE60E, 0xDE54, 0x4618], index=4, literal=True, delta=0x8)    # 0x0B569528
play_position = Anchor(sig=[0x420B, 0x0009, 0x2008, 0xD577, 0x8B02, 0x4F26], index=3, literal=True, delta=0x10)   # 0x09947488
title = Anchor(sig=[0xE10A, 0xE709, 0x0DB6, 0xDB5C, 0x24E2, 0x1411], index=3, literal=True, delta=0x20C)          # 0x0994DE40
artist = Anchor(sig=[0xE10A, 0xE709, 0x0DB6, 0xDB5C, 0x24E2, 0x1411], index=3, literal=True, delta=0x40C)         # 0x0994E040
detail_record = Anchor(sig=[0x4E0B, 0x476A, 0x0A6A, 0xD46B, 0x1BD3, 0x1BD4], index=3, literal=True, delta=0x8)    # 0x0B531EB8
player1_record = player_records._replace(delta=0x124)                                                              # 0x0A371E60

# -- display (SH7269, big-endian) --------------------------------------------

records = Anchor(sig=[0x0009, 0x3DF1, 0x6194, 0xD141, 0xD241, 0x0000], index=3, literal=True)            # 0x0E5BB45C the 600 overview records

# -- XDJ-700 MAIN (SH7724, little-endian), v1.15 --------------------------------

key_table = Anchor(sig=[0x08CF, 0xD576, 0xE28C, 0xD176, 0x602C, 0xD476], index=1, literal=True)          # 0x0BA39730 12 keys, 16 bytes each, the handler at +12
browse_mode = Anchor(sig=[0xD141, 0x410B, 0x0009, 0x046A, 0xD640, 0x24E9], index=4, literal=True)        # 0x08DB0DF4 browse mode of the UI
update_list = Anchor(sig=[0x8905, 0xD121, 0x410B, 0x0009, 0x026A, 0x22E9], index=1, literal=True)        # 0x08DAB83A BROWSE_CMD UPDATE_LIST
set_filter_onoff = Anchor(sig=[0xD266, 0x2118, 0x8D11, 0x656C, 0x420B, 0xE601], index=0, literal=True)   # 0x08B34CC0 the DB server's filter switch
set_filter_condition = Anchor(sig=[0x56E4, 0x2F66, 0xD93B, 0x57E3, 0x56E2, 0x55E1], index=2, literal=True)   # 0x08B34D5A
list_refresh_conditions = Anchor(sig=[0xD237, 0x65E2, 0x6D03, 0xD431, 0x1F98, 0x2199], index=0, literal=True)   # 0x08CE4FD0
list_refresh_switch = Anchor(sig=[0xD163, 0x6D03, 0x65E2, 0xD463, 0x2929, 0x1F2A], index=0, literal=True)        # 0x08CE5068
list_context = Anchor(sig=[0xD44E, 0x470B, 0xE600, 0x096A, 0xD14D, 0x64F3], index=0, literal=True)       # 0x0B0E0E98 the list server's context
filter_state = Anchor(sig=[0xD16F, 0xE805, 0xE900, 0xDA71, 0x6613, 0x717F], index=0, literal=True)       # 0x09603674 the USB filter's state block
deck_bpm = Anchor(sig=[0xD79C, 0x0A1A, 0x36A8, 0x5472, 0x666C, 0x3E45], index=0, literal=True, delta=8)  # 0x0C0E6B74 the deck's BPM x 10
