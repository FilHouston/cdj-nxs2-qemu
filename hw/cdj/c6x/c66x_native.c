/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * C66x core: native forms of hot pure DSP kernels.
 *
 * A kernel is a loop whose body reads and writes only RAM and registers. Its
 * native form runs whole passes of that loop from the loop head: each pass
 * produces exactly the registers, control registers, stores and cycle count
 * the interpreter would, so the core is in the interpreter's own state at the
 * pass boundary, and anything the native form does not cover (a pass that
 * would cross the end of the step, a pointer outside RAM, a directed rounding
 * mode) is simply run by the interpreter from there.
 *
 * Interrupts are raised only between c66x_step calls, and none of these loops
 * touches IER, ISR or the bus, so a pass that ends inside the step with no
 * interrupt deliverable at its start cannot have been interrupted.
 *
 * A kernel is found by its code, not by its address, so a firmware release
 * that moves it still runs natively: the decoded code is searched for the
 * kernel's bytes, leaving out the fields a relink changes (absolute addresses
 * built by MVK/MVKH, branches out of the kernel). The native form takes its
 * code addresses from where the match is and its data addresses from the
 * matched MVK/MVKH pairs. A kernel found nowhere, or in more than one place,
 * runs on the interpreter.
 */
#include "c66x_priv.h"

#define A(n) (n)
#define B(n) (32 + (n))

typedef struct native_state {
    uint32_t reg[C66X_NREGS];
    uint32_t cr[32];
    uint32_t pc;                    /* where the pass ended */
    uint32_t last_pc;               /* the last packet it executed */
    uint32_t cycles, packets, insns, sploops;
    uint32_t pm_resume;             /* pm_resume_at, cycles after the pass start; 0 = untouched */
    uint32_t branch_block;          /* 5 unless the pass ends in a branch's delay slot */
    unsigned nst;
    struct { uint32_t a, v, pc; } st[5];
    uint32_t at;                    /* in: where the kernel's code was found */
    uint32_t addr[2];               /* in: the data addresses its MVK/MVKH pairs build */
} native_state;

/* An instruction field a relink changes, left out of the comparison. The
 * 16-bit constant of an MVK or MVKH also gives the low or high half of addr[n]. */
typedef struct native_wild {
    uint16_t off;                   /* the instruction word, from the start of the code */
    int8_t addr;                    /* -1, or the addr[] it gives half of */
    uint8_t high;
    uint32_t mask;
} native_wild;

#define MVK_CST 0x007FFF80u         /* cst16 of a 32-bit MVK/MVKH */
#define ADDR_LO(off, n) { off, n, 0, MVK_CST }
#define ADDR_HI(off, n) { off, n, 1, MVK_CST }
#define WILD(off, mask) { off, -1, 0, mask }

/* tools/native_sig.py prints first, size and hash for a stretch of an image. */
typedef struct native_kernel {
    const char *name;
    uint32_t first;                 /* the first word of the code (never a wild one) */
    uint32_t size;                  /* bytes of code from a fetch packet start, wild fields included */
    uint64_t hash;                  /* FNV-1a of those bytes with the wild fields cleared */
    uint32_t entry;                 /* the loop head, from the start of the code */
    uint32_t exit;                  /* where the last pass ends, from the start of the code, or RETURNS */
    const native_wild *wild;
    unsigned nwild;
    int (*pass)(c66x_core *c, native_state *s);   /* 0: not natively (the code runs) */
} native_kernel;

#define NATIVE_SIZE_MAX 4096        /* the longest stretch a signature may cover */
#define RETURNS 0xFFFFFFFFu         /* a function: its one pass ends at B3 */

static inline float u2f(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }
static inline uint32_t f2u(float f) { uint32_t v; memcpy(&v, &f, 4); return v; }

static inline uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* ------------------------------------------------------------------------ */
/* polyphase FIR, one output per pass (NXS2: 0x800169AC)                    */

/* fir(in A4, out B4, count A6, channel B6). Per output: phase p = *++B16,
 * input offset k = *++A18 and h = the halfword at A19 + 4. While p <= h >> 1
 * the output is a 29-tap dot product of in[k..k+28] with the coefficient row
 * B9 + 116 p, summed in one serial faddsp chain starting from A20. Otherwise
 * a SPLOOP (14 iterations from ILC 12) sums in[k..k+27] against the row
 * R = B9 + 116 (h - p) read backwards, in two interleaved partial sums, and
 * the centre tap in[k+28] takes its coefficient from the channel's table at
 * *(addr[0] + 4 ch), addr[0] being 0x0088B2E0 on the NXS2. The pass costs
 * and counters below were measured on the interpreter and hold for every
 * pass of both paths. */

static int fir_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;

    if (((s->cr[CR_FADCR] | s->cr[CR_FMCR]) & (3u << 9 | 3u << 25))
        || r[A(27)] != 104 || r[B(27)] != 104 || r[A(28)] != 88 || r[B(28)] != 88
        || r[A(29)] != 72 || r[B(29)] != 72 || r[B(30)] != 56)
        return 0;
    const uint8_t *pp = ram_ptr(c, r[B(16)] + 4, 4), *kp = ram_ptr(c, r[A(18)] + 4, 4);
    const uint8_t *hp = ram_ptr(c, r[A(19)] + 4, 2);
    if (!pp || !kp || !hp || !ram_ptr(c, r[A(17)], 4))
        return 0;
    uint32_t p = ld32(pp), k = ld32(kp);
    int32_t h = (int16_t)(hp[0] | hp[1] << 8);
    uint32_t in = r[A(16)] + 4 * k;
    float acc;

    if (!((int32_t)p > h >> 1)) {
        uint32_t row = r[B(9)] + (uint32_t)(116 * (int64_t)(int32_t)p);
        const uint8_t *xp = ram_ptr(c, in, 116), *cp = ram_ptr(c, row, 116);
        if (!xp || !cp)
            return 0;
        float x[29], cf[29], pr[29];
        memcpy(x, xp, sizeof x);
        memcpy(cf, cp, sizeof cf);
        for (int i = 0; i < 29; i++)
            pr[i] = x[i] * cf[i];
        acc = u2f(r[A(20)]) + pr[0];
        for (int i = 1; i < 25; i++)
            acc = pr[i] + acc;
        float s25 = pr[25] + acc, s26 = pr[26] + s25, s27 = pr[27] + s26;
        acc = pr[28] + s27;
        r[A(4)] = f2u(s27);
        r[A(5)] = f2u(pr[27]);
        r[A(6)] = f2u(s25);
        r[A(7)] = in + 112;
        r[A(8)] = f2u(pr[24]);
        r[A(9)] = f2u(pr[25]);
        r[A(22)] = f2u(pr[22]);
        r[A(23)] = f2u(pr[23]);
        r[A(24)] = f2u(pr[12]);
        r[A(25)] = f2u(pr[13]);
        r[A(26)] = f2u(x[28]);
        r[A(30)] = 56;
        r[A(31)] = 32;
        r[B(1)] = 0;
        r[B(4)] = 96;
        r[B(5)] = row;
        r[B(6)] = f2u(cf[26]);
        r[B(7)] = f2u(cf[27]);
        r[B(26)] = f2u(cf[28]);
        r[B(31)] = 32;
        s->cycles = 131;
        s->packets = 105;
        s->insns = 128;
    } else {
        uint32_t rrow = r[B(9)] - (uint32_t)(116 * (int64_t)(int32_t)p) + (uint32_t)(116 * h);
        const uint8_t *xp = ram_ptr(c, in, 116), *cp = ram_ptr(c, rrow, 112);
        const uint8_t *tp = ram_ptr(c, s->addr[0] + r[B(17)], 4);
        if (!xp || !cp || !tp)
            return 0;
        uint32_t tab = ld32(tp) + 4 * p - ((2 * (uint32_t)h) & ~3u) - 4;
        const uint8_t *ctr = ram_ptr(c, tab, 4);
        if (!ctr)
            return 0;
        float x[29], cf[28];
        memcpy(x, xp, sizeof x);
        memcpy(cf, cp, sizeof cf);
        float sa = u2f(r[A(20)]), sb = sa;
        for (int j = 0; j < 14; j++) {
            sa = cf[26 - 2 * j] * x[2 * j + 1] + sa;
            sb = cf[27 - 2 * j] * x[2 * j] + sb;
        }
        float cc = u2f(ld32(ctr));
        acc = x[28] * cc + (sa + sb);
        r[A(4)] = f2u(x[26]);
        r[A(5)] = f2u(x[27]);
        r[A(6)] = f2u(sa);
        r[A(7)] = in + 112;
        r[A(8)] = rrow - 8;
        r[A(9)] = (uint32_t)h;
        r[A(30)] = f2u(sa + sb);
        r[A(31)] = f2u(x[28]);
        r[B(1)] = 1;
        r[B(4)] = f2u(cc);
        r[B(5)] = f2u(sb);
        r[B(6)] = rrow - 4;
        r[B(7)] = p;
        r[B(8)] = ld32(tp);
        r[B(31)] = 12;
        s->cr[CR_ILC] = 0;
        s->sploops = 1;
        s->cycles = 111;
        s->packets = 43;
        s->insns = 149;
        s->pm_resume = 84;
    }
    r[A(3)] = f2u(acc);
    r[B(16)] += 4;
    r[A(18)] += 4;
    s->st[0].a = r[A(17)];
    s->st[0].v = f2u(acc);
    s->st[0].pc = s->at + 0x2B0;
    s->nst = 1;
    r[A(17)] += 4;
    r[B(0)] -= 1;
    s->pc = s->at + (r[B(0)] ? 0x18 : 0x2BC);
    s->last_pc = s->at + 0x2B8;
    return 1;
}

/* the MVK/MVKH pair of the centre-tap table */
static const native_wild fir_wild[] = { ADDR_LO(0x210, 0), ADDR_HI(0x21C, 0) };

/* ------------------------------------------------------------------------ */
/* ring-descriptor walk, one step per pass (NXS2: 0x800091C4)              */

/* The loop walks B2 steps through a ring of four 40-byte descriptors (A5 the
 * current one, B5 its index, B6 the sample position in it, counting down). A
 * step moves to the previous descriptor when the position runs out (into 294
 * more samples), and once more when that descriptor's word +28 is 1 and its
 * word +32 is not above the position (to position 293). The pass covers steps
 * that end on a descriptor whose word +28 is non-zero; the other branch is
 * left to the interpreter. 37 cycles a step, measured on the interpreter. */

static int ring_walk_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;
    uint32_t a5 = r[A(5)], b5 = r[B(5)], b6 = r[B(6)];
    uint32_t a0 = (int32_t)b6 < 1, b0 = 0, b1 = 0;

    b6 -= 1;
    if (a0) {
        b6 += 294;
        a5 -= 40;
        b0 = (int32_t)b5 < 1;
        b5 -= 1;
    }
    if (b0) {
        a5 += 160;
        b5 += 4;
    }
    const uint8_t *d = ram_ptr(c, a5 + 28, 8);
    if (!d)
        return 0;
    uint32_t a6 = ld32(d + 4);
    uint32_t a3 = ld32(d) == 1;
    uint32_t b7 = !((int32_t)b6 > (int32_t)a6);
    b0 = b7 & a3;
    if (b0) {
        a5 -= 40;
        b6 = 293;
        b1 = (int32_t)b5 < 1;
        b5 -= 1;
    }
    if (b1) {
        a5 += 160;
        b5 += 4;
    }
    d = ram_ptr(c, a5 + 28, 4);
    if (!d || !ld32(d))
        return 0;
    r[A(0)] = ld32(d);
    r[A(3)] = a3;
    r[A(5)] = a5;
    r[A(6)] = a6;
    r[B(0)] = b0;
    r[B(1)] = b1;
    r[B(5)] = b5;
    r[B(6)] = b6;
    r[B(7)] = b7;
    r[B(2)] -= 1;
    s->pc = s->at + (r[B(2)] ? 0x18 : 0xC0);
    s->last_pc = s->at + 0xBC;
    s->cycles = 37;
    s->packets = 23;
    s->insns = 30;
    return 1;
}

/* the MVK/MVKH pair of the prologue's descriptor ring, which the pass does not use */
static const native_wild ring_walk_wild[] = { WILD(0x08, MVK_CST), WILD(0x0C, MVK_CST) };

/* ------------------------------------------------------------------------ */
/* cubic interpolator, one call per pass (NXS2: 0x80010BD8)                 */

static inline int directed_rounding(const native_state *s)
{
    return ((s->cr[CR_FADCR] | s->cr[CR_FMCR]) & (3u << 9 | 3u << 25)) != 0;
}

static inline int same_word(uint32_t a, uint32_t b)
{
    return a - b + 3 < 7;
}

/* interp(x A4, samples B4 A6 B6 A8), registers only: the Lagrange cubic
 * through four samples at fraction x, with the constants 2.0, 0.5 and 1/6
 * the code builds itself. The op order and every register it leaves are the
 * code's; 40 cycles a call, measured on the interpreter. */

static int interp_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;

    if (directed_rounding(s))
        return 0;
    float x = u2f(r[A(4)]), s0 = u2f(r[B(4)]), s1 = u2f(r[A(6)]), s2 = u2f(r[B(6)]), s3 = u2f(r[A(8)]);
    float x2 = x * x;
    float x3 = x * x2;
    float a9 = x2 + x2;
    float b5 = s0 * x2;
    float a7 = x3 - x;
    float a4 = x + x;
    float a17 = x3 - x2;
    a9 = a7 - a9;
    float a5 = a4 + x3;
    a17 = a17 - a4;
    a9 = 2.0f + a9;
    float a3 = s3 * a7;
    float a16 = a17 * s2;
    a4 = s1 * a9;
    float b6 = s0 * a5;
    a4 = a4 - a16;
    b5 = b5 + a4;
    a4 = a3 - b6;
    float b4 = 0.5f * b5;
    a3 = u2f(0x3E2AAAAB) * a4;
    a4 = a3 + b4;
    r[A(3)] = f2u(a3);
    r[A(4)] = f2u(a4);
    r[A(5)] = f2u(a5);
    r[A(7)] = f2u(a7);
    r[A(9)] = f2u(a9);
    r[A(16)] = f2u(a16);
    r[A(17)] = f2u(a17);
    r[B(4)] = f2u(b4);
    r[B(5)] = f2u(b5);
    r[B(6)] = f2u(b6);
    s->pc = r[B(3)];
    s->last_pc = s->at + 0x98;
    s->cycles = 40;
    s->packets = 31;
    s->insns = 32;
    return 1;
}

static const native_wild interp_wild[] = { };

/* ------------------------------------------------------------------------ */
/* two-pole filter step with a +-2.0 clip, one call per pass (NXS2: 0x80010C5C) */

/* step(A4 A6 A8 A10 A12 B4 B6 B8 B10 state and coefficient pointers): two
 * cascaded sections, each x - a * y[0] scaled by b and stored, then checked
 * against +-2.0. The clip branches are left to the interpreter. A12 is saved
 * on the stack across the call. One store may land where a later load reads:
 * then too the interpreter runs the call. 84 cycles, measured on the
 * interpreter. */

static int filter_step_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;

    if (directed_rounding(s))
        return 0;
    uint32_t a12 = r[A(12)], b15 = r[B(15)], b6 = r[B(6)], b10 = r[B(10)];
    const uint8_t *y0p = ram_ptr(c, a12, 8), *ap = ram_ptr(c, r[A(6)], 4), *xp = ram_ptr(c, r[A(4)], 4);
    const uint8_t *bp = ram_ptr(c, r[B(4)], 8), *a2p = ram_ptr(c, r[A(10)], 4), *x2p = ram_ptr(c, r[A(8)], 4);
    const uint8_t *b2p = ram_ptr(c, r[B(8)], 8);
    if (!y0p || !ap || !xp || !bp || !a2p || !x2p || !b2p || !ram_ptr(c, b15, 4) || !ram_ptr(c, b6, 4)
        || !ram_ptr(c, b10, 4))
        return 0;
    /* every load after the stack store, the second section's after the
     * first section's stores, and the reload of A12 after all of them */
    const uint32_t first[] = { a12, r[A(6)], r[A(4)], r[B(4)], r[B(4)] + 4 };
    const uint32_t second[] = { a12 + 4, r[A(10)], r[A(8)], r[B(8)], r[B(8)] + 4 };
    for (unsigned i = 0; i < 5; i++)
        if (same_word(first[i], b15) || same_word(second[i], b15) || same_word(second[i], b6)
            || same_word(second[i], a12))
            return 0;
    if (same_word(b15, b6) || same_word(b15, a12) || same_word(b15, a12 + 4) || same_word(b15, b10))
        return 0;

    uint32_t a7l = ld32(y0p);
    float a7 = u2f(a7l), a3 = a7 * u2f(ld32(ap));
    float a5 = u2f(ld32(xp)) - a3;
    uint32_t b9l = ld32(bp + 4);
    float b4 = u2f(ld32(bp)) * a5;
    float b7 = u2f(b9l) * a7;
    b4 = b7 + b4;
    if (a5 > 2.0f || a5 < -2.0f)
        return 0;
    uint32_t a9l = ld32(y0p + 4);
    float a9 = u2f(a9l);
    float m = a9 * u2f(ld32(a2p));
    float y = u2f(ld32(x2p)) - m;
    float coef0 = u2f(ld32(b2p));
    float b5 = coef0 * y;
    float b4b = coef0 * a9;
    b4b = b4b + b5;
    if (y < -2.0f || y > 2.0f)
        return 0;

    s->st[0].a = b15;
    s->st[0].v = a12;
    s->st[0].pc = s->at + 0x1C;
    s->st[1].a = b6;
    s->st[1].v = f2u(b4);
    s->st[1].pc = s->at + 0x60;
    s->st[2].a = a12;
    s->st[2].v = f2u(a5);
    s->st[2].pc = s->at + 0xD0;
    s->st[3].a = b10;
    s->st[3].v = f2u(b4b);
    s->st[3].pc = s->at + 0x114;
    s->st[4].a = a12 + 4;
    s->st[4].v = f2u(y);
    s->st[4].pc = s->at + 0x16C;
    s->nst = 5;
    r[A(0)] = 0;
    r[A(3)] = 0x40000000;
    r[A(4)] = 0xC0000000;
    r[A(5)] = 0;
    r[A(6)] = 0;
    r[A(7)] = f2u(y);
    r[A(9)] = a9l;
    r[B(4)] = f2u(b4b);
    r[B(5)] = f2u(b5);
    r[B(7)] = f2u(b7);
    r[B(8)] += 4;
    r[B(9)] = b9l;
    s->pc = r[B(3)];
    s->last_pc = s->at + 0x172;
    s->cycles = 88;
    s->packets = 49;
    s->insns = 52;
    return 1;
}

static const native_wild filter_step_wild[] = { };

/* ------------------------------------------------------------------------ */
/* ring copy, one 8-byte frame per pass (NXS2: 0x800093E0, loop at 0x80009430) */

/* The loop copies B1 frames from B4 to B5 while stepping the read position
 * through the descriptor ring (A4 + 40 A18; B7 the position in it, A7 the
 * descriptors left, *A19 the ring length). The second word of a frame is
 * copied at the top of a pass and the first word of the next frame in the
 * back-branch's delay slot. The pass covers the steps that stay inside a
 * descriptor; a wrap to the next one, or running out of descriptors, is left
 * to the interpreter, as is a frame stored over a word the pass reads. */

static int ring_copy_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;
    uint32_t b4 = r[B(4)], b5 = r[B(5)], b7 = r[B(7)] + 1, a18 = r[A(18)], a7 = r[A(7)], a19 = r[A(19)];
    uint32_t a4 = r[A(4)], b6 = r[B(6)];

    if ((int32_t)b7 >= 294)
        return 0;
    const uint8_t *src = ram_ptr(c, b4 + 4, 4), *dst = ram_ptr(c, b5 + 4, 4);
    if (!src || !dst)
        return 0;
    uint32_t w1 = ld32(src);
    if ((b7 | a18) == 0)
        b4 = b6;
    else
        b4 += 8;
    uint32_t desc = a4 + 40 * a18;
    const uint8_t *d = ram_ptr(c, desc + 28, 8), *len = ram_ptr(c, a19, 4);
    if (!d || !len || same_word(b5 + 4, desc + 28) || same_word(b5 + 4, desc + 32) || same_word(b5 + 4, a19))
        return 0;
    uint32_t a0 = (ld32(d + 4) == b7) & (ld32(d) == 0);
    uint32_t b9 = r[B(9)];
    if (a0) {
        a18 = (a18 + 1) & (ld32(len) - 1);
        int64_t off = (int64_t)(int16_t)2352 * (int32_t)a18;
        b9 = (uint32_t)((uint64_t)off >> 32);
        b4 = b6 + (uint32_t)off;
        b7 = 0;
        a7 -= 1;
        if (!a7)
            return 0;
    }
    desc = a4 + 40 * a18;
    d = ram_ptr(c, desc + 28, 4);
    if (!d || same_word(b5 + 4, desc + 28))
        return 0;
    uint32_t a8 = ld32(d) == 1, b8 = b7 == 0;
    if (b8 & a8)
        return 0;
    uint32_t b1 = r[B(1)] - 1;
    int64_t m40 = (int64_t)40 * (int32_t)r[A(18)];

    s->st[0].a = b5 + 4;
    s->st[0].v = w1;
    s->st[0].pc = s->at + 0x18;
    s->nst = 1;
    if (b1) {
        const uint8_t *next = ram_ptr(c, b4, 4);
        if (!next || same_word(b4, b5 + 4) || !ram_ptr(c, b5 + 8, 4))
            return 0;
        b8 = ld32(next);
        s->st[1].a = b5 + 8;
        s->st[1].v = b8;
        s->st[1].pc = s->at + 0x14C;
        s->nst = 2;
    }
    r[A(0)] = a0;
    r[A(1)] = a0 ? a7 : 1;
    r[A(3)] = desc;
    r[A(5)] = 294;
    r[A(7)] = a7;
    r[A(8)] = a8;
    r[A(9)] += 1;
    r[A(16)] = (uint32_t)m40;
    r[A(17)] = (uint32_t)((uint64_t)m40 >> 32);
    r[A(18)] = a18;
    r[B(0)] = 0;
    r[B(1)] = b1;
    r[B(4)] = b4;
    r[B(5)] = b5 + 8;
    r[B(7)] = b7;
    r[B(8)] = b8;
    r[B(9)] = b9;
    s->pc = s->at + (b1 ? 0x10 : 0x150);
    s->branch_block = 4;
    s->last_pc = s->at + 0x14C;
    s->cycles = 85;
    s->packets = 56;
    s->insns = 60;
    return 1;
}

static const native_wild ring_copy_wild[] = { };

/* ------------------------------------------------------------------------ */
/* MASTER TEMPO level envelope, one sample per pass (NXS2: 0x80045174)      */

/* Two twin loops (one per channel pair) of 650 iterations each, software
 * pipelined over two stages. Each pass forms the energy x of one sample pair
 * read from both ends of a 2048-frame stereo ring, ((a + b) / 2)^2 +
 * ((c - d) / 2)^2, seeds its reciprocal square root with 0x5F3759DF minus half
 * its bits (the bits go through the stack), and finishes the previous
 * sample's three Newton steps. That sample's scaled root replaces an output
 * word, and the difference to the word it replaces goes to a second array,
 * or a register's 0.0 when that array's old word d is negative and the
 * difference lies in [0, -2 d]. The loop runs under DINT; a pass is entered
 * at a packet with nothing in flight, so both stages' live values are plain
 * registers there. */

static inline void put_dp(uint32_t *r, unsigned lo, double d)
{
    uint64_t v;
    memcpy(&v, &d, 8);
    r[lo] = (uint32_t)v;
    r[lo + 1] = (uint32_t)(v >> 32);
}

static inline void put_st(native_state *s, uint32_t a, uint32_t v, uint32_t pc)
{
    s->st[s->nst].a = a;
    s->st[s->nst].v = v;
    s->st[s->nst].pc = pc;
    s->nst++;
}

/* One Newton step of 1/sqrt: y (1.5 - y (y h)) in the loop's own order. */
static inline float rsqrt_step(float y, float yyh, float three_halves)
{
    return y * (three_halves - yyh);
}

/* The first twin's loop head is the packet after its bdec target. */
static int mt_env_a_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg, head = s->at + 8;

    if (directed_rounding(s) || r[A(1)] || (int32_t)r[B(0)] <= 0)
        return 0;
    const uint8_t *rb = ram_ptr(c, r[B(9)], 4), *lb = ram_ptr(c, r[B(8)], 4);
    const uint8_t *front = ram_ptr(c, r[A(18)], 8), *outp = ram_ptr(c, r[A(22)], 4);
    const uint8_t *difp = ram_ptr(c, r[A(21)], 4);
    if (!rb || !lb || !front || !outp || !difp || !ram_ptr(c, r[B(15)] + 4, 8))
        return 0;
    float half = u2f(r[A(16)]), th = u2f(r[B(6)]), h = u2f(r[A(19)]);

    float y1 = rsqrt_step(u2f(r[B(16)]), u2f(r[B(4)]), th);
    float y2 = rsqrt_step(y1, y1 * (y1 * h), th);
    float y3 = rsqrt_step(y2, y2 * (y2 * h), th);

    float sa = half * (u2f(ld32(front)) + u2f(ld32(lb)));
    float sd = (u2f(ld32(front + 4)) - u2f(ld32(rb))) * half;
    float x = sa * sa + sd * sd;
    uint32_t y0 = r[B(7)] - (uint32_t)((int32_t)f2u(x) >> 1);
    float hn = half * x;

    float out = u2f(r[A(23)]) * (u2f(r[A(3)]) * y3);
    float old = u2f(ld32(outp)), dold = u2f(ld32(difp));
    float diff = out - old, floor2 = u2f(r[A(20)]) * dold;
    uint32_t sel = r[A(17)];
    if (diff < 0.0f || !((double)dold < 0.0) || diff > floor2)
        sel = f2u(diff);

    put_st(s, r[B(15)] + 8, f2u(y3), head + 0x7C);
    put_st(s, r[B(15)] + 8, f2u(x), head + 0x80);
    put_st(s, r[B(15)] + 4, y0, head + 0xA6);
    put_st(s, r[A(22)], f2u(out), head + 0xA6);
    put_st(s, r[A(21)], sel, head + 0x100);

    r[A(0)] = diff > floor2;
    r[A(3)] = f2u(x);
    put_dp(r, A(4), (double)dold);
    r[A(6)] = f2u(floor2);
    r[A(7)] = sel;
    put_dp(r, A(8), (double)diff);
    r[A(18)] += 8;
    r[A(19)] = f2u(hn);
    r[A(21)] += 4;
    r[A(22)] += 4;
    r[A(24)] = f2u(diff);
    r[B(0)] -= 1;
    r[B(4)] = f2u(u2f(y0) * (u2f(y0) * hn));
    r[B(5)] = 0;
    r[B(8)] -= 8;
    r[B(9)] -= 8;
    r[B(16)] = y0;
    s->cycles = 60;
    s->packets = 51;
    s->insns = 68;
    s->pc = head;
    s->last_pc = head - 4;
    s->branch_block = 0;
    return 1;
}

/* The second twin's loop head is its bdec target. */
static int mt_env_b_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg, head = s->at + 0xC;

    if (directed_rounding(s) || r[A(1)] || (int32_t)r[B(0)] <= 0)
        return 0;
    const uint8_t *lb = ram_ptr(c, r[B(18)], 4), *rb = ram_ptr(c, r[B(19)], 4);
    const uint8_t *front = ram_ptr(c, r[A(19)] + 8, 8), *outp = ram_ptr(c, r[A(17)], 4);
    const uint8_t *difp = ram_ptr(c, r[A(16)], 4);
    if (!rb || !lb || !front || !outp || !difp || !ram_ptr(c, r[B(15)] + 12, 8))
        return 0;
    float half = u2f(r[B(20)]), th = u2f(r[B(16)]), h = u2f(r[B(7)]);

    float y1 = rsqrt_step(u2f(r[B(8)]), u2f(r[B(4)]), th);
    float y2 = rsqrt_step(y1, y1 * (h * y1), th);
    float y3 = rsqrt_step(y2, y2 * (h * y2), th);

    float sd = half * (u2f(ld32(lb)) - u2f(ld32(front)));
    float sa = half * (u2f(ld32(rb)) + u2f(ld32(front + 4)));
    float x = sd * sd + sa * sa;
    uint32_t y0 = r[B(17)] - (uint32_t)((int32_t)f2u(x) >> 1);
    float hn = half * x;

    float out = u2f(r[A(18)]) * (y3 * u2f(r[B(6)]));
    float old = u2f(ld32(outp)), dold = u2f(ld32(difp));
    float diff = out - old, floor2 = u2f(r[A(3)]) * dold;
    uint32_t sel = r[A(20)];
    if (diff < 0.0f || !((double)dold < 0.0) || diff > floor2)
        sel = f2u(diff);

    put_st(s, r[B(15)] + 16, f2u(y3), head + 0x80);
    put_st(s, r[B(15)] + 16, f2u(x), head + 0x84);
    put_st(s, r[B(15)] + 12, y0, head + 0xA8);
    put_st(s, r[A(17)], f2u(out), head + 0xB4);
    put_st(s, r[A(16)], sel, head + 0x104);

    r[A(0)] = diff > floor2;
    put_dp(r, A(4), (double)dold);
    r[A(6)] = sel;
    r[A(7)] = f2u(floor2);
    put_dp(r, A(8), (double)diff);
    r[A(16)] += 4;
    r[A(17)] += 4;
    r[A(19)] += 8;
    r[A(21)] = f2u(diff);
    r[B(0)] -= 1;
    r[B(4)] = f2u(u2f(y0) * (hn * u2f(y0)));
    r[B(5)] = 0;
    r[B(6)] = f2u(x);
    r[B(7)] = f2u(hn);
    r[B(8)] = y0;
    r[B(9)] = f2u(hn * u2f(y0));
    r[B(18)] -= 8;
    r[B(19)] -= 8;
    s->cycles = 60;
    s->packets = 50;
    s->insns = 69;
    s->pc = head;
    s->last_pc = head + 0x104;
    s->branch_block = 0;
    return 1;
}

static const native_wild mt_env_wild[] = { };

/* ------------------------------------------------------------------------ */
/* MASTER TEMPO peak-neighbour marking, one index per pass (NXS2: 0x8004190C) */

/* For i = A3 below 650, two halfword arrays (h1 walked by *++B5, h2 = A10[i])
 * and one flag byte f = A16[i] decide whether i's neighbours get marked: when
 * 0 < h1 < 6, f == 1 and the float A8[i] > 0, or 0 < h2 < 6, f == 1 and the
 * float A9[i] > 0, the loop stores 1 to f[i - 1] and f[i + 1]. Playback never
 * takes those marking paths, so a pass declines at f == 1 and the interpreter
 * runs them; the two paths left (h2 out of range: 45 cycles; h2 in range,
 * f != 1: 52) store nothing. The last index is left to the interpreter too. */

static int mt_mark_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg, i = r[A(3)], head = s->at + 0x18;

    if (i + 1 >= 650)
        return 0;
    const uint8_t *h1p = ram_ptr(c, r[B(5)] + 2, 2), *h2p = ram_ptr(c, r[A(10)] + 2 * i, 2);
    const uint8_t *fp = ram_ptr(c, r[A(16)] + i, 1);
    if (!h1p || !h2p || !fp)
        return 0;
    int32_t h1 = (int16_t)(h1p[0] | h1p[1] << 8), h2 = (int16_t)(h2p[0] | h2p[1] << 8);
    int in1 = 0 < h1 && h1 < 6, in2 = 0 < h2 && h2 < 6;
    if ((in1 || in2) && (int8_t)fp[0] == 1)
        return 0;

    if (in1 || in2)
        r[A(4)] = i + r[A(16)];
    r[A(0)] = 1;
    r[A(3)] = i + 1;
    r[A(5)] = 650;
    r[A(6)] = (uint32_t)h2;
    r[B(0)] = in2;
    r[B(1)] = 0;
    r[B(4)] = 6 > h2;
    r[B(5)] += 2;
    r[B(31)] = 0;
    s->cycles = in2 ? 52 : 45;
    s->packets = in2 ? 29 : 26;
    s->insns = in2 ? 36 : 31;
    s->pc = head;
    s->last_pc = head + 0x94;
    return 1;
}

static const native_wild mt_mark_wild[] = { };

/* ------------------------------------------------------------------------ */
/* C6747 decks, cubic interpolator, one call per pass (XDJ-1000: 0xC000FC50) */

/* The same Lagrange cubic as the NXS2's, scheduled differently: interp(t A4,
 * x0 B4, x1 A6, x2 B6, x3 A8) returns in A4, evaluated as
 *   0.5 (x0 t^2 + (x1 (t^3 - t - 2t^2 + 2) - x2 (t^3 - t^2 - 2t)))
 *     + (x3 (t^3 - t) - x0 (t^3 + 2t)) / 6
 * in the firmware's operation order. Registers only: entered at the call,
 * left through B3, 50 cycles on every call. These decks run their float
 * units rounding toward zero, which the pass reproduces on the host. */

static int float_mode(const native_state *s)
{
    uint32_t f = s->cr[CR_FADCR], m = s->cr[CR_FMCR];
    unsigned rm = f >> 9 & 3;

    if ((f >> 25 & 3) != rm || (m >> 9 & 3) != rm || (m >> 25 & 3) != rm)
        return -1;
    return (int)rm;
}

static int xdj_interp_pass(c66x_core *c, native_state *s)
{
    uint32_t *r = s->reg;
    int rm = float_mode(s);

    if (rm < 0)
        return 0;
    if (rm)
        host_round(rm);
    float t = u2f(r[A(4)]), x0 = u2f(r[B(4)]), x1 = u2f(r[A(6)]), x2 = u2f(r[B(6)]), x3 = u2f(r[A(8)]);
    float t2 = t * t, t3 = t * t2;
    float tt2 = t2 + t2, x0t2 = x0 * t2, t3mt = t3 - t, tt = t + t, t3mt2 = t3 - t2;
    float a16 = t3mt - tt2, a5 = tt + t3, a18 = t3mt2 - tt;
    float a9 = 2.0f + a16;
    float a4 = x1 * a9, a16b = a18 * x2, a6 = x3 * t3mt, b6 = x0 * a5;
    a4 = a4 - a16b;
    float b4 = a6 - b6;
    b6 = x0t2 + a4;
    float b5 = 0.5f * b6;
    b4 = u2f(0x3E2AAAABu) * b4;
    b4 = b5 + b4;
    if (rm)
        host_round(0);
    r[A(3)] = f2u(t2);
    r[A(4)] = f2u(b4);
    r[A(5)] = f2u(a5);
    r[A(6)] = f2u(a6);
    r[A(7)] = f2u(t3mt);
    r[A(9)] = f2u(a9);
    r[A(16)] = f2u(a16b);
    r[A(17)] = 0x40000000;
    r[A(18)] = f2u(a18);
    r[B(4)] = f2u(b4);
    r[B(5)] = f2u(b5);
    r[B(6)] = f2u(b6);
    r[B(7)] = 0x3E2AAAAB;
    s->last_pc = s->at + 0xA0;
    s->pc = r[B(3)];
    s->cycles = 50;
    s->packets = 36;
    s->insns = 36;
    return 1;
}

static const native_wild xdj_interp_wild[] = { };

#define KERNEL(name, first, size, hash, entry, exit, wild, pass) \
    { name, first, size, hash, entry, exit, wild, sizeof wild / sizeof wild[0], pass }

static const native_kernel kernels[] = {
    KERNEL("fir", 0x0e802428, 0x2C0, 0x53818cd17afe5d79ull, 0x18, 0x2BC, fir_wild, fir_pass),
    KERNEL("ring_walk", 0x0380142a, 0xC0, 0xc62f9cdee2901fc9ull, 0x18, 0xC0, ring_walk_wild, ring_walk_pass),
    KERNEL("interp", 0x00006000, 0xA0, 0x131da3c257dffec2ull, 0x18, RETURNS, interp_wild, interp_pass),
    KERNEL("filter_step", 0x01d555a8, 0x180, 0xcaea3cdb3d032fdaull, 0x1C, RETURNS, filter_step_wild, filter_step_pass),
    KERNEL("ring_copy", 0x041002e6, 0x160, 0xfd497173d8a6ba9full, 0x10, 0x150, ring_copy_wild, ring_copy_pass),
    KERNEL("mt_env_a", 0x008000a8, 0x110, 0x6c7d92b20d46c2bdull, 0x8, 0x110, mt_env_wild, mt_env_a_pass),
    KERNEL("mt_env_b", 0x10004001, 0x120, 0xd6307a50e1686276ull, 0xC, 0x120, mt_env_wild, mt_env_b_pass),
    KERNEL("mt_mark", 0x01942234, 0xC0, 0x72626aaaf20a4d06ull, 0x18, 0xB4, mt_mark_wild, mt_mark_pass),
    KERNEL("xdj_interp", 0x02004b7e, 0xC0, 0x513ea38b2578b325ull, 0x10, RETURNS, xdj_interp_wild, xdj_interp_pass),
};
#define NKERNELS (sizeof kernels / sizeof kernels[0])

/* ------------------------------------------------------------------------ */
/* the driver                                                                */

typedef struct native_check {
    native_state s;
    uint64_t at, end_cycle, irqs;
    uint64_t packets, insns, stalls, sploops;
    unsigned wq_base;
    uint64_t checked, skipped, bad;
} native_check;

static uint64_t fnv(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++)
        h = (h ^ p[i]) * 1099511628211ull;
    return h;
}

typedef struct native_found {
    uint32_t at[NKERNELS];
    uint32_t addr[NKERNELS][2];
    unsigned matches[NKERNELS];     /* in the last search */
} native_found;

/* The bytes at p match kernel k: fill its addresses. */
static int native_match(const native_kernel *k, const uint8_t *p, uint32_t addr[2])
{
    uint8_t code[NATIVE_SIZE_MAX];
    if (k->size > sizeof code)
        return 0;
    memcpy(code, p, k->size);
    addr[0] = addr[1] = 0;
    for (unsigned i = 0; i < k->nwild; i++) {
        const native_wild *w = &k->wild[i];
        uint32_t v = ld32(code + w->off);
        if (w->addr >= 0) {
            uint32_t cst = (v & MVK_CST) >> 7;
            addr[w->addr] |= w->high ? cst << 16 : cst;
        }
        v &= ~w->mask;
        memcpy(code + w->off, &v, 4);
    }
    return fnv(code, k->size) == k->hash;
}

/* Search every fetch packet on a page that holds decoded code. A mapping that
 * shows the same bytes as another one already searched is skipped, so an
 * alias of the kernel is not a second match. */
static void native_search(c66x_core *c, native_found *f)
{
    memset(f->matches, 0, sizeof f->matches);
    for (unsigned ri = 0; ri < c->nram; ri++) {
        const ramreg *r = &c->ram[ri];
        int alias = 0;
        for (unsigned j = 0; j < ri; j++)
            alias |= c->ram[j].host == r->host;
        if (!r->fpp || alias)
            continue;
        for (uint32_t pg = 0; pg <= (r->size - 1) >> FP_PAGE_SHIFT; pg++) {
            if (!r->fpp[pg])
                continue;
            uint32_t end = (pg + 1) << FP_PAGE_SHIFT;
            for (uint32_t off = pg << FP_PAGE_SHIFT; off < end && off < r->size; off += 32) {
                uint32_t w = ld32(r->host + off);
                for (unsigned i = 0; i < NKERNELS; i++) {
                    const native_kernel *k = &kernels[i];
                    uint32_t addr[2];
                    if (w != k->first || k->size > r->size - off || !native_match(k, r->host + off, addr))
                        continue;
                    f->matches[i]++;
                    f->at[i] = r->base + off;
                    memcpy(f->addr[i], addr, sizeof addr);
                }
            }
        }
    }
}

/* Which kernels were found exactly once, searched again whenever decoded code
 * was dropped or reached a new page. The found code is decoded too, so a later
 * store into it drops decoded code and moves code_gen on. */
static uint32_t native_verified(c66x_core *c)
{
    if (c->native_gen == c->code_gen + 1 && c->native_pages == c->code_pages)
        return c->native_ok;
    native_found *f = c->native_found;
    native_search(c, f);
    uint32_t ok = 0;
    for (unsigned i = 0; i < NKERNELS; i++) {
        if (f->matches[i] != 1)
            continue;
        for (uint32_t a = f->at[i]; a < f->at[i] + kernels[i].size; a += 32)
            fetch_insn(c, a);
        ok |= 1u << i;
    }
    c->native_ok = ok;
    c->native_gen = c->code_gen + 1;
    c->native_pages = c->code_pages;
    return ok;
}

/* A compiled region rooted at the loop head wins: the module already runs the
 * kernel, and handing its packet to the general loop would only slow it. */
int native_entry(c66x_core *c, uint32_t pc)
{
    if (!c->native_mode)
        return 0;
    uint32_t ok = native_verified(c);
    const native_found *f = c->native_found;
    for (unsigned i = 0; i < NKERNELS; i++)
        if ((ok >> i & 1) && (f->at[i] + kernels[i].entry == pc
                              || (c->native_mode == 2 && kernels[i].exit != RETURNS
                                  && f->at[i] + kernels[i].exit == pc)))
            return !(jit_lookup(c, pc) || jit_lookup0(c, pc) || jit_lookupq(c, pc));
    const native_check *chk = c->native_chk;
    return chk && chk->end_cycle && pc == chk->s.pc;
}

int native_find(c66x_core *c, const char *name, uint32_t *at, uint32_t addr[2])
{
    uint32_t ok = native_verified(c);
    const native_found *f = c->native_found;
    for (unsigned i = 0; i < NKERNELS; i++)
        if (!strcmp(kernels[i].name, name) && (ok >> i & 1)) {
            *at = f->at[i];
            memcpy(addr, f->addr[i], sizeof f->addr[i]);
            return 1;
        }
    return 0;
}

static void check_arrival(c66x_core *c, native_check *k)
{
    if (c->st.interrupts != k->irqs) {
        k->skipped++;
        return;
    }
    const native_state *s = &k->s;
    char why[256] = "";
    if (c->cycle != k->end_cycle || c->pc != s->pc)
        snprintf(why, sizeof why, "cycle +%lld pc 0x%08x (predicted +%u 0x%08x)",
                 (long long)(c->cycle - k->at), c->pc, s->cycles, s->pc);
    for (unsigned i = 0; !*why && i < C66X_NREGS; i++)
        if (c->reg[i] != s->reg[i])
            snprintf(why, sizeof why, "reg %c%u 0x%08x (predicted 0x%08x)", i < 32 ? 'A' : 'B', i & 31,
                     c->reg[i], s->reg[i]);
    for (unsigned i = 0; !*why && i < 32; i++)
        if (c->cr[i] != s->cr[i])
            snprintf(why, sizeof why, "cr %u 0x%08x (predicted 0x%08x)", i, c->cr[i], s->cr[i]);
    if (!*why && (c->st.packets - k->packets != s->packets || c->st.insns - k->insns != s->insns
                  || c->st.sploops - k->sploops != s->sploops))
        snprintf(why, sizeof why, "packets %llu insns %llu sploops %llu (predicted %u %u %u)",
                 (unsigned long long)(c->st.packets - k->packets), (unsigned long long)(c->st.insns - k->insns),
                 (unsigned long long)(c->st.sploops - k->sploops), s->packets, s->insns, s->sploops);
    if (!*why && (c->st.stalls != k->stalls || c->wq_base != k->wq_base || c->branch_block != (int)s->branch_block
                  || c->nbr || c->mcnop || c->exec_pc != s->last_pc))
        snprintf(why, sizeof why,
                 "stalls %llu wq_base %d branch_block %d nbr %u mcnop %d exec 0x%08x (predicted %u, 0x%08x)",
                 (unsigned long long)(c->st.stalls - k->stalls), (int)(c->wq_base - k->wq_base),
                 c->branch_block, c->nbr, c->mcnop, c->exec_pc, s->branch_block, s->last_pc);
    if (!*why && s->pm_resume && c->pm_resume_at != k->at + s->pm_resume)
        snprintf(why, sizeof why, "pm_resume_at +%lld (predicted +%u)",
                 (long long)(c->pm_resume_at - k->at), s->pm_resume);
    for (unsigned i = 0; !*why && i < s->nst; i++) {
        unsigned later = i + 1;
        while (later < s->nst && s->st[later].a != s->st[i].a)
            later++;
        if (later < s->nst)
            continue;           /* overwritten within the pass */
        const uint8_t *p = ram_ptr(c, s->st[i].a, 4);
        if (!p || ld32(p) != s->st[i].v)
            snprintf(why, sizeof why, "store 0x%08x 0x%08x (predicted 0x%08x)", s->st[i].a,
                     p ? ld32(p) : 0, s->st[i].v);
    }
    k->checked++;
    if (*why && k->bad++ < 20)
        fprintf(stderr, "c66x native check: pass at cycle %llu: %s\n", (unsigned long long)k->at, why);
}

int native_run(c66x_core *c, uint64_t end)
{
    const native_kernel *k = NULL;
    const native_found *f = c->native_found;
    uint32_t ok = native_verified(c);
    unsigned ki = 0;
    for (; ki < NKERNELS; ki++)
        if ((ok >> ki & 1) && f->at[ki] + kernels[ki].entry == c->pc) {
            k = &kernels[ki];
            break;
        }
    native_check *chk = c->native_chk;
    if (chk && chk->end_cycle && (k || c->pc == chk->s.pc || native_entry(c, c->pc))) {
        check_arrival(c, chk);
        chk->end_cycle = 0;
    }
    if (!k)
        return 0;
    if (c->nbr || c->spl.active || (c->cr[CR_TSR] & TSR_SPLX) || c->idle_ret_pending || c->imm_n
        || !jit_wq_empty(c) || c->npst || c->trace || (c->idle_armed && !c->idle_fx)
        || (c->ifr && pending_interrupt(c)))
        return 0;

    native_state s, t;
    memcpy(s.reg, c->reg, sizeof s.reg);
    memcpy(s.cr, c->cr, sizeof s.cr);
    s.at = f->at[ki];
    memcpy(s.addr, f->addr[ki], sizeof s.addr);
    if (chk) {
        t = s;
        t.cycles = t.packets = t.insns = t.sploops = t.pm_resume = t.nst = 0;
        t.branch_block = 5;
        if (k->pass(c, &t)) {
            chk->s = t;
            chk->at = c->cycle;
            chk->end_cycle = c->cycle + t.cycles;
            chk->irqs = c->st.interrupts;
            chk->packets = c->st.packets;
            chk->insns = c->st.insns;
            chk->stalls = c->st.stalls;
            chk->sploops = c->st.sploops;
            chk->wq_base = c->wq_base;
            /* A function returns to a packet that may already be cached as
             * an ordinary one: hand it to the general loop for the compare. */
            pkc_ent *e = &c->pkc[PKC_SLOT(t.pc)];
            if (k->exit == RETURNS && e->pc == t.pc)
                e->special = 1;
        }
        return 0;
    }

    uint64_t at = c->cycle, gen = c->code_gen;
    int ran = 0;
    for (;;) {
        t = s;
        t.cycles = t.packets = t.insns = t.sploops = t.pm_resume = t.nst = 0;
        t.branch_block = 5;
        if (!k->pass(c, &t) || c->cycle + t.cycles > end)
            break;
        for (unsigned i = 0; i < t.nst; i++)
            mem_write(c, t.st[i].a, t.st[i].v, 4, c->isr_depth != 0, t.st[i].pc);
        if (t.pm_resume)
            c->pm_resume_at = c->cycle + t.pm_resume;
        c->cycle += t.cycles;
        c->st.packets += t.packets;
        c->st.insns += t.insns;
        c->st.sploops += t.sploops;
        s = t;
        ran = 1;
        if (t.pc != s.at + k->entry || c->code_gen != gen)
            break;
    }
    if (!ran)
        return 0;
    memcpy(c->reg, s.reg, sizeof c->reg);
    memcpy(c->cr, s.cr, sizeof c->cr);
    c->pc = s.pc;
    c->exec_pc = s.last_pc;
    c->branch_block = s.branch_block;
    c->wmask = 0;
    c->native_entries++;
    c->native_cycles += c->cycle - at;
    return 1;
}

/* C66X_NATIVE=0 runs every kernel on the interpreter; =check runs them there
 * too, and compares each pass with what its native form predicted. */
void native_init(c66x_core *c)
{
    const char *e = getenv("C66X_NATIVE");
    c->native_mode = !e ? 1 : !strcmp(e, "0") ? 0 : !strcmp(e, "check") ? 2 : 1;
    c->native_found = calloc(1, sizeof(native_found));
    if (c->native_mode == 2)
        c->native_chk = calloc(1, sizeof(native_check));
}

void native_free(c66x_core *c)
{
    native_check *k = c->native_chk;
    native_found *f = c->native_found;
    if (c->native_mode && c->native_gen) {
        fprintf(stderr, "c66x native: kernels");
        for (unsigned i = 0; i < NKERNELS; i++)
            if (f->matches[i] == 1)
                fprintf(stderr, " %s 0x%08x", kernels[i].name, f->at[i]);
            else
                fprintf(stderr, " %s (%u matches)", kernels[i].name, f->matches[i]);
        fputc('\n', stderr);
    }
    if (k)
        fprintf(stderr, "c66x native check: %llu passes checked, %llu differ, %llu interrupted\n",
                (unsigned long long)k->checked, (unsigned long long)k->bad, (unsigned long long)k->skipped);
    else if (c->native_entries)
        fprintf(stderr, "c66x native: %llu entries, %llu cycles\n",
                (unsigned long long)c->native_entries, (unsigned long long)c->native_cycles);
    free(k);
    free(f);
}
