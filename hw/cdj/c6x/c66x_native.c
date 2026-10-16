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
    unsigned nst;
    struct { uint32_t a, v, pc; } st[1];
} native_state;

typedef struct native_kernel {
    uint32_t entry;                 /* the loop head */
    uint32_t exit;                  /* where the last pass ends */
    uint32_t lo, hi;                /* the fetch packets the native form stands for */
    uint64_t hash;                  /* FNV-1a of those bytes in the image it was written for */
    int (*pass)(c66x_core *c, native_state *s);   /* 0: not natively (the code runs) */
} native_kernel;

static inline float u2f(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }
static inline uint32_t f2u(float f) { uint32_t v; memcpy(&v, &f, 4); return v; }

static inline uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* ------------------------------------------------------------------------ */
/* NXS2 0x800169AC: polyphase FIR, one output per pass                       */

/* fir(in A4, out B4, count A6, channel B6). Per output: phase p = *++B16,
 * input offset k = *++A18 and h = the halfword at A19 + 4. While p <= h >> 1
 * the output is a 29-tap dot product of in[k..k+28] with the coefficient row
 * B9 + 116 p, summed in one serial faddsp chain starting from A20. Otherwise
 * a SPLOOP (14 iterations from ILC 12) sums in[k..k+27] against the row
 * R = B9 + 116 (h - p) read backwards, in two interleaved partial sums, and
 * the centre tap in[k+28] takes its coefficient from the channel's table at
 * *(0x0088B2E0 + 4 ch). The pass costs and counters below were measured on
 * the interpreter and hold for every pass of both paths. */

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
        const uint8_t *tp = ram_ptr(c, 0x0088B2E0 + r[B(17)], 4);
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
    s->st[0].pc = 0x80016CB0;
    s->nst = 1;
    r[A(17)] += 4;
    r[B(0)] -= 1;
    s->pc = r[B(0)] ? 0x80016A18 : 0x80016CBC;
    s->last_pc = 0x80016CB8;
    return 1;
}

static const native_kernel kernels[] = {
    { 0x80016A18, 0x80016CBC, 0x80016A00, 0x80016CC0, 0x439a1eb2f301903cull, fir_pass },
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

/* Which kernels' code is in RAM as written for, once per code generation. The
 * fetch packets are decoded too, so a later store into them drops decoded code
 * and moves code_gen on. */
static uint32_t native_verified(c66x_core *c)
{
    if (c->native_gen == c->code_gen + 1)
        return c->native_ok;
    uint32_t ok = 0;
    for (unsigned i = 0; i < NKERNELS; i++) {
        const native_kernel *k = &kernels[i];
        const uint8_t *p = ram_ptr(c, k->lo, k->hi - k->lo);
        if (!p || fnv(p, k->hi - k->lo) != k->hash)
            continue;
        for (uint32_t a = k->lo; a < k->hi; a += 32)
            fetch_insn(c, a);
        ok |= 1u << i;
    }
    c->native_ok = ok;
    c->native_gen = c->code_gen + 1;
    return ok;
}

/* A compiled region rooted at the loop head wins: the module already runs the
 * kernel, and handing its packet to the general loop would only slow it. */
int native_entry(c66x_core *c, uint32_t pc)
{
    if (!c->native_mode)
        return 0;
    for (unsigned i = 0; i < NKERNELS; i++)
        if (kernels[i].entry == pc || (c->native_mode == 2 && kernels[i].exit == pc))
            return !(jit_lookup(c, pc) || jit_lookup0(c, pc) || jit_lookupq(c, pc));
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
    if (!*why && (c->st.stalls != k->stalls || c->wq_base != k->wq_base || c->branch_block != 5
                  || c->nbr || c->mcnop || c->exec_pc != s->last_pc))
        snprintf(why, sizeof why, "stalls %llu wq_base %d branch_block %d nbr %u mcnop %d exec 0x%08x",
                 (unsigned long long)(c->st.stalls - k->stalls), (int)(c->wq_base - k->wq_base),
                 c->branch_block, c->nbr, c->mcnop, c->exec_pc);
    if (!*why && s->pm_resume && c->pm_resume_at != k->at + s->pm_resume)
        snprintf(why, sizeof why, "pm_resume_at +%lld (predicted +%u)",
                 (long long)(c->pm_resume_at - k->at), s->pm_resume);
    for (unsigned i = 0; !*why && i < s->nst; i++) {
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
    unsigned ki = 0;
    for (; ki < NKERNELS; ki++)
        if (kernels[ki].entry == c->pc) {
            k = &kernels[ki];
            break;
        }
    native_check *chk = c->native_chk;
    if (chk && chk->end_cycle && (k || c->pc == chk->s.pc || native_entry(c, c->pc))) {
        check_arrival(c, chk);
        chk->end_cycle = 0;
    }
    if (!k || !(native_verified(c) >> ki & 1))
        return 0;
    if (c->nbr || c->spl.active || (c->cr[CR_TSR] & TSR_SPLX) || c->idle_ret_pending || c->imm_n
        || !jit_wq_empty(c) || c->npst || c->trace || (c->idle_armed && !c->idle_fx)
        || (c->ifr && pending_interrupt(c)))
        return 0;

    native_state s, t;
    memcpy(s.reg, c->reg, sizeof s.reg);
    memcpy(s.cr, c->cr, sizeof s.cr);
    if (chk) {
        t = s;
        t.cycles = t.packets = t.insns = t.sploops = t.pm_resume = t.nst = 0;
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
        }
        return 0;
    }

    uint64_t at = c->cycle, gen = c->code_gen;
    int ran = 0;
    for (;;) {
        t = s;
        t.cycles = t.packets = t.insns = t.sploops = t.pm_resume = t.nst = 0;
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
        if (t.pc != k->entry || c->code_gen != gen)
            break;
    }
    if (!ran)
        return 0;
    memcpy(c->reg, s.reg, sizeof c->reg);
    memcpy(c->cr, s.cr, sizeof c->cr);
    c->pc = s.pc;
    c->exec_pc = s.last_pc;
    c->branch_block = 5;
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
    if (c->native_mode == 2)
        c->native_chk = calloc(1, sizeof(native_check));
}

void native_free(c66x_core *c)
{
    native_check *k = c->native_chk;
    if (k)
        fprintf(stderr, "c66x native check: %llu passes checked, %llu differ, %llu interrupted\n",
                (unsigned long long)k->checked, (unsigned long long)k->bad, (unsigned long long)k->skipped);
    else if (c->native_entries)
        fprintf(stderr, "c66x native: %llu entries, %llu cycles\n",
                (unsigned long long)c->native_entries, (unsigned long long)c->native_cycles);
    free(k);
}
