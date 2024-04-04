/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#ifndef __GICV3_H__
#define __GICV3_H__

#include <arch/gic.h>

/*----------- GIC ITS -----------*/

// Define only to GICv3
// Verify the alignement and the offsets

#define GIC_MAX_TTD               8     //max translation table descriptors


struct gits_hw {
    /*ITS_CTRL_base frame*/
    uint32_t CTLR;
    uint32_t IIDR;
    uint64_t TYPER;
    uint8_t pad0[0x80 - 0x10];
    uint64_t CBASER;
    uint64_t CWRITER;
    uint64_t CREADR;
    uint8_t pad1[0x100 - 0x98];
    uint64_t BASER[GIC_MAX_TTD];
    uint8_t pad2[0xFFD0 - 0x140];   
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];

    /*translation_base frame - ITS_base + 0x10000*/
    uint8_t transl_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad3[0x40 - 0x0];
    uint32_t TRANSLATER;
    uint8_t pad4[0x10000 - 0x44];
} __attribute__((__packed__, aligned(0x10000)));    //64KB-aligned?

extern volatile struct gits_hw* gits;

static inline uint64_t gich_read_lr(size_t i)
{
    if (i >= NUM_LRS) {
        ERROR("gic: trying to read inexistent list register");
    }

    switch (i) {
        case 0:
            return sysreg_ich_lr0_el2_read();
        case 1:
            return sysreg_ich_lr1_el2_read();
        case 2:
            return sysreg_ich_lr2_el2_read();
        case 3:
            return sysreg_ich_lr3_el2_read();
        case 4:
            return sysreg_ich_lr4_el2_read();
        case 5:
            return sysreg_ich_lr5_el2_read();
        case 6:
            return sysreg_ich_lr6_el2_read();
        case 7:
            return sysreg_ich_lr7_el2_read();
        case 8:
            return sysreg_ich_lr8_el2_read();
        case 9:
            return sysreg_ich_lr9_el2_read();
        case 10:
            return sysreg_ich_lr10_el2_read();
        case 11:
            return sysreg_ich_lr11_el2_read();
        case 12:
            return sysreg_ich_lr12_el2_read();
        case 13:
            return sysreg_ich_lr13_el2_read();
        case 14:
            return sysreg_ich_lr14_el2_read();
        case 15:
            return sysreg_ich_lr15_el2_read();
        default:
            return 0;
    }
}

static inline void gich_write_lr(size_t i, uint64_t val)
{
    if (i >= NUM_LRS) {
        ERROR("gic: trying to write inexistent list register");
    }

    switch (i) {
        case 0:
            sysreg_ich_lr0_el2_write(val);
            break;
        case 1:
            sysreg_ich_lr1_el2_write(val);
            break;
        case 2:
            sysreg_ich_lr2_el2_write(val);
            break;
        case 3:
            sysreg_ich_lr3_el2_write(val);
            break;
        case 4:
            sysreg_ich_lr4_el2_write(val);
            break;
        case 5:
            sysreg_ich_lr5_el2_write(val);
            break;
        case 6:
            sysreg_ich_lr6_el2_write(val);
            break;
        case 7:
            sysreg_ich_lr7_el2_write(val);
            break;
        case 8:
            sysreg_ich_lr8_el2_write(val);
            break;
        case 9:
            sysreg_ich_lr9_el2_write(val);
            break;
        case 10:
            sysreg_ich_lr10_el2_write(val);
            break;
        case 11:
            sysreg_ich_lr11_el2_write(val);
            break;
        case 12:
            sysreg_ich_lr12_el2_write(val);
            break;
        case 13:
            sysreg_ich_lr13_el2_write(val);
            break;
        case 14:
            sysreg_ich_lr14_el2_write(val);
            break;
        case 15:
            sysreg_ich_lr15_el2_write(val);
            break;
    }
}

static inline uint32_t gich_get_hcr()
{
    return sysreg_ich_hcr_el2_read();
}

static inline void gich_set_hcr(uint32_t hcr)
{
    sysreg_ich_hcr_el2_write(hcr);
}

static inline uint32_t gich_get_misr()
{
    return sysreg_ich_misr_el2_read();
}

static inline uint64_t gich_get_eisr()
{
    return sysreg_ich_eisr_el2_read();
}

static inline uint64_t gich_get_elrsr()
{
    return sysreg_ich_elrsr_el2_read();
}

static inline uint32_t gicc_iar()
{
    return sysreg_icc_iar1_el1_read();
}

static inline void gicc_eoir(uint32_t eoir)
{
    sysreg_icc_eoir1_el1_write(eoir);
}

static inline void gicc_dir(uint32_t dir)
{
    sysreg_icc_dir_el1_write(dir);
}

inline void gits_map_mmio();

#endif /* __GICV3_H__ */
