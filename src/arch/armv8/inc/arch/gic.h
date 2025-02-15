/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#ifndef __GIC_H__
#define __GIC_H__

#include <bao.h>
#include <emul.h>
#include <bitmap.h>
#include <spinlock.h>
#include <arch/sysregs.h>

#define GICV2                     (2)
#define GICV3                     (3)
#define GICV4                     (4)

#define GIC_FIRST_SPECIAL_INTID   (1020)
#define GIC_MAX_INTERUPTS         1024
#define GIC_MAX_VALID_INTERRUPTS  (GIC_FIRST_SPECIAL_INTID)
#define GIC_MAX_SGIS              16
#define GIC_MAX_PPIS              16
#define GIC_N_LPIS                1024
#define GIC_FIRST_LPIS            8192
#define GIC_MAX_LPIS              (GIC_FIRST_LPIS + GIC_N_LPIS)
#define GIC_CPU_PRIV              (GIC_MAX_SGIS + GIC_MAX_PPIS)
#define GIC_MAX_SPIS              (GIC_MAX_INTERUPTS - GIC_CPU_PRIV)
#define GIC_PRIO_BITS             8
#define GIC_TARGET_BITS           8
#define GIC_MAX_TARGETS           GIC_TARGET_BITS
#define GIC_CONFIG_BITS           2
#define GIC_SEC_BITS              2
#define GIC_SGI_BITS              8
#define GICD_IROUTER_INV          (~MPIDR_AFF_MSK)
#define GIC_LOWEST_PRIO           (0xff)

#define GIC_INT_REG(NINT)         (NINT / (sizeof(uint32_t) * 8))
#define GIC_INT_MASK(NINT)        (1U << NINT % (sizeof(uint32_t) * 8))
#define GIC_NUM_INT_REGS(NINT)    GIC_INT_REG(NINT)
#define GIC_NUM_PRIVINT_REGS      (GIC_CPU_PRIV / (sizeof(uint32_t) * 8))

#define GIC_PRIO_REG(NINT)        ((NINT * GIC_PRIO_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_PRIO_REGS(NINT)   GIC_PRIO_REG(NINT)
#define GIC_PRIO_OFF(NINT)        (NINT * GIC_PRIO_BITS) % (sizeof(uint32_t) * 8)

#define GIC_TARGET_REG(NINT)      ((NINT * GIC_TARGET_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_TARGET_REGS(NINT) GIC_TARGET_REG(NINT)
#define GIC_TARGET_OFF(NINT)      (NINT * GIC_TARGET_BITS) % (sizeof(uint32_t) * 8)

#define GIC_CONFIG_REG(NINT)      ((NINT * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_CONFIG_REGS(NINT) GIC_CONFIG_REG(NINT)
#define GIC_CONFIG_OFF(NINT)      (NINT * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8)

#define GIC_NUM_SEC_REGS(NINT)    ((NINT * GIC_SEC_BITS) / (sizeof(uint32_t) * 8))

#define GIC_NUM_SGI_REGS          ((GIC_MAX_SGIS * GIC_SGI_BITS) / (sizeof(uint32_t) * 8))
#define GICD_SGI_REG(NINT)        (NINT / 4)
#define GICD_SGI_OFF(NINT)        ((NINT % 4) * 8)

#define GIC_NUM_APR_REGS          ((1UL << (GIC_PRIO_BITS - 1)) / (sizeof(uint32_t) * 8))
#define GIC_NUM_LIST_REGS         (64)

/* Distributor Control Register, GICD_CTLR */

#define GICD_CTLR_EN_BIT          (0x1)
#define GICD_CTLR_ENA_BIT         (0x2)
#define GICD_CTLR_ARE_NS_BIT      (0x10)

/*  Interrupt Controller Type Register, GICD_TYPER */

#define GICD_TYPER_ITLINENUM_OFF  (0)
#define GICD_TYPER_ITLINENUM_LEN  (5)
#define GICD_TYPER_CPUNUM_OFF     (5)
#define GICD_TYPER_CPUNUM_LEN     (3)
#define GICD_TYPER_CPUNUM_MSK     BIT32_MASK(GICD_TYPER_CPUNUM_OFF, GICD_TYPER_CPUNUM_LEN)
#define GICD_TYPER_SECUREXT_BIT   (1UL << 10)
#define GICD_TYPER_LSPI_OFF       (11)
#define GICD_TYPER_LSPI_LEN       (6)
#define GICD_TYPER_ITLN_OFF       0
#define GICD_TYPER_ITLN_LEN       5
#define GICD_TYPER_ITLN_MSK       BIT32_MASK(GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN)
#define GICD_TYPER_IDBITS_OFF     (19)
#define GICD_TYPER_IDBITS_LEN     (5)
#define GICD_TYPER_IDBITS_MSK     BIT32_MASK(GICD_TYPER_IDBITS_OFF, GICD_TYPER_IDBITS_LEN)
#define GICD_TYPER_LPIS_BIT       (1UL << 17)

/* Software Generated Interrupt Register, GICD_SGIR */

#define GICD_SGIR_SGIINTID_OFF    0
#define GICD_SGIR_SGIINTID_LEN    4
#define GICD_SGIR_SGIINTID_MSK    (BIT32_MASK(GICD_SGIR_SGIINTID_OFF, GICD_SGIR_SGIINTID_LEN))
#define GICD_SGIR_SGIINTID(sgir)  bit32_extract(sgir, GICD_SGIR_SGIINTID_OFF, GICD_SGIR_SGIINTID_LEN)
#define GICD_SGIR_CPUTRGLST_OFF   16
#define GICD_SGIR_CPUTRGLST_LEN   8
#define GICD_SGIR_CPUTRGLST(sgir) \
    bit32_extract(sgir, GICD_SGIR_CPUTRGLST_OFF, GICD_SGIR_CPUTRGLST_LEN)
#define GICD_SGIR_TRGLSTFLT_OFF 24
#define GICD_SGIR_TRGLSTFLT_LEN 2
#define GICD_SGIR_TRGLSTFLT(sgir) \
    bit32_extract(sgir, GICD_SGIR_TRGLSTFLT_OFF, GICD_SGIR_TRGLSTFLT_LEN)

/*  Interrupt Routing Registers, GICD_IROUTER */

#define GICD_IROUTER_RES0_MSK ((1ULL << 40) - 1)
#define GICD_IROUTER_IRM_BIT  (1ULL << 31)
#define GICD_IROUTER_AFF_MSK  (GICD_IROUTER_RES0_MSK & ~GICD_IROUTER_IRM_BIT)

struct gicd_hw {
    uint32_t CTLR;
    uint32_t TYPER;
    uint32_t IIDR;
    uint8_t pad0[0x0010 - 0x000C];
    uint32_t STATUSR;
    uint8_t pad1[0x0040 - 0x0014];
    uint32_t SETSPI_NSR;
    uint8_t pad2[0x0048 - 0x0044];
    uint32_t CLRSPI_NSR;
    uint8_t pad3[0x0050 - 0x004C];
    uint32_t SETSPI_SR;
    uint8_t pad4[0x0058 - 0x0054];
    uint32_t CLRSPI_SR;
    uint8_t pad9[0x0080 - 0x005C];
    uint32_t IGROUPR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)]; // banked CPU
    uint32_t ISENABLER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICENABLER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ISPENDR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICPENDR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ISACTIVER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICACTIVER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t IPRIORITYR[GIC_NUM_PRIO_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ITARGETSR[GIC_NUM_TARGET_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICFGR[GIC_NUM_CONFIG_REGS(GIC_MAX_INTERUPTS)];
    uint32_t IGPRMODR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint8_t pad5[0x0E00 - 0x0D80];
    uint32_t NSACR[GIC_NUM_SEC_REGS(GIC_MAX_INTERUPTS)];
    uint32_t SGIR;
    uint8_t pad6[0x0F10 - 0x0F04];
    uint32_t CPENDSGIR[GIC_NUM_SGI_REGS];
    uint32_t SPENDSGIR[GIC_NUM_SGI_REGS];
    uint8_t pad7[0x6000 - 0x0F30];
    uint64_t IROUTER[GIC_MAX_INTERUPTS];
    uint8_t pad8[0xFFD0 - 0x8000];
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];
} __attribute__((__packed__, aligned(0x10000)));

/* Redistributor Wake Register, GICD_WAKER */

#define GICR_CTRL_DS_BIT              (1 << 6)
#define GICR_CTRL_DS_DPG1NS           (1 << 25)
#define GICR_CTLR_EN_LPIS_OFF         (0)
#define GICR_CTLR_EN_LPIS_MSK         (BIT32_MASK(GICR_CTLR_EN_LPIS_OFF, 1))
#define GICR_TYPER_LAST_OFF           (4)
#define GICR_TYPER_PRCNUM_OFF         (8)
#define GICR_TYPER_AFFVAL_OFF         (32)
#define GICR_WAKER_ProcessorSleep_BIT (0x2)
#define GICR_WAKER_ChildrenASleep_BIT (0x4)

#define GICR_PROPBASER_PHY_OFF                  (12)
#define GICR_PROPBASER_PHY_LEN                  (40)
#define GICR_PROPBASER_SHAREABILITY_OFF         (10)
#define GICR_PROPBASER_INNERCACHE_OFF           (7)
#define GICR_PROPBASER_InnerShareable           (1ULL << GICR_PROPBASER_SHAREABILITY_OFF)
#define GICR_PROPBASER_RaWaWb                   (7ULL << GICR_PROPBASER_INNERCACHE_OFF)
#define GICR_PROPBASER_PHY_ADDR_MSK        (BIT64_MASK(GICR_PROPBASER_PHY_OFF,GICR_PROPBASER_PHY_LEN))
#define GICR_PROPBASER_ID_BITS_LEN              (5)
#define GICR_PROPBASER_ID_BITS_MSK         (BIT64_MASK(0,GICR_PROPBASER_ID_BITS_LEN))

#define GICR_PENDBASER_PHY_OFF                  (16)
#define GICR_PENDBASER_PHY_LEN                  (36)
#define GICR_PENDBASER_PHY_ADDR_MSK        (BIT64_MASK(GICR_PENDBASER_PHY_OFF,GICR_PENDBASER_PHY_LEN))


#define GICR_PROPTABLE_SZ(IDbits)               ((1<<(IDbits+1)) - 8192) //maybe not here

#define GICR_VPENDBASER_IDAI_BIT                (1ULL << 62)
#define GICR_VPENDBASER_VAL_BIT                 (1ULL << 63)

#define LPI_CONFIG_PRIO_OFF                     (2)
#define LPI_CONFIG_PRIO_LEN                     (6)
#define LPI_CONFIG_PRIO_MSK                     (BIT64_MASK(LPI_CONFIG_PRIO_OFF,LPI_CONFIG_PRIO_LEN))
#define LPI_CONFIG_EN_MSK                       (1)

#if (GIC_VERSION == GICV3)
    #define GICR_VFRAME_SIZE 0x0
#elif (GIC_VERSION == GICV4)
    #define GICR_VFRAME_SIZE 0x20000
#else
    #error "unknown GIV version " GIC_VERSION
#endif


struct gicr_hw {
    /* RD_base frame */
    uint32_t CTLR;
    uint32_t IIDR;
    uint64_t TYPER;
    uint32_t STATUSR;
    uint32_t WAKER;
    uint8_t pad0[0x0040 - 0x0018];
    uint64_t SETLPIR;
    uint64_t CLRLPIR;
    uint8_t pad1[0x0070 - 0x0050];
    uint64_t PROPBASER;
    uint64_t PENDBASER;
    uint8_t pad2[0x00A0 - 0x0080];
    uint64_t INVLPIR;
    uint8_t pad3[0x00B0 - 0x00A8];
    uint64_t INVALLR;
    uint8_t pad4[0x00c0 - 0x00b8];
    uint64_t SYNCR;
    uint8_t pad5[0xFFD0 - 0x00c8];
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];

    /* SGI_base frame */
    uint8_t sgi_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad6[0x0080 - 0x000];
    uint32_t IGROUPR0;
    uint8_t pad7[0x0100 - 0x084];
    uint32_t ISENABLER0;
    uint8_t pad8[0x0180 - 0x104];
    uint32_t ICENABLER0;
    uint8_t pad9[0x0200 - 0x184];
    uint32_t ISPENDR0;
    uint8_t pad10[0x0280 - 0x204];
    uint32_t ICPENDR0;
    uint8_t pad11[0x0300 - 0x284];
    uint32_t ISACTIVER0;
    uint8_t pad12[0x0380 - 0x304];
    uint32_t ICACTIVER0;
    uint8_t pad13[0x0400 - 0x384];
    uint32_t IPRIORITYR[GIC_NUM_PRIO_REGS(GIC_CPU_PRIV)];
    uint8_t pad14[0x0c00 - 0x420];
    uint32_t ICFGR0;
    uint32_t ICFGR1;
    uint8_t pad15[0x0D00 - 0xc08];
    uint32_t IGRPMODR0;
    uint8_t pad16[0x0e00 - 0xd04];
    uint32_t NSACR;

    #if (GIC_VERSION == GICV4)
    /* VLPI_base frame - only if gicv4 available*/
    uint8_t vlpi_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad17[0x70 - 0x00];
    uint64_t VPROPBASER;
    uint64_t VPENDBASER;
    uint8_t pad18[0x10000 - 0x80];

    /* Reserved_base frame - only if gicv4 available*/
    uint8_t reserved_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad19[0x10000];
    #endif
} __attribute__((__packed__, aligned(0x10000)));

/* CPU Interface Control Register, GICC_CTLR */

#define GICC_CTLR_EN_BIT        (0x1)
#define GICC_CTLR_EOImodeNS_BIT (1UL << 9)
#define GICC_CTLR_WR_MSK        (0x1)
#define GICC_IAR_ID_OFF         (0)
#if (GIC_VERSION == GICV2)
#define GICC_IAR_ID_LEN  (10)
#define GICC_IAR_CPU_OFF (10)
#define GICC_IAR_CPU_LEN (3)
#define GICC_IAR_CPU_MSK (BIT32_MASK(GICC_IAR_CPU_OFF, GICC_IAR_CPU_LEN))
#else
#define GICC_IAR_ID_LEN (24)
#endif
#define GICC_IAR_ID_MSK          (BIT32_MASK(GICC_IAR_ID_OFF, GICC_IAR_ID_LEN))

#define ICC_CTLR_EOIMode_BIT     (0x1ULL << 1)
#define ICC_SGIR_SGIINTID_OFF    24
#define ICC_SGIR_SGIINTID_LEN    4
#define ICC_SGIR_SGIINTID(sgir)  bit64_extract(sgir, ICC_SGIR_SGIINTID_OFF, ICC_SGIR_SGIINTID_LEN)
#define ICC_SGIR_IRM_BIT         (1ull << 40)
#define ICC_SGIR_TRGLSTFLT_OFF   0
#define ICC_SGIR_TRGLSTFLT_LEN   16
#define ICC_SGIR_TRGLSTFLT_MSK   BIT64_MASK(ICC_SGIR_TRGLSTFLT_OFF, ICC_SGIR_TRGLSTFLT_LEN)
#define ICC_SGIR_TRGLSTFLT(sgir) bit64_extract(sgir, ICC_SGIR_TRGLSTFLT_OFF, ICC_SGIR_TRGLSTFLT_LEN)
#define ICC_SGIR_AFF1_OFFSET     (16)

#define ICC_SRE_ENB_BIT          (0x8)
#define ICC_SRE_DIB_BIT          (0x4)
#define ICC_SRE_DFB_BIT          (0x2)
#define ICC_SRE_SRE_BIT          (0x1)
#define ICC_IGRPEN_EL1_ENB_BIT   (0x1)

struct gicc_hw {
    uint32_t CTLR;
    uint32_t PMR;
    uint32_t BPR;
    uint32_t IAR;
    uint32_t EOIR;
    uint32_t RPR;
    uint32_t HPPIR;
    uint32_t ABPR;
    uint32_t AIAR;
    uint32_t AEOIR;
    uint32_t AHPPIR;
    uint8_t pad0[0x00D0 - 0x002C];
    uint32_t APR[GIC_NUM_APR_REGS];
    uint32_t NSAPR[GIC_NUM_APR_REGS];
    uint8_t pad1[0x00FC - 0x00F0];
    uint32_t IIDR;
    uint8_t pad2[0x1000 - 0x0100];
    uint32_t DIR;
} __attribute__((__packed__, aligned(0x1000)));

#define GICH_HCR_En_BIT        (1 << 0)
#define GICH_HCR_UIE_BIT       (1 << 1)
#define GICH_HCR_LRENPIE_BIT   (1 << 2)
#define GICH_HCR_NPIE_BIT      (1 << 3)
#define GICH_HCR_VGrp0DIE_BIT  (1 << 4)
#define GICH_HCR_VGrp0EIE_BIT  (1 << 5)
#define GICH_HCR_VGrp1EIE_BIT  (1 << 6)
#define GICH_HCR_VGrp1DIE_BIT  (1 << 7)
#define GICH_HCR_EOICount_OFF  (27)
#define GICH_HCR_EOICount_LEN  (5)
#define GICH_HCR_EOICount_MASK BIT32_MASK(GICH_HCR_EOICount_OFF, GICH_HCR_EOICount_LEN)

#define ICH_HCR_VGrp1EIE_BIT   (1ULL << 6)
#define ICH_HCR_LRENPIE_BIT    GICH_HCR_LRENPIE_BIT

#define GICH_VTR_OFF           (0)
#define GICH_VTR_LEN           (6)
#define GICH_VTR_MSK           BIT32_MASK(GICH_VTR_OFF, GICH_VTR_LEN)

#define ICH_VTR_OFF            GICH_VTR_OFF
#define ICH_VTR_LEN            GICH_VTR_LEN
#define ICH_VTR_MSK            GICH_VTR_MSK

#if (GIC_VERSION == GICV2)
#define GICH_LR_VID_OFF   (0)
#define GICH_LR_VID_LEN   (10)
#define GICH_LR_PID_OFF   (10)
#define GICH_LR_PID_LEN   (10)
#define GICH_LR_PRIO_OFF  (23)
#define GICH_LR_PRIO_LEN  (5)
#define GICH_LR_STATE_OFF (28)
#define GICH_LR_STATE_LEN (2)
#define GICH_LR_HW_BIT    (1U << 31)
#define GICH_LR_EOI_BIT   (1U << 19)
#define GICH_NUM_ELRSR    (2)
#define GICH_LR_PRIO_MSK  BIT32_MASK(GICH_LR_PRIO_OFF, GICH_LR_PRIO_LEN)
#define GICH_LR_PID_MSK   BIT32_MASK(GICH_LR_PID_OFF, GICH_LR_PID_LEN)
#define GICH_LR_STATE_MSK BIT32_MASK(GICH_LR_STATE_OFF, GICH_LR_STATE_LEN)
#define GICH_LR_STATE(LR) (bit32_extract(LR, GICH_LR_STATE_OFF, GICH_LR_STATE_LEN))
typedef uint32_t gic_lr_t;
#else
#define GICH_LR_VID_OFF   (0)
#define GICH_LR_VID_LEN   (32)
#define GICH_LR_PID_OFF   (32)
#define GICH_LR_PID_LEN   (10)
#define GICH_LR_PRIO_OFF  (48)
#define GICH_LR_PRIO_LEN  (8)
#define GICH_LR_STATE_OFF (62)
#define GICH_LR_STATE_LEN (2)
#define GICH_LR_GRP_BIT   (1ULL << 60)
#define GICH_LR_HW_BIT    (1ULL << 61)
#define GICH_LR_EOI_BIT   (1ULL << 41)
#define GICH_NUM_ELRSR    (1)
#define GICH_LR_PRIO_MSK  BIT64_MASK(GICH_LR_PRIO_OFF, GICH_LR_PRIO_LEN)
#define GICH_LR_PID_MSK   BIT64_MASK(GICH_LR_PID_OFF, GICH_LR_PID_LEN)
#define GICH_LR_STATE_MSK BIT64_MASK(GICH_LR_STATE_OFF, GICH_LR_STATE_LEN)
#define GICH_LR_STATE(LR) (bit64_extract(LR, GICH_LR_STATE_OFF, GICH_LR_STATE_LEN))
typedef uint64_t gic_lr_t;
#endif

#define GICH_LR_CPUID_OFF     (10)
#define GICH_LR_CPUID_LEN     (3)

#define GICH_LR_VID_MSK       BIT_MASK(GICH_LR_VID_OFF, GICH_LR_VID_LEN)
#define GICH_LR_VID(LR)       (bit_extract(LR, GICH_LR_VID_OFF, GICH_LR_VID_LEN))

#define GICH_LR_CPUID_MSK     BIT_MASK(GICH_LR_CPUID_OFF, GICH_LR_CPUID_LEN)
#define GICH_LR_CPUID(LR)     (bit_extract(LR, GICH_LR_CPUID_OFF, GICH_LR_CPUID_LEN))

#define GICH_LR_STATE_INV     ((0ULL << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_PND     ((1ULL << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_ACT     ((2ULL << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_ACTPEND ((3ULL << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)

#define GICH_MISR_EOI         (1U << 0)
#define GICH_MISR_U           (1U << 1)
#define GICH_MISR_LRPEN       (1U << 2)
#define GICH_MISR_NP          (1U << 3)
#define GICH_MISR_VGrp0E      (1U << 4)
#define GICH_MISR_VGrp0D      (1U << 5)
#define GICH_MISR_VGrp1E      (1U << 6)
#define GICH_MISR_VGrp1D      (1U << 7)

struct gich_hw {
    uint32_t HCR;
    uint32_t VTR;
    uint32_t VMCR;
    uint8_t pad0[0x10 - 0x0c];
    uint32_t MISR;
    uint8_t pad1[0x20 - 0x14];
    uint32_t EISR[GIC_NUM_LIST_REGS / (sizeof(uint32_t) * 8)];
    uint8_t pad2[0x30 - 0x28];
    uint32_t ELSR[GIC_NUM_LIST_REGS / (sizeof(uint32_t) * 8)];
    uint8_t pad3[0xf0 - 0x38];
    uint32_t APR;
    uint8_t pad4[0x100 - 0x0f4];
    uint32_t LR[GIC_NUM_LIST_REGS];
} __attribute__((__packed__, aligned(0x1000)));

struct gicv_hw {
    uint32_t CTLR;
    uint32_t PMR;
    uint32_t BPR;
    uint32_t IAR;
    uint32_t EOIR;
    uint32_t RPR;
    uint32_t HPPIR;
    uint32_t ABPR;
    uint32_t AIAR;
    uint32_t AEOIR;
    uint32_t AHPPIR;
    uint8_t pad0[0xD0 - 0x2C];
    uint32_t APR[GIC_NUM_APR_REGS];
    uint8_t pad1[0x00FC - 0x00E0];
    uint32_t IIDR;
    uint8_t pad2[0x1000 - 0x0100];
    uint32_t DIR;
} __attribute__((__packed__, aligned(0x1000)));

extern volatile struct gicd_hw* gicd;
extern volatile struct gicc_hw* gicc;
extern volatile struct gich_hw* gich;

enum int_state { INV, PEND, ACT, PENDACT };

struct gicc_state {
    uint32_t CTLR;
    uint32_t PMR;
    uint32_t BPR;
    uint32_t IAR;
    uint32_t EOIR;
    uint32_t RPR;
    uint32_t HPPIR;
    uint32_t priv_ISENABLER;
    uint32_t priv_IPRIORITYR[GIC_NUM_PRIO_REGS(GIC_CPU_PRIV)];

    uint32_t HCR;
    unsigned long LR[GIC_NUM_LIST_REGS];
};

extern size_t NUM_LRS;

void gic_init();
void gic_cpu_init();
void gic_send_sgi(cpuid_t cpu_target, irqid_t sgi_num);

void gicc_save_state(struct gicc_state* state);
void gicc_restore_state(struct gicc_state* state);

void gic_set_enable(irqid_t int_id, bool en);
void gic_set_prio(irqid_t int_id, uint8_t prio);
void gic_set_icfgr(irqid_t int_id, uint8_t cfg);
void gic_set_pend(irqid_t int_id, bool pend);
void gic_set_act(irqid_t int_id, bool act);
uint8_t gic_get_prio(irqid_t int_id);
bool gic_get_pend(irqid_t int_id);
bool gic_get_act(irqid_t int_id);

void gicd_set_enable(irqid_t int_id, bool en);
void gicd_set_pend(irqid_t int_id, bool pend);
void gicd_set_prio(irqid_t int_id, uint8_t prio);
void gicd_set_icfgr(irqid_t int_id, uint8_t cfg);
void gicd_set_act(irqid_t int_id, bool act);
void gicd_set_trgt(irqid_t int_id, uint8_t cpu_targets);
void gicd_set_route(irqid_t int_id, unsigned long route);
bool gicd_get_pend(irqid_t int_id);
bool gicd_get_act(irqid_t int_id);
uint8_t gicd_get_prio(irqid_t int_id);

void gicr_set_enable(irqid_t int_id, bool en, cpuid_t gicr_id);
void gicr_set_pend(irqid_t int_id, bool pend, cpuid_t gicr_id);
void gicr_set_prio(irqid_t int_id, uint8_t prio, cpuid_t gicr_id);
void gicr_set_icfgr(irqid_t int_id, uint8_t cfg, cpuid_t gicr_id);
void gicr_set_act(irqid_t int_id, bool act, cpuid_t gicr_id);
uint8_t gicr_get_prio(irqid_t int_id, cpuid_t gicr_id);

bool gicr_get_en_lpis(cpuid_t gicr_id);
void gicr_set_propbaser(cpuid_t gicr_id, uint64_t phy_addr, size_t id_bits);
void gicr_set_pendbaser(cpuid_t gicr_id, uint64_t phy_addr);
void gicr_set_vpropbaser(cpuid_t gicr_id, uint64_t phy_addr, size_t id_bits);
void gicr_set_vpendbaser(cpuid_t gicr_id, uint64_t phy_addr);

void gic_maintenance_handler(irqid_t irq_id);

struct its_cmd{
    uint64_t cmd[4];
};

static inline void its_mask_encode(uint64_t *cmd_dw, uint64_t val, size_t off, size_t len){
    uint64_t msk = BIT64_MASK(off,len);
    *cmd_dw &= ~msk;
    *cmd_dw |= (val << off) & msk;
}

void its_encode_cmd(struct its_cmd *cmd, uint8_t cmd_id);
void its_encode_valid(struct its_cmd *cmd, size_t val);
void its_encode_target(struct its_cmd *cmd, uint64_t target);
void its_encode_ic_id(struct its_cmd *cmd, uint64_t ic_id);
void its_encode_size(struct its_cmd *cmd, uint8_t size);
void its_encode_itt_addr(struct its_cmd *cmd, uint64_t itt_addr);
void its_encode_device_id(struct its_cmd *cmd, uint32_t device_id);

void its_encode_vpe_id(struct its_cmd *cmd, uint16_t vpe_id);
void its_encode_vpt_addr(struct its_cmd *cmd, uint64_t vpt_addr);
void its_encode_vpt_size(struct its_cmd *cmd, uint8_t vpt_sz);
void its_encode_event_id(struct its_cmd *cmd, uint32_t event_id);
void its_encode_db_id(struct its_cmd *cmd, uint32_t db_id);
void its_encode_virt_id(struct its_cmd *cmd, uint32_t virt_id);

#if (GIC_VERSION == GICV4)
void its_translate_vcmd(struct its_cmd *dest_cmd,
                    struct its_cmd *src_cmd);
#elif (GIC_VERSION == GICv3)
void its_translate_cmd(struct its_cmd *dest_cmd,
                    struct its_cmd *src_cmd);
#endif


extern volatile struct gicd_hw* gicd;
extern volatile struct gicr_hw* gicr;
extern spinlock_t gicr_lock;


    /*----------- GIC ITS -----------*/

    // Define only to GICv3
    // Verify the alignement and the offsets

    #define GIC_MAX_TTD               8     //max translation table descriptors

    #define GITS_TYPER_PHY_OFF              (0)
    #define GITS_TYPER_VIRT_OFF             (1)
    #define GITS_TYPER_VIRT_MSK             (1ULL << 1)

    #define GITS_TYPER_CID_OFF              (32)
    #define GITS_TYPER_CID_LEN              (4)
    #define GITS_TYPER_CID_MSK              (BIT_MASK(GITS_TYPER_CID_OFF, GITS_TYPER_CID_LEN))
    #define GITS_TYPER_CIL_BIT              (1ULL << 36)

    

    #define GITS_CBASER_RaWaWb              (7ULL << 59)
    #define GITS_CBASER_InnerShareable      (1ULL << 10)
    #define GITS_CBASER_VALID               (1ULL << 63)
    #define GITS_CBASER_PHY_ADDR_OFF        (12)
    #define GITS_CBASER_PHY_ADDR_LEN        (40)

    #define GITS_CBASER_SIZE_MSK            (0xff)
    #define GITS_CBASER_PHY_ADDR_MSK        (BIT64_MASK(GITS_CBASER_PHY_ADDR_OFF,GITS_CBASER_PHY_ADDR_LEN))

    #define GITS_BASER_VALID_BIT            (1ULL << 63)
    #define GITS_BASER_PHY_ADDR_OFF         (12)
    #define GITS_BASER_PHY_ADDR_LEN         (36)
    #define GITS_BASER_PHY_ADDR_MSK         (BIT64_MASK(GITS_BASER_PHY_ADDR_OFF,GITS_BASER_PHY_ADDR_LEN))
    #define GITS_BASER_TYPE_OFF             (56)
    #define GITS_BASER_TYPE_LEN             (3)
    #define GITS_BASER_TYPE_MASK            (BIT64_MASK(GITS_BASER_TYPE_OFF,GITS_BASER_TYPE_LEN))
    #define GITS_BASER_ENTRY_SZ_OFF         (48)
    #define GITS_BASER_ENTRY_SZ_LEN         (5)
    #define GITS_BASER_ENTRY_SZ_MASK        (BIT64_MASK(GITS_BASER_ENTRY_SZ_OFF,GITS_BASER_ENTRY_SZ_LEN))
    #define GITS_BASER_PAGE_SZ_OFF          (56)
    #define GITS_BASER_PAGE_SZ_LEN          (3)
    #define GITS_BASER_PAGE_SZ_MASK         (BIT64_MASK(GITS_BASER_PAGE_SZ_OFF,GITS_BASER_PAGE_SZ_LEN))
    #define GITS_BASER_RO_MASK              (GITS_BASER_TYPE_MASK | GITS_BASER_ENTRY_SZ_MASK | GITS_BASER_PAGE_SZ_MASK)
    
    #define GITS_BASER_PHY_OFF                  (12)
    #define GITS_BASER_PHY_LEN                  (36)
    #define GITS_BASER_SHAREABILITY_OFF         (10)
    #define GITS_BASER_INNERCACHE_OFF           (59)
    #define GITS_BASER_InnerShareable           (1ULL << GITS_BASER_SHAREABILITY_OFF)
    #define GITS_BASER_RaWaWb                   (7ULL << GITS_BASER_INNERCACHE_OFF)
    #define GITS_BASER_VAL_BIT                   (1ULL << 63)

    #define GIC_HAS_VLPI(gits)		(!!((gits)->TYPER & GITS_TYPER_VIRT_MSK))

    #define GITS_BASER_COLLT_TYPE           (0x4)
    #define GITS_BASER_VPET_TYPE            (0x2)



    /*
    * ITS command descriptors - parameters to be encoded in a command
    * block.
    */
    struct its_cmd_desc {
        union {
            struct {
            	uint16_t ic_id;
                uint64_t target;
                bool valid;
            } its_mapc_cmd;

            struct {
                uint64_t target;
            } its_sync_cmd;

            struct {
                uint32_t device_id;
                uint8_t size;
                uint64_t itt_addr;
                bool valid;
            } its_mapd_cmd;

            struct {
                uint32_t device_id;
                uint32_t event_id;
            } its_inv_cmd;

            struct {
                uint16_t vpe_id;
                uint64_t target;
                uint64_t vpt_addr;
                uint8_t vpt_size;
                bool valid;
            } its_vmapp_cmd;

            struct {
                uint16_t vpe_id;
            } its_vmovi_cmd;

            struct {
                uint16_t vpe_id;
            } its_vinvall_cmd;

            struct {
                uint16_t vpe_id;
            } its_vsync_cmd;

            struct {
                uint16_t vpe_id;
                uint32_t device_id;
                uint32_t virt_id;
                uint32_t event_id;
                uint32_t db_id;
                bool db_enabled;
            } its_vmapti_cmd;
        };
    };

    //Changed the pads numbers
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
        /*uint8_t transl_base[0] __attribute__((aligned(0x10000)));
        uint8_t pad3[0x40 - 0x0];
        uint32_t TRANSLATER;
        uint8_t pad4[0x10000 - 0x44];*/
    } __attribute__((__packed__, aligned(0x10000)));    //64KB-aligned?

    extern volatile struct gits_hw* gits;


    #define ITS_CMD_QUEUE_N_PAGE     16
    #define ITS_COLL_BITS_MAX        16



    /* ITS defines */
    #define ITS_MAPC_CMD            (0x09)     
    #define ITS_SYNC_CMD            (0x05)
    #define ITS_MAPD_CMD            (0x08)
    #define ITS_INV_CMD             (0x0C)
    #define ITS_MAPI_CMD            (0x0B)
    #define ITS_INVALL_CMD          (0x0D)
    #define ITS_MAPTI_CMD           (0x0A)

    #define ITS_VMAPP_CMD           (0x29)
    #define ITS_VSYNC_CMD           (0x25)
    #define ITS_VINVALL_CMD         (0x2D)
    #define ITS_VMAPTI_CMD          (0x2A)


    #define ITS_CMD_ENC_OFF         (0)
    #define ITS_CMD_ENC_LEN         (8)
    #define ITS_CMD_RDBASE_OFF      (16)
    #define ITS_CMD_RDBASE_LEN      (35)

    extern struct its_cmd *its_cmd_queue;
//#endif

size_t gich_num_lrs();

static inline size_t gic_num_irqs()
{
    size_t itlinenumber = bit32_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    return 32 * itlinenumber + 1;
}

static inline bool gic_is_sgi(irqid_t int_id)
{
    return int_id < GIC_MAX_SGIS;
}

static inline bool gic_is_priv(irqid_t int_id)
{
    return int_id < GIC_CPU_PRIV;
}

#endif /* __GIC_H__ */
