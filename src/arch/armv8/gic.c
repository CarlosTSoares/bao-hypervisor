/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <arch/gic.h>

#if (GIC_VERSION == GICV2)
#include <arch/gicv2.h>
#elif (GIC_VERSION == GICV3)
#include <arch/gicv3.h>
#else
#error "unknown GIV version " GIC_VERSION
#endif

#include <interrupts.h>
#include <cpu.h>
#include <spinlock.h>
#include <platform.h>
#include <fences.h>

volatile struct gicd_hw* gicd;
spinlock_t gicd_lock;

void gicd_init()
{
    size_t int_num = gic_num_irqs();

    /* Bring distributor to known state */
    for (size_t i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
        /**
         * Make sure all interrupts are not enabled, non pending, non active.
         */
        gicd->IGROUPR[i] = -1;
        gicd->ICENABLER[i] = -1;
        gicd->ICPENDR[i] = -1;
        gicd->ICACTIVER[i] = -1;
    }

    /* All interrupts have lowest priority possible by default */
    for (size_t i = GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i < GIC_NUM_PRIO_REGS(int_num); i++) {
        gicd->IPRIORITYR[i] = -1;
    }

    if (GIC_VERSION == GICV2) {
        /* No CPU targets for any interrupt by default */
        for (size_t i = GIC_NUM_TARGET_REGS(GIC_CPU_PRIV); i < GIC_NUM_TARGET_REGS(int_num); i++) {
            gicd->ITARGETSR[i] = 0;
        }

        /* Enable distributor */
        gicd->CTLR |= GICD_CTLR_EN_BIT;

    } else {
        for (size_t i = GIC_CPU_PRIV; i < GIC_MAX_INTERUPTS; i++) {
            gicd->IROUTER[i] = GICD_IROUTER_INV;
        }

        /* Enable distributor and affinity routing */
        gicd->CTLR |= GICD_CTLR_ARE_NS_BIT | GICD_CTLR_ENA_BIT;
    }

    /* ICFGR are platform dependent, lets leave them as is */

    /* No need to setup gicd->NSACR as all interrupts are  setup to group 1 */

    if (!interrupts_reserve(platform.arch.gic.maintenance_id, gic_maintenance_handler)) {
        ERROR("Failed to reserve GIC maintenance interrupt");
    }
}

void gic_map_mmio();

bool gicd_supports_LPIs(){

    return (gicd->TYPER & GICD_TYPER_LPIS_BIT) ? true: false;
}

void gic_init()
{
    if (GIC_VERSION == GICV3) {
        sysreg_icc_sre_el2_write(ICC_SRE_SRE_BIT | ICC_SRE_ENB_BIT);    //Enable the system register interface and enable el1 access to icc_sre_el1
        ISB();
    }

    if (cpu()->id == CPU_MASTER) {
        gic_map_mmio();
        gicd_init();
        NUM_LRS = gich_num_lrs();

        if(gicd_supports_LPIs()) //don't need gic version condition
        {
            console_printk("[BAO] LPI supported\n");
            gits_map_mmio();
        }
    }

    cpu_sync_and_clear_msgs(&cpu_glb_sync);

    gic_cpu_init();

    //console_printk("[BAO] Value of propbaser affinity is 0x%x\n",(gicr[cpu()->id].TYPER >> 24) & 0x3);

    //if gicv3
    // if(gicd_supports_LPIs() && cpu()->id == CPU_MASTER)
    // {
    //     console_printk("[BAO] Support LPIs in distributor\n");
    //     //disable redist LPIs
    //     for(cpuid_t cpu_id = 0; cpu_id < PLAT_CPU_NUM;cpu_id++)
    //         disable_gicr_lpis(cpu_id); // all redistributor have the same propbaser

    //     //allocate proptable
    //     bool err = gic_alloc_lpi_tables();
    //     if(err)
    //         ERROR("Can't allocate the LPI tables\n");

        
    //     gic_cpu_init_lpis();
        
    //     //enable redist LPIs
    //     //enable_gicr_lpis();
    // }


}

void gic_handle()
{
    uint32_t ack = gicc_iar();  //ack
    irqid_t id = bit32_extract(ack, GICC_IAR_ID_OFF, GICC_IAR_ID_LEN);

    if (id < GIC_FIRST_SPECIAL_INTID) {
        // if(id != 27 && id != 78 && id != 1 && id != 79)
        //     console_printk("BAO: Interrupt received wiht ID - %d\n",id);
        enum irq_res res = interrupts_handle(id);
        gicc_eoir(ack);         //gic end of interrupt
        if (res == HANDLED_BY_HYP) {
            gicc_dir(ack);      //gic desactivate interrupt
        }
    }else {
        console_printk("[BAO] Interrupt received wiht ID out of range - %d\n",id);
        /*LPI range*/

        /* To-Do
        - Verify if INTID belongs to VM
        - Condition if no List register is available
        */

        /*List register available*/
        ssize_t lr_ind = -1;
        gic_lr_t lr;
        uint64_t elrsr = gich_get_elrsr();          //locate a usable List register when hypervisor is delivering an interrupt to a VM
        for (size_t i = 0; i < NUM_LRS; i++) {
            if (bit64_get(elrsr, i)) {               //contains a valid interrupt
                lr_ind = i;
                break;
            }
        }

        console_printk("[Bao] List register index: %d\n",lr_ind);
        
        if(lr_ind < 0) {
            console_printk("[Bao] Cannot get a List register\n");
        } else {
            console_printk("[Bao] List register obtained\n");
            lr = ((id << GICH_LR_VID_OFF) & GICH_LR_VID_MSK);
            lr |= (((gic_lr_t)0x02 << GICH_LR_PRIO_OFF) & GICH_LR_PRIO_MSK) | GICH_LR_GRP_BIT;
            lr |= GICH_LR_EOI_BIT;
            lr |= ((gic_lr_t)PEND << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK;
            gich_write_lr(lr_ind, lr);

            console_printk("[Bao] List register updated\n");
        }
        gicc_eoir(ack);

    }
}

uint8_t gicd_get_prio(irqid_t int_id)
{
    size_t reg_ind = GIC_PRIO_REG(int_id);
    size_t off = GIC_PRIO_OFF(int_id);

    uint8_t prio = gicd->IPRIORITYR[reg_ind] >> off & BIT32_MASK(off, GIC_PRIO_BITS);

    return prio;
}

void gicd_set_icfgr(irqid_t int_id, uint8_t cfg)
{
    size_t reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    size_t off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    uint32_t mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    spin_lock(&gicd_lock);

    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);

    spin_unlock(&gicd_lock);
}

void gicd_set_prio(irqid_t int_id, uint8_t prio)
{
    size_t reg_ind = GIC_PRIO_REG(int_id);
    size_t off = GIC_PRIO_OFF(int_id);
    uint32_t mask = BIT32_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicd_lock);

    gicd->IPRIORITYR[reg_ind] = (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);

    spin_unlock(&gicd_lock);
}

void gicd_set_pend(irqid_t int_id, bool pend)
{
    size_t reg_ind = GIC_INT_REG(int_id);
    if (pend) {
        gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    } else {
        gicd->ICPENDR[reg_ind] = GIC_INT_MASK(int_id);
    }
}

bool gicd_get_pend(irqid_t int_id)
{
    return (gicd->ISPENDR[GIC_INT_REG(int_id)] & GIC_INT_MASK(int_id)) != 0;
}

void gicd_set_act(irqid_t int_id, bool act)
{
    size_t reg_ind = GIC_INT_REG(int_id);

    if (act) {
        gicd->ISACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    } else {
        gicd->ICACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    }
}

bool gicd_get_act(irqid_t int_id)
{
    return (gicd->ISACTIVER[GIC_INT_REG(int_id)] & GIC_INT_MASK(int_id)) != 0;
}

void gicd_set_enable(irqid_t int_id, bool en)
{
    size_t reg_ind = GIC_INT_REG(int_id);
    uint32_t bit = GIC_INT_MASK(int_id);

    if (en) {
        gicd->ISENABLER[reg_ind] = bit;
    } else {
        gicd->ICENABLER[reg_ind] = bit;
    }
}
