/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <bao.h>
#include <interrupts.h>

#include <cpu.h>
#include <platform.h>
#include <arch/gic.h>
#include <mem.h>
#include <arch/sysregs.h>
#include <vm.h>

#ifndef GIC_VERSION
#error "GIC_VERSION not defined for this platform"
#endif

void interrupts_arch_init()
{
    gic_init();
    interrupts_cpu_enable(platform.arch.gic.maintenance_id, true);
}

void interrupts_arch_ipi_send(cpuid_t target_cpu, irqid_t ipi_id)
{
    if (ipi_id < GIC_MAX_SGIS) {
        gic_send_sgi(target_cpu, ipi_id);
    }
}

void interrupts_arch_enable(irqid_t int_id, bool en)
{
    gic_set_enable(int_id, en);
    gic_set_prio(int_id, 0x01);
    if (GIC_VERSION == GICV2) {
        gicd_set_trgt(int_id, 1 << cpu()->id);
    } else {
        gicd_set_route(int_id, cpu()->arch.mpidr);
    }
}

bool interrupts_arch_check(irqid_t int_id)
{
    return gic_get_pend(int_id);
}

inline bool interrupts_arch_conflict(bitmap_t* interrupt_bitmap, irqid_t int_id)
{
    return (bitmap_get(interrupt_bitmap, int_id) && int_id > GIC_CPU_PRIV);
}

void interrupts_arch_clear(irqid_t int_id)
{
    gic_set_act(int_id, false);
    gic_set_pend(int_id, false);
}

void interrupts_arch_vm_assign(struct vm* vm, irqid_t id)
{
    vgic_set_hw(vm, id);
}

//MSI

bool interrupts_arch_msi_init(struct vm* vm){
    if(GIC_HAS_VLPI(gits)){
        struct ppages pages = { .num_pages = 0 };

        //vpendtables size in bytes
        // size_t id_bits = (gicd->TYPER & GICD_TYPER_IDBITS_MSK) >> GICD_TYPER_IDBITS_OFF;

        // size_t size = (1 << (id_bits + 1)) / 8;
        // console_printk("Size is: 0x%x and num pages is %d\n",size, NUM_PAGES(0x10000));
        //Alloc vpendtables
        for(int n_vcpus=0;n_vcpus<vm->cpu_num;n_vcpus++)   //for all vcpus
        {
            //vm->vcpus[n_vcpus].arch.vgits_vpendTable = mem_alloc_page(NUM_PAGES(0x10000),SEC_HYP_VM,true);
            //pp_alloc(,16,true,&pages);
            pages = mem_alloc_ppages(cpu()->as.colors,16,true);
            console_printk("PHY page of vpend is 0x%lx\n",pages.base);

            //TODO: Verify if all table is cleared


            cpuid_t pgicr_id = vm_translate_to_pcpuid(vm, n_vcpus); //ERROR verification
            console_printk("Value of pgicr_id id %d and nvcpu is %d\n",pgicr_id,n_vcpus);
            console_printk("Value of vpend is 0x%lx\n",gicr[pgicr_id].VPENDBASER);

            cpu()->vcpu->arch.vgits_vpendTable = pages.base;

            gicr[pgicr_id].VPENDBASER = pages.base |
                            GICR_PROPBASER_InnerShareable |
                            GICR_PROPBASER_RaWaWb |
                            GICR_VPENDBASER_IDAI_BIT;
            console_printk("Value of vpend is 0x%lx\n",gicr[pgicr_id].VPENDBASER);

            gicr[pgicr_id].VPENDBASER |= GICR_VPENDBASER_VAL_BIT;
            console_printk("Value of vpend is 0x%lx\n",gicr[pgicr_id].VPENDBASER);
        }

        return false;
    } else {
        return true;
    }
    return false;
}