/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <arch/vgic.h>
#include <arch/vgicv3.h>

#include <bit.h>
#include <spinlock.h>
#include <cpu.h>
#include <interrupts.h>
#include <vm.h>
#include <platform.h>

#define GICR_IS_REG(REG, offset)                    \
    (((offset) >= offsetof(struct gicr_hw, REG)) && \
        (offset) < (offsetof(struct gicr_hw, REG) + sizeof(gicr[0].REG)))


#define GICR_REG_OFF(REG)   (offsetof(struct gicr_hw, REG) & 0x1ffff)

//#if (GIC_VERSION == GICV3)
    #define GICR_REG_MASK(ADDR) ((ADDR) & 0x1ffff)
// #elif (GIC_VERSION == GICV4)
//     #define GICR_REG_MASK(ADDR) (((ADDR) & 0xffff) | ((ADDR & 0x30000)^0x20000))
// #else
//     #error "unknown GIV version " GIC_VERSION
// #endif


#define GICD_REG_MASK(ADDR) ((ADDR) & (GIC_VERSION == GICV2 ? 0xfffUL : 0xffffUL))


#define GITS_IS_REG(REG, offset)                    \
    (((offset) >= offsetof(struct gits_hw, REG)) && \
        (offset) < (offsetof(struct gits_hw, REG) + sizeof(gits->REG)))
#define GITS_REG_OFF(REG)   (offsetof(struct gits_hw, REG) & 0x1ffff)
#define GITS_REG_MASK(ADDR) ((ADDR) & 0x1ffff)

#define GITS_CMD_MASK(CMD)  (bit64_extract(CMD->cmd[0],ITS_CMD_ENC_OFF,ITS_CMD_ENC_LEN))


//static spinlock_t gits_lock = SPINLOCK_INITVAL;

bool vgic_int_has_other_target(struct vcpu* vcpu, struct vgic_int* interrupt)
{
    bool priv = gic_is_priv(interrupt->id);
    bool routed_here =
        !priv && !(interrupt->phys.route ^ (sysreg_mpidr_el1_read() & MPIDR_AFF_MSK));
    bool route_valid = interrupt->phys.route != GICD_IROUTER_INV;
    bool any = !priv && vgic_broadcast(vcpu, interrupt);
    return any || (!routed_here && route_valid);
}

uint8_t vgic_int_ptarget_mask(struct vcpu* vcpu, struct vgic_int* interrupt)
{
    if (vgic_broadcast(vcpu, interrupt)) {
        return cpu()->vcpu->vm->cpus & ~(1U << cpu()->vcpu->phys_id);
    } else {
        return (1 << interrupt->phys.route);
    }
}

bool vgic_int_set_route(struct vcpu* vcpu, struct vgic_int* interrupt, unsigned long route)
{
    unsigned long phys_route;
    unsigned long prev_route = interrupt->route;

    if (gic_is_priv(interrupt->id)) {
        return false;
    }

    if (route & GICD_IROUTER_IRM_BIT) {
        phys_route = cpu_id_to_mpidr(vcpu->phys_id);
    } else {
        struct vcpu* tvcpu = vm_get_vcpu_by_mpidr(vcpu->vm, route & MPIDR_AFF_MSK);
        if (tvcpu != NULL) {
            phys_route = cpu_id_to_mpidr(tvcpu->phys_id) & MPIDR_AFF_MSK;
        } else {
            phys_route = GICD_IROUTER_INV;
        }
    }
    interrupt->phys.route = phys_route;

    interrupt->route = route & GICD_IROUTER_RES0_MSK;
    return prev_route != interrupt->route;
}

unsigned long vgic_int_get_route(struct vcpu* vcpu, struct vgic_int* interrupt)
{
    if (gic_is_priv(interrupt->id)) {
        return 0;
    }
    return interrupt->route;
}

void vgic_int_set_route_hw(struct vcpu* vcpu, struct vgic_int* interrupt)
{
    gicd_set_route(interrupt->id, interrupt->phys.route);
}

void vgicr_emul_ctrl_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id)
{
    if (!acc->write) {
        if(cpu()->vcpu->vm->msi){
            cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
            vcpu_writereg(cpu()->vcpu, acc->reg, gicr_get_en_lpis(pgicr_id));
            console_printk("VGICv3: rCTRL value readed: 0x%x\n",gicr_get_en_lpis(pgicr_id));
        } else {
            vcpu_writereg(cpu()->vcpu, acc->reg, 0); //read as zero
        }
    } else {    //if hasnt given the msi config then the VM cannot modify the CTLR.ENABLEBITS
        if(cpu()->vcpu->vm->msi){
            cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
            uint32_t val = gicr[pgicr_id].CTLR & ~(GICR_CTLR_EN_LPIS_MSK);
            gicr[pgicr_id].CTLR = val | (vcpu_readreg(cpu()->vcpu, acc->reg) & GICR_CTLR_EN_LPIS_MSK); 
            console_printk("VGICv3: rCTRL value set to: 0x%x\n",gicr[cpu()->id].CTLR);
        }
    }
}

void vgicr_emul_typer_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id)
{
    bool word_access = (acc->width == 4);
    bool top_access = word_access && ((acc->addr & 0x4) != 0);

    if (!acc->write) {
        struct vcpu* vcpu = vm_get_vcpu(cpu()->vcpu->vm, vgicr_id);
        uint64_t typer = vcpu->arch.vgic_priv.vgicr.TYPER;

        console_printk("Typer value of vcpu %d is 0x%x\n",vcpu->id,typer);

        if (top_access) {
            typer >>= 32;
        } else if (word_access) {
            typer &= BIT_MASK(0, 32);
        }

        vcpu_writereg(cpu()->vcpu, acc->reg, typer);
    }
}

void vgicr_emul_pidr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id)
{
    if (!acc->write) {
        //unsigned long val = 0;
        // cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
        // if (pgicr_id != INVALID_CPUID) {
        //     //val = gicr[pgicr_id].ID[((acc->addr & 0xff) - 0xd0) / 4];
        // }
        vcpu_writereg(cpu()->vcpu, acc->reg, 0x3b);
    }
}

void vgicd_emul_router_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id)
{
    bool word_access = (acc->width == 4);
    bool top_access = word_access && ((acc->addr & 0x4) != 0);
    vaddr_t aligned_addr = acc->addr & ~((vaddr_t)0x7);
    size_t irq_id = (GICD_REG_MASK(aligned_addr) - offsetof(struct gicd_hw, IROUTER)) / 8;

    struct vgic_int* interrupt = vgic_get_int(cpu()->vcpu, irq_id, cpu()->vcpu->id);

    if (interrupt == NULL) {
        return vgic_emul_razwi(acc, handlers, gicr_access, vgicr_id);
    }

    uint64_t route = vgic_int_get_route(cpu()->vcpu, interrupt);
    if (!acc->write) {  //read route
        if (top_access) {
            vcpu_writereg(cpu()->vcpu, acc->reg, (uint32_t)(route >> 32));
        } else if (word_access) {
            vcpu_writereg(cpu()->vcpu, acc->reg, (uint32_t)route);
        } else {
            vcpu_writereg(cpu()->vcpu, acc->reg, route);
        }
    } else {
        uint64_t reg_value = vcpu_readreg(cpu()->vcpu, acc->reg);
        if (top_access) {
            route = (route & BIT64_MASK(0, 32)) | ((reg_value & BIT64_MASK(0, 32)) << 32);
        } else if (word_access) {
            route = (route & BIT64_MASK(32, 32)) | (reg_value & BIT64_MASK(0, 32));
        } else {
            route = reg_value;
        }
        vgic_int_set_field(handlers, cpu()->vcpu, interrupt, route);
    }
}

/* Propbaser and Pendbaser emulation*/

// bool proptable_emul_handler(struct emul_access* acc){


void vgicr_emul_propbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    struct vcpu *target_vcpu = vm_get_vcpu(cpu()->vcpu->vm, vgicr_id);
    struct vm *vm = target_vcpu->vm;

    if (!acc->write) {
        
        if(vm->msi)
        {
            cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
            console_printk("Redistributor vID is %d and pID is %d\n",vgicr_id,pgicr_id);
            if (pgicr_id != INVALID_CPUID) {
                vcpu_writereg(cpu()->vcpu, acc->reg,cpu()->vcpu->arch.vgic_priv.vgicr.PROPBASER);
                console_printk("VGIC3: Propbaser read from cpu %d -> 0x%x\n",cpu()->id,cpu()->vcpu->arch.vgic_priv.vgicr.PROPBASER);
            }
        } else {
            vcpu_writereg(cpu()->vcpu, acc->reg,0);
        }

    }else{
        cpuid_t pgicr_id = vm_translate_to_pcpuid(vm, vgicr_id);
        
        if((pgicr_id != INVALID_CPUID) && vm->msi && !gicr_get_en_lpis(pgicr_id))
        {
            //translate to physical
            uint64_t tmp_propbaser = vcpu_readreg(cpu()->vcpu, acc->reg);
            paddr_t proptable_pa = 0;

            vaddr_t *proptable_vaddr = (vaddr_t *)(tmp_propbaser & GICR_PROPBASER_PHY_ADDR_MSK);
            size_t id_bits = tmp_propbaser & GICR_PROPBASER_ID_BITS_MSK;
            size_t proptable_size = GICR_PROPTABLE_SZ(id_bits);

            mem_guest_ipa_translate(proptable_vaddr,&proptable_pa);


            if(vm->arch.prop_tab.proptab_base == NULL) {
                console_printk("[BAO-VGICV3] First allocation of Proptable from cpu %d\n",cpu()->id);

                vm->arch.prop_tab.proptab_size = proptable_size;
                vm->arch.prop_tab.proptab_base = (uint8_t *)mem_alloc_map_dev(&cpu()->as, SEC_HYP_GLOBAL, INVALID_VA,
                proptable_pa,NUM_PAGES(vm->arch.prop_tab.proptab_size)); //Wrong section probably

                console_printk("Here 1 and vm id is %d\n",vm->id);
                console_printk("Proptable vaddr is 0x%lx and pages %d\n",(vaddr_t)proptable_vaddr,NUM_PAGES(vm->arch.prop_tab.proptab_size));

                vm->arch.prop_tab.vm_proptable_vaddr = (vaddr_t)proptable_vaddr;

            } else {
                console_printk("[BAO-VGICV3] Second allocation of Proptable from cpu %d\n",cpu()->id);

                if((vaddr_t)proptable_vaddr != vm->arch.prop_tab.vm_proptable_vaddr) {
                    console_printk("[BAO-VGICV3] Modification done\n");
                    //unmap and map as RW the proptable current region in VM space

                    //unmap of proptable in Bao space
                    mem_unmap(&cpu()->as,(vaddr_t)vm->arch.prop_tab.proptab_base,vm->arch.prop_tab.proptab_size,true);


                    //map of the new proptable region in Bao Space
                    vm->arch.prop_tab.proptab_size = proptable_size;
                    vm->arch.prop_tab.proptab_base = (uint8_t *)mem_alloc_map_dev(&cpu()->as, SEC_HYP_GLOBAL, INVALID_VA,
                    proptable_pa,NUM_PAGES(vm->arch.prop_tab.proptab_size));

                    vm->arch.prop_tab.vm_proptable_vaddr = (vaddr_t)proptable_vaddr;
                } else {
                    console_printk("[BAO-VGICV3] Modification not done\n");
                }
            }

            console_printk("Final here\n");

            
            target_vcpu->arch.vgic_priv.vgicr.PROPBASER = tmp_propbaser;
            
            #if (GIC_VERSION == GICV4)
                gicr_set_vpropbaser(pgicr_id,proptable_pa,id_bits);
            #else
                gicr_set_propbaser(pgicr_id,proptable_pa,id_bits);
            #endif
            

            console_printk("VGIC3: Propbaser write from cpu %d -> 0x%x\n",cpu()->id,gicr[pgicr_id].PROPBASER);
        }
    }
}

void vgicr_emul_pendbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        if(cpu()->vcpu->vm->msi)
        {
            cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);

            if (pgicr_id != INVALID_CPUID) {
                vcpu_writereg(cpu()->vcpu, acc->reg,cpu()->vcpu->arch.vgic_priv.vgicr.PENDBASER);
            }
        } else {
            vcpu_writereg(cpu()->vcpu, acc->reg,0);
        }

    }else {
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);

        if((pgicr_id != INVALID_CPUID) && cpu()->vcpu->vm->msi && !gicr_get_en_lpis(pgicr_id))
        {
            //translate to physical
            paddr_t pend_pa=0;
            uint64_t tmp = vcpu_readreg(cpu()->vcpu, acc->reg);
            vaddr_t *pendbaser_vaddr = (vaddr_t *)(tmp & GICR_PENDBASER_PHY_ADDR_MSK);

            console_printk("[BAO-VGICV3] Pendbaser virtual is 0x%lx\n",pendbaser_vaddr);


            mem_guest_ipa_translate(pendbaser_vaddr,&pend_pa);

            console_printk("[BAO-VGICV3] Pendbaser phy is 0x%lx\n",pend_pa);

            // uint64_t pendbaser_paddr = pend_pa |
            //             (tmp & ~GICR_PENDBASER_PHY_ADDR_MSK);
            struct vcpu *target_vcpu = vm_get_vcpu(cpu()->vcpu->vm, vgicr_id);
            target_vcpu->arch.vgic_priv.vgicr.PENDBASER = tmp;

            #if (GIC_VERSION == GICV4)
                gicr_set_vpendbaser(pgicr_id,pend_pa);
            #else
                gicr_set_pendbaser(pgicr_id,pend_pa);
            #endif    
        }
    }
}

extern struct vgic_reg_handler_info isenabler_info;
extern struct vgic_reg_handler_info ispendr_info;
extern struct vgic_reg_handler_info isactiver_info;
extern struct vgic_reg_handler_info icenabler_info;
extern struct vgic_reg_handler_info icpendr_info;
extern struct vgic_reg_handler_info iactiver_info;
extern struct vgic_reg_handler_info icfgr_info;
extern struct vgic_reg_handler_info ipriorityr_info;
extern struct vgic_reg_handler_info razwi_info;

struct vgic_reg_handler_info irouter_info = {
    vgicd_emul_router_access,
    0b1100,
    VGIC_IROUTER_ID,
    offsetof(struct gicd_hw, IROUTER),
    64,
    vgic_int_get_route,
    vgic_int_set_route,
    vgic_int_set_route_hw,
};

struct vgic_reg_handler_info vgicr_ctrl_info = {
    vgicr_emul_ctrl_access,
    0b0100,
};
struct vgic_reg_handler_info vgicr_typer_info = {
    vgicr_emul_typer_access,
    0b1100,
};
struct vgic_reg_handler_info vgicr_pidr_info = {
    vgicr_emul_pidr_access,
    0b0100,
};

struct vgic_reg_handler_info vgicr_propbaser_info = {
    vgicr_emul_propbaser_access,
    0b1000,
};

struct vgic_reg_handler_info vgicr_pendbaser_info = {
    vgicr_emul_pendbaser_access,
    0b1000,
};

static inline vcpuid_t vgicr_get_id(struct emul_access* acc)
{
    return (acc->addr - cpu()->vcpu->vm->arch.vgicr_addr) / (sizeof(struct gicr_hw)-GICR_VFRAME_SIZE);
}

bool vgicr_emul_handler(struct emul_access* acc)
{
    struct vgic_reg_handler_info* handler_info = NULL;
    console_printk("Access to rdestributor with addr 0x%lx by vcpu %d -> cpu %d\n",acc->addr, vgicr_get_id(acc),cpu()->id);

    switch (GICR_REG_MASK(acc->addr)) {
        case GICR_REG_OFF(CTLR):
            console_printk("CTLR Access\n");
            handler_info = &vgicr_ctrl_info;
            break;
        case GICR_REG_OFF(ISENABLER0):
            console_printk("ISENABLER Access\n");
            handler_info = &isenabler_info;
            break;
        case GICR_REG_OFF(ISPENDR0):
            console_printk("ISPENDR Access\n");
            handler_info = &ispendr_info;
            break;
        case GICR_REG_OFF(ISACTIVER0):
            console_printk("ISACTIVER Access\n");
            handler_info = &iactiver_info;
            break;
        case GICR_REG_OFF(ICENABLER0):
            console_printk("ICENABLER Access\n");
            handler_info = &icenabler_info;
            break;
        case GICR_REG_OFF(ICPENDR0):
            console_printk("ICPENDR Access\n");
            handler_info = &icpendr_info;
            break;
        case GICR_REG_OFF(ICACTIVER0):
            console_printk("ICACTIVER Access\n");
            handler_info = &icfgr_info;
            break;
        case GICR_REG_OFF(ICFGR0):
        case GICR_REG_OFF(ICFGR1):
            console_printk("ICF Access\n");
            handler_info = &icfgr_info;
            break;
        case GICR_REG_OFF(PROPBASER):
            console_printk("PROP Access\n");
            handler_info = &vgicr_propbaser_info;
            break;
        case GICR_REG_OFF(PENDBASER):
            console_printk("PEND Access\n");
            handler_info = &vgicr_pendbaser_info;
            break;
        default: {
            console_printk("Default Access\n");
            //#if (GIC_VERSION == GICV3)
            size_t base_offset = acc->addr - cpu()->vcpu->vm->arch.vgicr_addr;
            size_t acc_offset = GICR_REG_MASK(base_offset);
            // #elif (GIC_VERSION == GICV4)
            //     size_t acc_offset = GICR_REG_MASK(acc->addr);
            // #endif
            console_printk("Base offset is 0x%x\n",acc_offset);
            if (GICR_IS_REG(TYPER, acc_offset)) {
                console_printk("Typer Access\n");
                handler_info = &vgicr_typer_info;
            } else if (GICR_IS_REG(IPRIORITYR, acc_offset)) {
                handler_info = &ipriorityr_info;
            } else if (GICR_IS_REG(ID, acc_offset)) {
                console_printk("Inside ID\n");
                handler_info = &vgicr_pidr_info;
            } else {
                handler_info = &razwi_info;
                //console_printk("GICv3: Inside razwi rEmulation in address:0x%x with base_offset=0x%x\n",acc->addr,base_offset);
            }
        }
    }

    if (vgic_check_reg_alignment(acc, handler_info)) {
        vcpuid_t vgicr_id = vgicr_get_id(acc);
        struct vcpu* vcpu =
            vgicr_id == cpu()->vcpu->id ? cpu()->vcpu : vm_get_vcpu(cpu()->vcpu->vm, vgicr_id);
        spin_lock(&vcpu->arch.vgic_priv.vgicr.lock);
            handler_info->reg_access(acc, handler_info, true, vgicr_id);
        spin_unlock(&vcpu->arch.vgic_priv.vgicr.lock);
        return true;
    } else {
        console_printk("GICv3: Not aligned rEmulation in address:0x%x\n",acc->addr);
        return false;
    }
}

/*-------------------- ITS -----------------------*/

void vgits_emul_pidr2_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        //vcpu_writereg(cpu()->vcpu, acc->reg,gits->ID[((acc->addr & 0xff) - 0xd0) / 4]);
        vcpu_writereg(cpu()->vcpu, acc->reg,0x3b);
        console_printk("VGIC3: PIDR2 read from addr -> 0x%x\n",acc->addr,gits->ID[((acc->addr & 0xff) - 0xd0) / 4]);
    }
}

void vgits_emul_ctlr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CTLR);
        console_printk("[BAO-VGICV3] CTLR read from addr 0x%x -> 0x%x\n",acc->addr,gits->CTLR);
    }else{
        gits->CTLR=vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] -------> CTLR write from addr 0x%x -> 0x%x\n",acc->addr,gits->CTLR);
    }
}

void vgits_emul_typer_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        //TODO: Get the value of PTA to now the RDbase format

        vcpu_writereg(cpu()->vcpu, acc->reg,gits->TYPER);
        console_printk("[BAO-VGICV3] TYPER read from addr 0x%x\n",acc->addr);
    }
}

void vgits_emul_cbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {  //read register

        //TO-DO Give to VM his virtual value of cbaser
        vcpu_writereg(cpu()->vcpu, acc->reg,cpu()->vcpu->vm->arch.vgits.CBASER);
        console_printk("[BAO-VGICV3] CBASER read from addr 0x%x\n",acc->addr);
    }else{
        //remove it

        /*TO-DO
        1. Verify locks and alignments
        2. Allow the modification of cmd queue base addr
        */
        struct vm* vm =  cpu()->vcpu->vm;
        uint64_t tmp_cbaser = vcpu_readreg(cpu()->vcpu, acc->reg);
        paddr_t cmdq_pa=0;
        vaddr_t *cbaser_vaddr = (vaddr_t *)(tmp_cbaser & GITS_CBASER_PHY_ADDR_MSK);
        size_t pages = (tmp_cbaser & GITS_CBASER_SIZE_MSK) + 1;

        console_printk("[BAO-VGICV3] Number of command pages:%d,vaddr:0x%lx\n",pages,cbaser_vaddr);

        mem_guest_ipa_translate(cbaser_vaddr,&cmdq_pa);

        //Unmap from the Bao space
        if(vm->arch.vgits.vgits_cmdq.base_cmdq != NULL) {
            //unmap
            mem_unmap(&cpu()->as,(vaddr_t)vm->arch.vgits.vgits_cmdq.base_cmdq,vm->arch.vgits.vgits_cmdq.page_size,true);
        }

        vm->arch.vgits.vgits_cmdq.base_cmdq = (void*)mem_alloc_map_dev(&cpu()->as, SEC_HYP_GLOBAL, INVALID_VA,
        (vaddr_t)cmdq_pa,pages);

        if(vm->arch.vgits.vgits_cmdq.base_cmdq == NULL)
            ERROR("[BAO] Command queue not mapped to Bao\n");

        vm->arch.vgits.vgits_cmdq.page_size = pages;
        vm->arch.vgits.CBASER = tmp_cbaser;

        console_printk("[BAO-VGICV3] CBASER write from addr 0x%x\n",acc->addr);
    }
}





void its_clear_cmd(struct its_cmd* curr_cmd)
{
    for(int cmd_i = 0; cmd_i < 4; cmd_i++)
        curr_cmd->cmd[cmd_i] = 0;
}

void its_build_mapc(struct its_cmd *curr_cmd,
                    struct its_cmd_desc *desc)
{
    console_printk("Build mapc command\n");

    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_MAPC_CMD);
    its_encode_target(curr_cmd,desc->its_mapc_cmd.target);
    its_encode_ic_id(curr_cmd,desc->its_mapc_cmd.ic_id);
    its_encode_valid(curr_cmd,desc->its_mapc_cmd.valid);

    console_printk("Valid is 0x%x\n",desc->its_mapc_cmd.valid);

    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
            "1- 0x%lx\n"
            "2- 0x%lx\n"    
            "3- 0x%lx\n"    
            "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);

}

void its_build_sync(struct its_cmd *curr_cmd,
                    struct its_cmd_desc *desc)
{
    console_printk("Build sync command\n");

    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_SYNC_CMD);
    its_encode_target(curr_cmd,desc->its_sync_cmd.target);

    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
            "1- 0x%lx\n"
            "2- 0x%lx\n"    
            "3- 0x%lx\n"    
            "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);

}

void its_build_mapd(struct its_cmd *curr_cmd,
                    struct its_cmd_desc *desc)
{
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_MAPD_CMD);
    its_encode_device_id(curr_cmd,desc->its_mapd_cmd.device_id);
    its_encode_size(curr_cmd,desc->its_mapd_cmd.size);
    its_encode_itt_addr(curr_cmd,desc->its_mapd_cmd.itt_addr);
    its_encode_valid(curr_cmd,desc->its_mapd_cmd.valid);
    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
        "1- 0x%lx\n"
        "2- 0x%lx\n"    
        "3- 0x%lx\n"    
        "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);
}

void its_build_inv(struct its_cmd *curr_cmd,
                    struct its_cmd_desc *desc)
{
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_INV_CMD);
    its_encode_device_id(curr_cmd,desc->its_inv_cmd.device_id);
    its_encode_event_id(curr_cmd,desc->its_inv_cmd.event_id);
    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
    "1- 0x%lx\n"
    "2- 0x%lx\n"    
    "3- 0x%lx\n"    
    "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);

}

void its_build_vmapp(struct its_cmd *curr_cmd,
                    struct its_cmd_desc *desc)
{
    console_printk("Build vmapp command\n");
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_VMAPP_CMD);
    its_encode_vpe_id(curr_cmd,desc->its_vmapp_cmd.vpe_id); 
    its_encode_valid(curr_cmd,desc->its_vmapp_cmd.valid);
    its_encode_target(curr_cmd,desc->its_vmapp_cmd.target);
    its_encode_vpt_addr(curr_cmd,desc->its_vmapp_cmd.vpt_addr);
    its_encode_vpt_size(curr_cmd,16);
    // console_printk("[BAO-VGICv3] ID is 0x%x\n",ITS_VMAPP_CMD);
    // console_printk("[BAO-VGICv3] VPE ID is 0x%x\n",desc->its_vmapp_cmd.vpe_id);
    // console_printk("[BAO-VGICv3] Valid is 0x%x\n",desc->its_vmapp_cmd.target);
    // console_printk("[BAO-VGICv3] Target is 0x%x\n",desc->its_vmapp_cmd.target);
    // console_printk("[BAO-VGICv3] VPT_addr is 0x%lx\n",desc->its_vmapp_cmd.vpt_addr);
    // console_printk("[BAO-VGICv3] VPT_SZ is 0x%x\n",16);
    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
        "1- 0x%lx\n"
        "2- 0x%lx\n"    
        "3- 0x%lx\n"    
        "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);
}

void its_build_vsync(struct its_cmd* curr_cmd, 
                struct its_cmd_desc *desc)
{
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_VSYNC_CMD);
    its_encode_vpe_id(curr_cmd,desc->its_vsync_cmd.vpe_id);
}

void its_build_vinvall(struct its_cmd* curr_cmd, 
                struct its_cmd_desc *desc)
{
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_VINVALL_CMD);
    its_encode_vpe_id(curr_cmd,desc->its_vinvall_cmd.vpe_id);
}

void its_build_vmapti(struct its_cmd* curr_cmd, 
                struct its_cmd_desc *desc)
{
    its_clear_cmd(curr_cmd);
    its_encode_cmd(curr_cmd,ITS_VMAPTI_CMD);
    its_encode_vpe_id(curr_cmd,desc->its_vmapti_cmd.vpe_id);
    its_encode_device_id(curr_cmd,desc->its_vmapti_cmd.device_id);
    its_encode_event_id(curr_cmd,desc->its_vmapti_cmd.event_id);
    // if()
    //     its_encode_db_id();
    // else
    its_encode_db_id(curr_cmd,desc->its_vmapti_cmd.db_id);

    its_encode_virt_id(curr_cmd,desc->its_vmapti_cmd.virt_id);

    console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
        "1- 0x%lx\n"
        "2- 0x%lx\n"    
        "3- 0x%lx\n"    
        "4- 0x%lx\n\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);
}

void its_copy_to_cmdq(struct its_cmd *dest_cmd,
                    struct its_cmd *src_cmd)
{
    for(int i = 0; i < 4; i++)
        dest_cmd->cmd[i] = src_cmd->cmd[i];
}

void its_translate_cmd(struct its_cmd *dest_cmd,
                    struct its_cmd *src_cmd)
{
    vcpuid_t vrdbase;
    cpuid_t pgicr_id;

    //TODO LOCK mechanism
    struct its_cmd_desc desc;

    switch (GITS_CMD_MASK(src_cmd)) {
    case ITS_MAPC_CMD:
        
        vrdbase = bit64_extract(src_cmd->cmd[2],ITS_CMD_RDBASE_OFF,ITS_CMD_RDBASE_LEN);
        pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vrdbase); //ERROR verification

        desc.its_mapc_cmd.target = pgicr_id;
        desc.its_mapc_cmd.ic_id = bit64_extract(src_cmd->cmd[2],0,12);   //See imple defined sizes
        desc.its_mapc_cmd.valid = !!bit64_extract(src_cmd->cmd[2],63,1);

        its_build_mapc(dest_cmd,&desc);
        console_printk("BAO-VGICV3: MAPC cmd received\n");
        break;
    case ITS_SYNC_CMD:
        vrdbase = bit64_extract(src_cmd->cmd[2],ITS_CMD_RDBASE_OFF,ITS_CMD_RDBASE_LEN);
        pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vrdbase); //ERROR verification

        desc.its_sync_cmd.target = pgicr_id; //store the vpe info
        console_printk("Value of sync target is 0x%x and virtual is 0x%x and cpu is %d\n",pgicr_id,vrdbase,cpu()->id);
        its_build_sync(dest_cmd,&desc);
        console_printk("BAO-VGICV3: SYNC cmd received\n");
        break;
    case ITS_MAPD_CMD:
        paddr_t itt_paddr;
        vaddr_t *itt_vaddr = (vaddr_t *)bit64_extract(src_cmd->cmd[2],0,52);
        mem_guest_ipa_translate(itt_vaddr,&itt_paddr);

        desc.its_mapd_cmd.device_id = bit64_extract(src_cmd->cmd[0],32,32);
        desc.its_mapd_cmd.size = bit64_extract(src_cmd->cmd[1],0,5);
        desc.its_mapd_cmd.itt_addr = itt_paddr;
        desc.its_mapd_cmd.valid = !!bit64_extract(src_cmd->cmd[2],63,1);

        console_printk("[BAO-VGICv3] In MAPD translation: vaddr= 0x%lx and paddr = 0x%lx\n",itt_vaddr,itt_paddr);

        its_build_mapd(dest_cmd,&desc);
        break;
    default:
        its_copy_to_cmdq(dest_cmd,src_cmd);
        console_printk("BAO-VGICV3: Other cmd received -> 0x%x\n",GITS_CMD_MASK(src_cmd));        
    }
}

void its_translate_vcmd(struct its_cmd *dest_cmd,
                    struct its_cmd *src_cmd)
{
    vcpuid_t vrdbase;
    cpuid_t pgicr_id;
    struct its_cmd_desc desc;

    switch (GITS_CMD_MASK(src_cmd)) {
        case ITS_MAPC_CMD:

            paddr_t pa_vpt;
            struct vcpu *target_vcpu;

            vrdbase = bit64_extract(src_cmd->cmd[2],ITS_CMD_RDBASE_OFF,ITS_CMD_RDBASE_LEN);
            pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vrdbase); //ERROR verification
            target_vcpu = vm_get_vcpu(cpu()->vcpu->vm, vrdbase);
            mem_guest_ipa_translate((vaddr_t*)(target_vcpu->arch.vgic_priv.vgicr.PENDBASER & GICR_PENDBASER_PHY_ADDR_MSK),&pa_vpt);
            console_printk("[BAO-VGICV3] Pendbaser phy is 0x%lx\n",pa_vpt);

            //with some VM requires other logic
            desc.its_vmapp_cmd.vpe_id = bit64_extract(src_cmd->cmd[2],0,16);   //See imple defined sizes
            desc.its_vmapp_cmd.target = pgicr_id;
            desc.its_vmapp_cmd.vpt_addr = pa_vpt;   //review
            desc.its_vmapp_cmd.vpt_size = bit64_extract(src_cmd->cmd[3],0,5);
            desc.its_vmapp_cmd.valid = !!bit64_extract(src_cmd->cmd[2],63,1);
            
            its_build_vmapp(dest_cmd,&desc);

            console_printk("BAO-VGICV3: MAPC cmd received\n");
            break;
        case ITS_INVALL_CMD:
            // TODO - vpe_id receives the same value as the collection
            desc.its_vinvall_cmd.vpe_id = bit64_extract(src_cmd->cmd[2],0,16); //store the vpe info
            its_build_vinvall(dest_cmd,&desc);
            console_printk("BAO-VGICV3: INVALL cmd received\n");
            break;
        case ITS_MAPTI_CMD:
            desc.its_vmapti_cmd.device_id = bit64_extract(src_cmd->cmd[0],32,32);
            desc.its_vmapti_cmd.event_id = bit64_extract(src_cmd->cmd[1],0,32);
            desc.its_vmapti_cmd.virt_id = bit64_extract(src_cmd->cmd[1],32,32);
            desc.its_vmapti_cmd.vpe_id = bit64_extract(src_cmd->cmd[2],0,16); //store the vpe info
            desc.its_vmapti_cmd.db_id = desc.its_vmapti_cmd.virt_id;

            its_build_vmapti(dest_cmd,&desc);
            console_printk("BAO-VGICV3: MAPTI cmd received\n");
            break;
        case ITS_SYNC_CMD:
            desc.its_vsync_cmd.vpe_id = 0; //store the vpe info
            its_build_vsync(dest_cmd,&desc);
            console_printk("BAO-VGICV3: SYNC cmd received\n");
            break;
        case ITS_INV_CMD:
            console_printk("BAO-VGICV3: MAPI cmd received\n");
            desc.its_inv_cmd.device_id = bit64_extract(src_cmd->cmd[0],32,32);
            desc.its_inv_cmd.event_id = bit64_extract(src_cmd->cmd[1],0,32);

            its_build_inv(dest_cmd,&desc);
            break;
        case ITS_MAPD_CMD:
            paddr_t itt_paddr;
            vaddr_t *itt_vaddr = (vaddr_t *)bit64_extract(src_cmd->cmd[2],0,52);
            mem_guest_ipa_translate(itt_vaddr,&itt_paddr);

            console_printk("[BAO-VGICv3] ITT paddr is 0x%lx and vaddr is 0x%lx\n",itt_vaddr,itt_paddr);

            desc.its_mapd_cmd.device_id = bit64_extract(src_cmd->cmd[0],32,32);
            desc.its_mapd_cmd.size = bit64_extract(src_cmd->cmd[1],0,5);
            desc.its_mapd_cmd.itt_addr = itt_paddr;
            desc.its_mapd_cmd.valid = !!bit64_extract(src_cmd->cmd[2],63,1);

            its_build_mapd(dest_cmd,&desc);
            console_printk("BAO-VGICV3: MAPD cmd received\n");
            break;
        default:
            console_printk("BAO-VGICV3: Other cmd received -> 0x%x\n",GITS_CMD_MASK(src_cmd));        
    }
}

void vgits_emul_cwriter_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id)
{
    uint64_t prev_cwriter, curr_cwriter, cmd_off;
    size_t n_cmd;
    struct its_cmd *vm_cmd, *its_cmd;


    if (!acc->write) {
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CWRITER);
        console_printk("[BAO-VGICV3] CBASER read from addr 0x%x in cpu %d\n",acc->addr,cpu()->id);
    }else{

        //Number of commands to translate
        prev_cwriter = gits->CWRITER;
        cmd_off =  prev_cwriter/0x20;
        curr_cwriter = vcpu_readreg(cpu()->vcpu, acc->reg);
        n_cmd = (prev_cwriter > curr_cwriter)? (((4096 * (ITS_CMD_QUEUE_N_PAGE + 1))- prev_cwriter) + curr_cwriter)/0x20 : (curr_cwriter - prev_cwriter)/0x20;

        vm_cmd = cpu()->vcpu->vm->arch.vgits.vgits_cmdq.base_cmdq + cmd_off;
        its_cmd = its_cmd_queue + cmd_off;

        console_printk("Value of its cmd is 0x%lx\n",its_cmd);
        
        while(n_cmd-- > 0)
        {
            #if (GIC_VERSION == GICV4)
                its_translate_vcmd(its_cmd,vm_cmd);
            #else
                its_translate_cmd(its_cmd,vm_cmd);
            #endif
            vm_cmd++;
            its_cmd++;
        }
        
        gits->CWRITER = curr_cwriter;
        console_printk("[BAO-VGICV3] CWRITER write from addr 0x%x with the offset 0x%lx\n",acc->addr,gits->CWRITER);
    }
}

void vgits_emul_creadr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {  //read only
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CREADR);
        console_printk("[BAO-VGICV3] CREADR read from addr 0x%x with the offset 0x%x\n",acc->addr,bit64_extract(gits->CREADR,5,15));

    }
}

void vgits_emul_baser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    size_t index = (GITS_REG_MASK(acc->addr) - GITS_REG_OFF(BASER)) >> 3;
        /*
    1. Get the baser index from acc->addr
    2. 
    3. write in the vcpu register

    ---
    Mask the addr to get the index value
    0x8080100 - 0 - 00000000
    0x8080108 - 1 - 00001000
    0x8080110 - 2 - 00010000
    0x8080118 - 3 - 00011000
    0x8080120 - 4 - 00100000
    */
    if (!acc->write) { //read baser
        vcpu_writereg(cpu()->vcpu, acc->reg,(cpu()->vcpu->vm->arch.vgits.BASER[index]));
        console_printk("[BAO-VGICV3] BASER read from addr 0x%x, index %d -> 0x%lx\n",acc->addr,index,cpu()->vcpu->vm->arch.vgits.BASER[index]);
    }else{
        
        uint64_t tmp = vcpu_readreg(cpu()->vcpu, acc->reg);
        size_t type = bit64_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN);
        console_printk("[BAO-VGICV3] -----> Baser tmp is 0x%lx\n",tmp);
        console_printk("[BAO-VGICV3] Baser real is 0x%lx\n",gits->BASER[index]);


        if((tmp & GITS_BASER_VALID_BIT) &&  type == 0x1) //multiprocessor works?
        {
            
            //translate to physical
            paddr_t baser_pa = 0;
            vaddr_t *baser_vaddr = (vaddr_t *)(tmp & GITS_BASER_PHY_ADDR_MSK);
 
            console_printk("[BAO-VGICV3] Baser virtual is 0x%lx\n",baser_vaddr);


            mem_guest_ipa_translate(baser_vaddr,&baser_pa); //maybe has some implications

            console_printk("[BAO-VGICV3] Baser phy is 0x%lx\n",baser_pa);
            //need to alloc the coll table? If not, what happen?

            uint64_t baser_paddr = baser_pa |
                        (tmp & ~GITS_BASER_PHY_ADDR_MSK);
            
            gits->BASER[index]= baser_paddr;
        }
        console_printk("Value of gits Baser with type %d is 0x%x\n",bit64_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN),
                gits->BASER[index]);

        cpu()->vcpu->vm->arch.vgits.BASER[index] = (cpu()->vcpu->vm->arch.vgits.BASER[index] & GITS_BASER_RO_MASK) | (tmp & ~GITS_BASER_RO_MASK);

        console_printk("[BAO-VGICV3] BASER write from addr 0x%x, index %d with value 0x%lx\n",acc->addr,index,cpu()->vcpu->vm->arch.vgits.BASER[index]);
    }
}

void vgits_emul_translater_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if(acc->write){
        gits->TRANSLATER=vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] TRANSLATER write from addr 0x%x\n",acc->addr);
    }
}

void vgits_emul_iidr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) { //read only
        console_printk("[BAO-VGICV3] CTRANSLATER write from addr 0x%x\n",acc->addr);
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->IIDR);  //Only gicv3 is visible for the guest

        console_printk("VGIC3: PIDR2 read from addr 0x%x-> 0x%x\n",acc->addr,gits->ID[((acc->addr & 0xff) - 0xd0) / 4]);
    }
}

struct vgic_reg_handler_info vgits_pidr2_info = {
    vgits_emul_pidr2_access,
    0b0100,
};

struct vgic_reg_handler_info vgits_ctlr_access = {
    vgits_emul_ctlr_access,
    0b0100,
};

struct vgic_reg_handler_info vgits_typer_access = {
    vgits_emul_typer_access,
    0b1000,
};
struct vgic_reg_handler_info vgits_cbaser_access = {
    vgits_emul_cbaser_access,
    0b1000,
};

struct vgic_reg_handler_info vgits_cwriter_access = {
    vgits_emul_cwriter_access,
    0b1100,
};

struct vgic_reg_handler_info vgits_baser_access = {
    vgits_emul_baser_access,
    0b1000,
};
struct vgic_reg_handler_info vgits_translater_access = {
    vgits_emul_translater_access,
    0b0100,
};


struct vgic_reg_handler_info vgits_creadr_access = {
    vgits_emul_creadr_access,
    0b0100,
};

struct vgic_reg_handler_info vgits_iidr_access = {
    vgits_emul_iidr_access,
    0b0100,
};


/* ITS emul handler */
bool vgits_emul_handler(struct emul_access* acc){

    struct vgic_reg_handler_info* handler_info = NULL;
    struct vm *vm = cpu()->vcpu->vm;

     switch (GITS_REG_MASK(acc->addr)) {
        case GITS_REG_OFF(CTLR):
            //console_printk("[BAO-VGICV3] Inside CTLR ITS emul in address:0x%x\n",acc->addr);
            handler_info = &vgits_ctlr_access;
            break;
        case GITS_REG_OFF(IIDR):
            console_printk("[BAO-VGICV3] Inside IIDR ITS emul in address:0x%x\n",acc->addr);
            handler_info = &vgits_iidr_access;
            break;
        case GITS_REG_OFF(TYPER):
            //console_printk("[BAO-VGICV3] Inside TYPER ITS emul in address:0x%x\n",acc->addr);
            handler_info = &vgits_typer_access;
        break;
        case GITS_REG_OFF(CBASER):
            handler_info = &vgits_cbaser_access;
        break;
        case GITS_REG_OFF(CWRITER):
            handler_info = &vgits_cwriter_access;
            break;
        case GITS_REG_OFF(CREADR):
            handler_info = &vgits_creadr_access;
            break;
        case GITS_REG_OFF(TRANSLATER):
            handler_info = &vgits_translater_access;
            break;
        default: {
            size_t base_offset = acc->addr - cpu()->vcpu->vm->arch.vgicr_addr;
            size_t acc_offset = GITS_REG_MASK(base_offset);
            if (GITS_IS_REG(BASER, acc_offset)) {
                handler_info = &vgits_baser_access;
                //console_printk("[BAO-VGICV3] Inside default ITS emul in address:0x%x\n",acc->addr);
            }  else if (GITS_IS_REG(ID, acc_offset)) {
                handler_info = &vgits_pidr2_info;
            } else {
                handler_info = &razwi_info;
                console_printk("GICv3: Inside razwi rEmulation in address:0x%x with base_offset=0x%x\n",acc->addr,base_offset);
            }             
        }
    }

    if (vgic_check_reg_alignment(acc, handler_info)) {
        spin_lock(&vm->arch.vgits.lock);
            handler_info->reg_access(acc, handler_info, false, 0);
        spin_unlock(&vm->arch.vgits.lock);

        return true;
    } else {
        return false;
    }
}

bool vgic_icc_sgir_handler(struct emul_access* acc)
{
    if (acc->write) {
        uint64_t sgir = vcpu_readreg(cpu()->vcpu, acc->reg);
        if (acc->multi_reg) {
            uint64_t sgir_high = vcpu_readreg(cpu()->vcpu, acc->reg_high);
            sgir |= (sgir_high << 32);
        }
        irqid_t int_id = ICC_SGIR_SGIINTID(sgir);
        cpumap_t trgtlist;
        if (sgir & ICC_SGIR_IRM_BIT) {
            trgtlist = cpu()->vcpu->vm->cpus & ~(1U << cpu()->vcpu->phys_id);
        } else {
            /**
             * TODO: we are assuming the vm has a single cluster. Change this when adding virtual
             * cluster support.
             */
            trgtlist = vm_translate_to_pcpu_mask(cpu()->vcpu->vm, ICC_SGIR_TRGLSTFLT(sgir),
                cpu()->vcpu->vm->cpu_num);
        }
        vgic_send_sgi_msg(cpu()->vcpu, trgtlist, int_id);
    }

    return true;
}

bool vgic_icc_sre_handler(struct emul_access* acc)
{
    if (!acc->write) {
        vcpu_writereg(cpu()->vcpu, acc->reg, 0x1);
    }
    return true;
}

void vgic_init(struct vm* vm, const struct vgic_dscrp* vgic_dscrp)
{
    vm->arch.vgicr_addr = vgic_dscrp->gicr_addr;
    vm->arch.vgicd.CTLR = 0;
    vm->msi = vgic_dscrp->msi;
    size_t vtyper_itln = vgic_get_itln(vgic_dscrp);
    vm->arch.vgicd.int_num = 32 * (vtyper_itln + 1);
    vm->arch.vgicd.TYPER = ((vtyper_itln << GICD_TYPER_ITLN_OFF) & GICD_TYPER_ITLN_MSK) |
        (((vm->cpu_num - 1) << GICD_TYPER_CPUNUM_OFF) & GICD_TYPER_CPUNUM_MSK) |
        ((((vm->msi ? 16 : 10) - 1) << GICD_TYPER_IDBITS_OFF) & GICD_TYPER_IDBITS_MSK) |
        (vm->msi? GICD_TYPER_LPIS_BIT : 0); //LPI support
    vm->arch.vgicd.IIDR = gicd->IIDR;

    console_printk("[BAO-VGICV3] Value of msi is %d\n",vm->msi);

    size_t vgic_int_size = vm->arch.vgicd.int_num * sizeof(struct vgic_int);
    vm->arch.vgicd.interrupts = mem_alloc_page(NUM_PAGES(vgic_int_size), SEC_HYP_VM, false);
    if (vm->arch.vgicd.interrupts == NULL) {
        ERROR("failed to alloc vgic");
    }

    for (size_t i = 0; i < vm->arch.vgicd.int_num; i++) {
        vm->arch.vgicd.interrupts[i].owner = NULL;
        vm->arch.vgicd.interrupts[i].lock = SPINLOCK_INITVAL;
        vm->arch.vgicd.interrupts[i].id = i + GIC_CPU_PRIV;
        vm->arch.vgicd.interrupts[i].state = INV;
        vm->arch.vgicd.interrupts[i].prio = GIC_LOWEST_PRIO;
        vm->arch.vgicd.interrupts[i].cfg = 0;
        vm->arch.vgicd.interrupts[i].route = GICD_IROUTER_INV;
        vm->arch.vgicd.interrupts[i].phys.route = GICD_IROUTER_INV;
        vm->arch.vgicd.interrupts[i].hw = false;
        vm->arch.vgicd.interrupts[i].in_lr = false;
        vm->arch.vgicd.interrupts[i].enabled = false;
    }

    vm->arch.vgicd_emul = (struct emul_mem){ .va_base = vgic_dscrp->gicd_addr,
        .size = ALIGN(sizeof(struct gicd_hw), PAGE_SIZE),
        .handler = vgicd_emul_handler };
    vm_emul_add_mem(vm, &vm->arch.vgicd_emul);

    /* Initialize virtual its registers*/
    for (vcpuid_t vcpuid = 0; vcpuid < vm->cpu_num; vcpuid++) {
        struct vcpu* vcpu = vm_get_vcpu(vm, vcpuid);
        uint64_t typer = (uint64_t)vcpu->id << GICR_TYPER_PRCNUM_OFF;
        typer |= ((uint64_t)vcpu->arch.vmpidr & MPIDR_AFF_MSK) << GICR_TYPER_AFFVAL_OFF;
        typer |= !!(vcpu->id == vcpu->vm->cpu_num - 1) << GICR_TYPER_LAST_OFF;
        typer |= (vm->msi ? 0x1 : 0x0);   /*enable PLPIS*/
        vcpu->arch.vgic_priv.vgicr.TYPER = typer;
        vcpu->arch.vgic_priv.vgicr.IIDR = gicr[cpu()->id].IIDR;
        console_printk("Typer init for vcpu %d is 0x%x\n",vcpuid,typer);
    }
    /*GIC version of cpu interface*/

    //This must be modified, in gicv4 only the first 2 frames can be emulated.
    console_printk("Size is 0x%x and %d and version is %d\n",sizeof(struct gicr_hw),GICR_VFRAME_SIZE, GIC_VERSION);
    vm->arch.vgicr_emul = (struct emul_mem){ .va_base = vgic_dscrp->gicr_addr,
        .size = ALIGN(sizeof(struct gicr_hw) - GICR_VFRAME_SIZE, PAGE_SIZE) * vm->cpu_num,
        .handler = vgicr_emul_handler };
    vm_emul_add_mem(vm, &vm->arch.vgicr_emul);
    console_printk("SIZE is %d\n\n",vm->arch.vgicr_emul.size);

    /*ITS emul */
    if(vm->msi){
        for (size_t index = 0; index < GIC_MAX_TTD; index++) {
            //TODO -  Verify if flat tables are supported and manage Indirect bit
            if(bit64_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == GITS_BASER_VPET_TYPE)
            {
                console_printk("[BAO-VGICV3] VPE table found\n");
                vm->arch.vgits.BASER[index]= 0;
            } else {
                vm->arch.vgits.BASER[index]= (gits->BASER[index] & GITS_BASER_RO_MASK);
            }
        }

        // uint64_t gits_typer = 1ULL << GITS_TYPER_PHY_OFF;
        // gits_typer |= 

        //TODO Create typer and pidr2 virtual registers to each VM
        vm->arch.vgits.TYPER = gits->TYPER & ~GITS_TYPER_VIRT_MSK;
        console_printk("[BAO-VGICV3] Value of gits ptyper is 0x%lx\n",gits->TYPER);
        console_printk("[BAO-VGICV3] Value of gits vtyper is 0x%lx\n",vm->arch.vgits.TYPER);


        vm->arch.vgits_emul = (struct emul_mem){ .va_base = vgic_dscrp->gits_addr,
            .size = ALIGN(sizeof(struct gits_hw), PAGE_SIZE),
            .handler = vgits_emul_handler };
        vm_emul_add_mem(vm, &vm->arch.vgits_emul);

    }


    vm->arch.icc_sgir_emul = (struct emul_reg){ .addr = SYSREG_ENC_ADDR(3, 0, 12, 11, 5),
        .handler = vgic_icc_sgir_handler };
    vm_emul_add_reg(vm, &vm->arch.icc_sgir_emul);

    vm->arch.icc_sre_emul = (struct emul_reg){ .addr = SYSREG_ENC_ADDR(3, 0, 12, 12, 5),
        .handler = vgic_icc_sre_handler };
    vm_emul_add_reg(vm, &vm->arch.icc_sre_emul);

    list_init(&vm->arch.vgic_spilled);
    vm->arch.vgic_spilled_lock = SPINLOCK_INITVAL;
}

void vgic_cpu_init(struct vcpu* vcpu)
{
    for (size_t i = 0; i < GIC_CPU_PRIV; i++) {
        vcpu->arch.vgic_priv.interrupts[i].owner = NULL;
        vcpu->arch.vgic_priv.interrupts[i].lock = SPINLOCK_INITVAL;
        vcpu->arch.vgic_priv.interrupts[i].id = i;
        vcpu->arch.vgic_priv.interrupts[i].state = INV;
        vcpu->arch.vgic_priv.interrupts[i].prio = GIC_LOWEST_PRIO;
        vcpu->arch.vgic_priv.interrupts[i].cfg = 0;
        vcpu->arch.vgic_priv.interrupts[i].route = GICD_IROUTER_INV;
        vcpu->arch.vgic_priv.interrupts[i].phys.redist = vcpu->phys_id;
        vcpu->arch.vgic_priv.interrupts[i].hw = false;
        vcpu->arch.vgic_priv.interrupts[i].in_lr = false;
        vcpu->arch.vgic_priv.interrupts[i].enabled = false;
    }

    for (size_t i = 0; i < GIC_MAX_SGIS; i++) {
        vcpu->arch.vgic_priv.interrupts[i].cfg = 0b10;
    }

    list_init(&vcpu->arch.vgic_spilled);
}

static inline uint8_t vgic_get_prio_lpi(struct vm *vm, irqid_t id){
    return vm->arch.prop_tab.proptab_base[id - GIC_FIRST_LPIS] & LPI_CONFIG_PRIO_MSK;
}

static inline uint8_t vgic_get_en_lpi(struct vm *vm, irqid_t id){
    return vm->arch.prop_tab.proptab_base[id - GIC_FIRST_LPIS] & LPI_CONFIG_EN_MSK;
}

struct vgic_int vgic_tmp_lpi(struct vcpu* vcpu, irqid_t id){
    struct vgic_int interrupt;

    interrupt.lock = SPINLOCK_INITVAL;
    interrupt.owner = vcpu;
    interrupt.state = PEND;
    interrupt.in_lr = false;
    interrupt.id = id;
    interrupt.prio = vgic_get_prio_lpi(vcpu->vm,id);
    interrupt.cfg = 0;
    interrupt.phys.redist = vcpu->phys_id;
    interrupt.hw = false;
    interrupt.enabled = vgic_get_en_lpi(vcpu->vm,id);

    console_printk("LPI interrupt %d has priority 0x%x and en is %d\n",interrupt.id,interrupt.prio,interrupt.enabled);

    return interrupt;
}

void vgic_inject_msi(struct vcpu* vcpu, irqid_t id){

    struct vgic_int tmp_interrupt = vgic_tmp_lpi(vcpu,id);

    vgic_add_lr(vcpu,&tmp_interrupt);
}
