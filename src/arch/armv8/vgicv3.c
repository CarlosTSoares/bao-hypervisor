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
#define GICR_REG_MASK(ADDR) ((ADDR) & 0x1ffff)
#define GICD_REG_MASK(ADDR) ((ADDR) & (GIC_VERSION == GICV2 ? 0xfffUL : 0xffffUL))


#define GITS_IS_REG(REG, offset)                    \
    (((offset) >= offsetof(struct gits_hw, REG)) && \
        (offset) < (offsetof(struct gits_hw, REG) + sizeof(gits->REG)))
#define GITS_REG_OFF(REG)   (offsetof(struct gits_hw, REG) & 0x1ffff)
#define GITS_REG_MASK(ADDR) ((ADDR) & 0x1ffff)



#define GICD_TYPER_LPIS 0x20000

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
    uint32_t val = 0;
    val |= (gicr[cpu()->id].CTLR & 0x1);

    if (!acc->write) {
        vcpu_writereg(cpu()->vcpu, acc->reg, val);
        console_printk("VGICv3: rCTRL value readed: 0x%x\n",val);
    } else {
        gicr[cpu()->id].CTLR |= (vcpu_readreg(cpu()->vcpu, acc->reg)&0x1);
        console_printk("VGICv3: rCTRL value set to: 0x%x\n",gicr[cpu()->id].CTLR);
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
        unsigned long val = 0;
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
        if (pgicr_id != INVALID_CPUID) {
            val = gicr[pgicr_id].ID[((acc->addr & 0xff) - 0xd0) / 4];
        }
        vcpu_writereg(cpu()->vcpu, acc->reg, val);
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
    if (!acc->write) {
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


void vgicr_emul_propbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) { // && rCTRL.enableLPIS = 0
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
        console_printk("Redistributor vID is %d and pID is %d\n",vgicr_id,pgicr_id);
        if (pgicr_id != INVALID_CPUID) {
            vcpu_writereg(cpu()->vcpu, acc->reg,gicr[pgicr_id].PROPBASER);
            console_printk("VGIC3: Propbaser read from cpu %d -> 0x%x\n",cpu()->id,gicr[pgicr_id].PROPBASER);
        }

        //To-do The gicr_id need to be translated to the physical id
    }else{
        //if(cpu()->vcpu->vm->config.platform.msi)
        //To-Do msi condition and get physical translation
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
        console_printk("Redistributor vID is %d and pID is %d\n",vgicr_id,pgicr_id);
        if (pgicr_id != INVALID_CPUID) {
            gicr[pgicr_id].PROPBASER = vcpu_readreg(cpu()->vcpu, acc->reg);
            console_printk("VGIC3: Propbaser write from cpu %d -> 0x%x\n",cpu()->id,gicr[pgicr_id].PROPBASER);
        }
    }
}

void vgicr_emul_pendbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        /*platform.msi == true ? vcpu_writereg(cpu()->vcpu, acc->reg,gicr[cpu()->id].PENDBASER) :
        vcpu_writereg(cpu()->vcpu, acc->reg,0);*/

        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);

        if (pgicr_id != INVALID_CPUID) {
            vcpu_writereg(cpu()->vcpu, acc->reg,gicr[pgicr_id].PENDBASER);
        }
        
        //console_printk("VGIC3: Pendbaser read from cpu %d -> 0x%x\n",cpu()->id,gicr[vgicr_id].PENDBASER);
    }else {
        //if(cpu()->vcpu->vm->config.platform.msi)
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);

        if (pgicr_id != INVALID_CPUID) {
            gicr[pgicr_id].PENDBASER = vcpu_readreg(cpu()->vcpu, acc->reg);
        }
        //console_printk("VGIC3: Pendbaser write from cpu %d -> 0x%x\n",cpu()->id,gicr[vgicr_id].PENDBASER);
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
    return (acc->addr - cpu()->vcpu->vm->arch.vgicr_addr) / sizeof(struct gicr_hw);
}

bool vgicr_emul_handler(struct emul_access* acc)
{
    struct vgic_reg_handler_info* handler_info = NULL;
    switch (GICR_REG_MASK(acc->addr)) {
        case GICR_REG_OFF(CTLR):
            handler_info = &vgicr_ctrl_info;
            break;
        case GICR_REG_OFF(ISENABLER0):
            handler_info = &isenabler_info;
            break;
        case GICR_REG_OFF(ISPENDR0):
            handler_info = &ispendr_info;
            break;
        case GICR_REG_OFF(ISACTIVER0):
            handler_info = &iactiver_info;
            break;
        case GICR_REG_OFF(ICENABLER0):
            handler_info = &icenabler_info;
            break;
        case GICR_REG_OFF(ICPENDR0):
            handler_info = &icpendr_info;
            break;
        case GICR_REG_OFF(ICACTIVER0):
            handler_info = &icfgr_info;
            break;
        case GICR_REG_OFF(ICFGR0):
        case GICR_REG_OFF(ICFGR1):
            handler_info = &icfgr_info;
            break;
        case GICR_REG_OFF(PROPBASER):
            handler_info = &vgicr_propbaser_info;
            //console_printk("[BAO] Address 0x%x access the propbaser handler\n",acc->addr);
            break;
        case GICR_REG_OFF(PENDBASER):
            handler_info = &vgicr_pendbaser_info;
            break;
        default: {
            size_t base_offset = acc->addr - cpu()->vcpu->vm->arch.vgicr_addr;
            size_t acc_offset = GICR_REG_MASK(base_offset);
            if (GICR_IS_REG(TYPER, acc_offset)) {
                handler_info = &vgicr_typer_info;
            } else if (GICR_IS_REG(IPRIORITYR, acc_offset)) {
                handler_info = &ipriorityr_info;
            } else if (GICR_IS_REG(ID, acc_offset)) {
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
/* Propbaser and Pendbaser emulation*/

void vgits_emul_pidr2_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) { // && rCTRL.enableLPIS = 0 //read only
        // TO-DO read the value from the physical addr

        // unsigned long val = 0;
        // cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vgicr_id);
        // if (pgicr_id != INVALID_CPUID) {
        //     val = gicr[pgicr_id].ID[((acc->addr & 0xff) - 0xd0) / 4];
        // vcpu_writereg(cpu()->vcpu, acc->reg, val);

        vcpu_writereg(cpu()->vcpu, acc->reg,gits->ID[((acc->addr & 0xff) - 0xd0) / 4]); //??
        // console_printk("[BAO-VGIC3] ID index is 0x%x\n",((acc->addr & 0xff) - 0xd0) / 4);
        // console_printk("[BAO-VGIC3] PIDR2 read from cpu %d -> 0 0x%x\n",cpu()->id,gits->ID[0]);
        // console_printk("[BAO-VGIC3] PIDR2 read from cpu %d -> 1 0x%x\n",cpu()->id,gits->ID[1]);
        // console_printk("[BAO-VGIC3] PIDR2 read from cpu %d -> 2 0x%x\n",cpu()->id,gits->ID[2]);
        // console_printk("[BAO-VGIC3] PIDR2 read from cpu %d -> 3 0x%x\n",cpu()->id,gits->ID[3]);
        // console_printk("VGIC3: PIDR2 read from cpu %d -> 4 0x%x\n",cpu()->id,gits->ID[4]);
        // console_printk("VGIC3: PIDR2 read from cpu %d -> 5 0x%x\n",cpu()->id,gits->ID[5]);
        console_printk("VGIC3: PIDR2 read from addr -> 0x%x\n",acc->addr,gits->ID[((acc->addr & 0xff) - 0xd0) / 4]);
    }else{
        //if(cpu()->vcpu->vm->config.platform.msi)
        //To-Do msi condition and get physical translation
        //gicr[vgicr_id].PROPBASER = vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] PIDR2 write from addr 0x%x\n",acc->addr);
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
        console_printk("[BAO-VGICV3] CTLR write from addr 0x%x -> 0x%x\n",acc->addr,gits->CTLR);
    }
}

void vgits_emul_typer_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->TYPER);
        console_printk("[BAO-VGICV3] TYPER read from addr 0x%x\n",acc->addr);
    }else{

        //console_printk("[BAO-VGICV3] TYPER write from addr 0x%x\n",acc->addr);
    }
}

void vgits_emul_cbaser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {  //read register

        //TO-DO Give to VM his virtual value of cbaser
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CBASER);
        console_printk("[BAO-VGICV3] CBASER read from addr 0x%x\n",acc->addr);
    }else{
        //remove it

        /*TO-DO
        1. Verify locks and alignments
        */
        //paddr_t cmdq_pa=0;
        size_t tmp_cbaser = vcpu_readreg(cpu()->vcpu, acc->reg);
        gits->CBASER=tmp_cbaser;
        vaddr_t cbaser_vaddr = tmp_cbaser & 0xFFFFFFFFFF000;//use macro
        size_t pages = (tmp_cbaser & 0xff)+ 1;  //number of 4k pages
        size_t size = pages*0x1000;

        console_printk("[BAO-VGICV3] Number of command pages:%d,vaddr:0x%lx,size:%d\n",pages,cbaser_vaddr,size);


        //TO-DO - Unmap only once
        //mem_unmap(&cpu()->vcpu->vm->as,(vaddr_t)cbaser_vaddr,pages,true);
        //cbaser_vaddr = 0x83000000;
        console_printk("[BAO-MEM] Cpu as type is %d\n",cpu()->as.type);
        console_printk("[BAO-MEM] Vm as type is %d\n",cpu()->vcpu->vm->as.type);

        //cbaser_vaddr=0x09000000;

        // bool val = mem_translate(&cpu()->as,cbaser_vaddr,&cmdq_pa);
        // if (!val)
        //     ERROR("[BAO] Physical addr of command queue is 0x%lx \n",cmdq_pa);

        // console_printk("[BAO] Physical addr of command queue is 0x%lx \n",cmdq_pa);


        //Map to the Bao space
        its_cmdq = (void*)mem_alloc_map_dev(&cpu()->as, SEC_HYP_GLOBAL, INVALID_VA,
        cbaser_vaddr,pages);

        if(its_cmdq == NULL)
            ERROR("[BAO] Command queue not mapped to Bao\n");

        // //Create emulated memory
        // cpu()->vcpu->vm->arch.vgits_cbaser_vaddr = cbaser_vaddr;
        
        // //Add emulated memory
        // cpu()->vcpu->vm->arch.vgits_cmdq_emul = (struct emul_mem){ .va_base = cbaser_vaddr,
        // .size = size, //TO-DO optimization
        // .handler = cmd_queue_emul_handler };

        // vm_emul_add_mem(cpu()->vcpu->vm, &cpu()->vcpu->vm->arch.vgits_cmdq_emul);


        console_printk("[BAO-VGICV3] CBASER write from addr 0x%x\n",acc->addr);
    }
}

bool cmd_is_mapc(struct its_cmd* curr_cmd){
    if(bit64_extract(curr_cmd->cmd[0],0,8)==0x9)
        return true;
    else
        return false;
}

void vgits_emul_cwriter_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {
        //translate to physical addr
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CWRITER);
        console_printk("[BAO-VGICV3] CBASER read from addr 0x%x in cpu %d\n",acc->addr,cpu()->id);
    }else{
        //Get the offset
        struct its_cmd* curr_cmd = its_cmdq + gits->CWRITER;
        console_printk("[BAO-VGICV3] Value of command pointed by cwriter in cpu %d is\n"
                    "1- 0x%lx\n"
                    "2- 0x%lx\n"    
                    "3- 0x%lx\n"    
                    "4- 0x%lx\n",cpu()->id,curr_cmd->cmd[0],curr_cmd->cmd[1],curr_cmd->cmd[2],curr_cmd->cmd[3]);

        
        //Is mapc command?
        if(cmd_is_mapc(curr_cmd)){
            //Get the rdbase
            vcpuid_t vrbase = bit64_extract(curr_cmd->cmd[2],16,35);
            console_printk("[BAO-VGICV3] Value of vRdbaser is 0x%lx\n",vrbase);

            //Translate to the physical red
            cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu()->vcpu->vm, vrbase);
            console_printk("[BAO-VGICV3] Value of pRdbaser is 0x%lx\n",pgicr_id);

            //update the command
            curr_cmd->cmd[2] = (curr_cmd->cmd[2] & ~(BIT64_MASK(16,35))) | (pgicr_id << 16);     //improve
            console_printk("[BAO-VGICV3] Value of cmd 2 mapc is 0x%lx\n",curr_cmd->cmd[2]);

            //Then the sync command
            console_printk("Value is 0x%lx\n",curr_cmd);
            curr_cmd += 1;
            console_printk("Value is 0x%lx\n",curr_cmd);
            if(bit64_extract(curr_cmd->cmd[0],0,8)==0x5)
            {
                console_printk("Inside sync\n");
                //update the command
                curr_cmd->cmd[2] = (curr_cmd->cmd[2] & ~(BIT64_MASK(16,35))) | (pgicr_id << 16);     //improve
                console_printk("[BAO-VGICV3] Value of cmd 2 sync is 0x%lx\n",curr_cmd->cmd[2]);
            }

        }
        

        console_printk("[BAO-VGICV3] Value of CREADR is 0x%lx\n",gits->CREADR);
        
        gits->CWRITER=vcpu_readreg(cpu()->vcpu, acc->reg);


        //console_printk("[BAO-VGICV3] CWRITER write from addr 0x%x\n",acc->addr);
        console_printk("[BAO-VGICV3] CWRITER write from addr 0x%x with the offset 0x%lx\n",acc->addr,gits->CWRITER);

    }
}

void vgits_emul_creadr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) {  //read only
        //translate to physical addr
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->CREADR);
        console_printk("[BAO-VGICV3] CREADR read from addr 0x%x with the offset 0x%x\n",acc->addr,bit64_extract(gits->CREADR,5,15));

    }else{
        //translate to virtual
        // gits->CREADR=vcpu_readreg(cpu()->vcpu, acc->reg);
        // console_printk("[BAO-VGICV3] CREADR write from cpu %d\n",cpu()->id);
    }
}

void vgits_emul_baser_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    size_t index = (GITS_REG_MASK(acc->addr) - GITS_REG_OFF(BASER)) >> 3;
    if (!acc->write) { //read baser

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
      

        vcpu_writereg(cpu()->vcpu, acc->reg,gits->BASER[index]);
        console_printk("[BAO-VGICV3] BASER read from addr 0x%x, index %d\n",acc->addr,index);
    }else{
        gits->BASER[index]=vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] BASER write from addr 0x%x, index %d with value 0x%lx\n",acc->addr,index,gits->BASER[index]);
        // if(bit64_extract(gits->BASER[index],56,3)==0x4){
        //     vaddr_t addr = bit64_extract(gits->BASER[index],12,36) << 12;
        //     size_t size = bit64_extract(gits->BASER[index],0,8) +1;
        //     console_printk("[BAO-VGICV3] Collection table allocation with addr 0x%lx and size 0x%x\n",addr,size);

        //      //TO-DO - Unmap only once
        //     //mem_unmap(&cpu()->vcpu->vm->as,(vaddr_t)addr,size,true);
        // }
    }
}

void vgits_emul_translater_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) { //write only
        //vcpu_writereg(cpu()->vcpu, acc->reg,gits->CTRANSLATER);
    }else{

        gits->TRANSLATER=vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] TRANSLATER write from addr 0x%x\n",acc->addr);
    }
}

void vgits_emul_iidr_access(struct emul_access* acc, struct vgic_reg_handler_info* handlers,
    bool gicr_access, vcpuid_t vgicr_id) 
{
    if (!acc->write) { //read only
        console_printk("[BAO-VGICV3] CTRANSLATER write from addr 0x%x\n",acc->addr);
        vcpu_writereg(cpu()->vcpu, acc->reg,gits->IIDR);
    }else{

        //gits->TRANSLATER=vcpu_readreg(cpu()->vcpu, acc->reg);
        console_printk("[BAO-VGICV3] CTRANSLATER write from addr 0x%x\n",acc->addr);
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

    // console_printk("Offset of TYPER is 0x%x\n",GITS_REG_OFF(TYPER));
    // console_printk("Offset of BASER is 0x%x\n",GITS_REG_OFF(BASER));
    // console_printk("Offset of TRANS is 0x%x\n",GITS_REG_OFF(TRANSLATER));
    // console_printk("Offset of ID is 0x%x\n",GITS_REG_OFF(ID));
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
        // case GITS_REG_OFF(BASER):
        //     handler_info = &vgits_baser_access;
        //     break;
        case GITS_REG_OFF(TRANSLATER):
            handler_info = &vgits_translater_access;
            break;
        case 0xffe8: //TO-DO improve
            handler_info = &vgits_pidr2_info;
            break;
        default: {
            size_t base_offset = acc->addr - cpu()->vcpu->vm->arch.vgicr_addr;
            size_t acc_offset = GITS_REG_MASK(base_offset);
            if (GITS_IS_REG(BASER, acc_offset)) {
                handler_info = &vgits_baser_access;
                //console_printk("[BAO-VGICV3] Inside default ITS emul in address:0x%x\n",acc->addr);
            } else {
                console_printk("GICv3: Inside razwi rEmulation in address:0x%x with base_offset=0x%x\n",acc->addr,base_offset);
            } 
            
            
            
            //else if (GICR_IS_REG(IPRIORITYR, acc_offset)) {
            //     handler_info = &vgits_baser_access;
            // } else if (GICR_IS_REG(ID, acc_offset)) {
            //     handler_info = &vgicr_pidr_info;
            // } else {
            //     handler_info = &razwi_info;
            //     console_printk("GICv3: Inside razwi rEmulation in address:0x%x with base_offset=0x%x\n",acc->addr,base_offset);
            // }
            
        }
    }

    if (vgic_check_reg_alignment(acc, handler_info)) {
        // vcpuid_t vgicr_id = vgicr_get_id(acc);
        // struct vcpu* vcpu =
        //     vgicr_id == cpu()->vcpu->id ? cpu()->vcpu : vm_get_vcpu(cpu()->vcpu->vm, vgicr_id);
        //spin_lock(&vcpu->arch.vgic_priv.vgicr.lock);
            handler_info->reg_access(acc, handler_info, false, 0);
        //spin_unlock(&vcpu->arch.vgic_priv.vgicr.lock);
        return true;
    } else {
        console_printk("GICv3: Not aligned rEmulation in address:0x%x\n",acc->addr);
        return false;
    }
    
    return true;
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

void vgic_init(struct vm* vm, const struct vgic_dscrp* vgic_dscrp,bool msi)
{
    vm->arch.vgicr_addr = vgic_dscrp->gicr_addr;
    vm->arch.vgicd.CTLR = 0;
    size_t vtyper_itln = vgic_get_itln(vgic_dscrp);
    vm->arch.vgicd.int_num = 32 * (vtyper_itln + 1);
    vm->arch.vgicd.TYPER = ((vtyper_itln << GICD_TYPER_ITLN_OFF) & GICD_TYPER_ITLN_MSK) |
        (((vm->cpu_num - 1) << GICD_TYPER_CPUNUM_OFF) & GICD_TYPER_CPUNUM_MSK) |
        ((((msi ? 16 : 10) - 1) << GICD_TYPER_IDBITS_OFF) & GICD_TYPER_IDBITS_MSK) | (msi? GICD_TYPER_LPIS : 0); //LPI support
    vm->arch.vgicd.IIDR = gicd->IIDR;

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

    for (vcpuid_t vcpuid = 0; vcpuid < vm->cpu_num; vcpuid++) {
        struct vcpu* vcpu = vm_get_vcpu(vm, vcpuid);
        uint64_t typer = (uint64_t)vcpu->id << GICR_TYPER_PRCNUM_OFF;
        typer |= ((uint64_t)vcpu->arch.vmpidr & MPIDR_AFF_MSK) << GICR_TYPER_AFFVAL_OFF;
        typer |= !!(vcpu->id == vcpu->vm->cpu_num - 1) << GICR_TYPER_LAST_OFF;
        typer |= (msi ? 0x1 : 0x0);   /*enable PLPIS*/
        vcpu->arch.vgic_priv.vgicr.TYPER = typer;
        vcpu->arch.vgic_priv.vgicr.IIDR = gicr[cpu()->id].IIDR;
    }

    /*GIC version of cpu interface*/


    vm->arch.vgicr_emul = (struct emul_mem){ .va_base = vgic_dscrp->gicr_addr,
        .size = ALIGN(sizeof(struct gicr_hw), PAGE_SIZE) * vm->cpu_num,
        .handler = vgicr_emul_handler };
    vm_emul_add_mem(vm, &vm->arch.vgicr_emul);

    /*ITS emul */
    vm->arch.vgits_emul = (struct emul_mem){ .va_base = vgic_dscrp->gits_addr,
        .size = ALIGN(sizeof(struct gits_hw), PAGE_SIZE),
        .handler = vgits_emul_handler };
    vm_emul_add_mem(vm, &vm->arch.vgits_emul);

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
