/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#ifndef __GICV4_H__
#define __GICV4_H__

#include <arch/gic.h>

void gicr_set_vpropbaser(cpuid_t gicr_id, uint64_t phy_addr, size_t id_bits);
void gicr_set_vpendbaser(cpuid_t gicr_id, uint64_t phy_addr);

#endif /* __GICV4_H__ */