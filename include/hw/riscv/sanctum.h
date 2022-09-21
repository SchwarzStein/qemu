/*
 * Sanctum machine interface
 *
 * Copyright (c) 2019 Ilia Lebedev, MIT.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_RISCV_SANCTUM_H
#define HW_RISCV_SANCTUM_H

typedef struct {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    RISCVHartArrayState soc;
    DeviceState *plic;
    void *fdt;
    int fdt_size;
} SanctumState;

enum {
    SANCTUM_MROM,
    SANCTUM_PUF,
    SANCTUM_ELFLD,
    SANCTUM_CLINT,
    SANCTUM_UART0,
    SANCTUM_PLIC,
    SANCTUM_VIRTIO,
    SANCTUM_DRAM
};

enum {
    UART0_IRQ = 10,
    SANCTUM_CLOCK_FREQ = 1250000000,
    VIRTIO_IRQ = 1, /* 1 to 8 */
    VIRTIO_COUNT = 8,
    VIRTIO_NDEV = 0x35, /* Arbitrary maximum number of interrupts */
};

#define SANCTUM_PLIC_HART_CONFIG "MS"
#define SANCTUM_PLIC_NUM_SOURCES 127
#define SANCTUM_PLIC_NUM_PRIORITIES 7
#define SANCTUM_PLIC_PRIORITY_BASE 0x04
#define SANCTUM_PLIC_PENDING_BASE 0x1000
#define SANCTUM_PLIC_ENABLE_BASE 0x2000
#define SANCTUM_PLIC_ENABLE_STRIDE 0x80
#define SANCTUM_PLIC_CONTEXT_BASE 0x200000
#define SANCTUM_PLIC_CONTEXT_STRIDE 0x1000

#define FDT_PLIC_ADDR_CELLS   0
#define FDT_PLIC_INT_CELLS    1
#define FDT_INT_MAP_WIDTH     (1 + FDT_PLIC_ADDR_CELLS + FDT_PLIC_INT_CELLS)

#define SANCTUM_CPU TYPE_RISCV_CPU_RV64GCSU_V1_10_0

#endif
