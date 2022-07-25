/*
 * QEMU RISC-V VMP (Physical Memory Protection)
 *
 * Author: Pamenas
 *
 * This provides a RISC-V Virtual Memory Protection interface
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

#ifndef RISCV_VMP_H
#define RISCV_VMP_H

#include "cpu.h"

typedef enum {
    VMP_READ  = 1 << 0,
    VMP_WRITE = 1 << 1,
    VMP_EXEC  = 1 << 2,
    VMP_LOCK  = 1 << 7
} vmp_priv_t;

typedef enum {
    VMP_AMATCH_OFF,  /* Null (off)                            */
    VMP_AMATCH_TOR,  /* Top of Range                          */
    VMP_AMATCH_NA4,  /* Naturally aligned four-byte region    */
    VMP_AMATCH_NAPOT /* Naturally aligned power-of-two region */
} vmp_am_t;

typedef struct {
    target_ulong addr_reg;
    uint8_t  cfg_reg;
} vmp_entry_t;

typedef struct {
    target_ulong sa;
    target_ulong ea;
} vmp_addr_t;

typedef struct {
    vmp_entry_t vmp[MAX_RISCV_VMPS];
    vmp_addr_t  addr[MAX_RISCV_VMPS];
    uint32_t num_rules;
} vmp_table_t;

void vmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val);
target_ulong vmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index);

void mseccfg_csr_write(CPURISCVState *env, target_ulong val);
target_ulong mseccfg_csr_read(CPURISCVState *env);

void vmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val);
target_ulong vmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index);
bool vmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, vmp_priv_t privs, vmp_priv_t *allowed_privs,
    target_ulong mode);
bool vmp_is_range_in_tlb(CPURISCVState *env, hwaddr tlb_sa,
                         target_ulong *tlb_size);
void vmp_update_rule_addr(CPURISCVState *env, uint32_t vmp_index);
void vmp_update_rule_nums(CPURISCVState *env);
uint32_t vmp_get_num_rules(CPURISCVState *env);
int vmp_priv_to_page_prot(vmp_priv_t vmp_priv);

#endif
