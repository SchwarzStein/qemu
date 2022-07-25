/*
 * QEMU RISC-V VMP (Physical Memory Protection)
 *
 * Author: Daire McNamara, daire.mcnamara@emdalo.com
 *         Ivan Griffin, ivan.griffin@emdalo.com
 *
 * This provides a RISC-V Physical Memory Protection implementation
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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "trace.h"
#include "exec/exec-all.h"

static void vmp_write_cfg(CPURISCVState *env, uint32_t addr_index,
    uint8_t val);
static uint8_t vmp_read_cfg(CPURISCVState *env, uint32_t addr_index);
static void vmp_update_rule(CPURISCVState *env, uint32_t vmp_index);

/*
 * Accessor method to extract address matching type 'a field' from cfg reg
 */
static inline uint8_t vmp_get_a_field(uint8_t cfg)
{
    uint8_t a = cfg >> 3;
    return a & 0x3;
}

/*
 * Check whether a VMP is locked or not.
 */
static inline int vmp_is_locked(CPURISCVState *env, uint32_t vmp_index)
{

    if (env->vmp_state.vmp[vmp_index].cfg_reg & VMP_LOCK) {
        return 1;
    }

    /* Top VMP has no 'next' to check */
    if ((vmp_index + 1u) >= MAX_RISCV_VMPS) {
        return 0;
    }

    return 0;
}

/*
 * Count the number of active rules.
 */
uint32_t vmp_get_num_rules(CPURISCVState *env)
{
     return env->vmp_state.num_rules;
}

/*
 * Accessor to get the cfg reg for a specific VMP/HART
 */
static inline uint8_t vmp_read_cfg(CPURISCVState *env, uint32_t vmp_index)
{
    if (vmp_index < MAX_RISCV_VMPS) {
        return env->vmp_state.vmp[vmp_index].cfg_reg;
    }

    return 0;
}

/*
 * Accessor to set the cfg reg for a specific VMP/HART
 * Bounds checks and relevant lock bit.
 */
static void vmp_write_cfg(CPURISCVState *env, uint32_t vmp_index, uint8_t val)
{
    if (vmp_index < MAX_RISCV_VMPS) {
        bool locked = true;

        if (!vmp_is_locked(env, vmp_index)) {
            locked = false;
        }

        if (locked) {
            qemu_log_mask(LOG_GUEST_ERROR, "ignoring vmpcfg write - locked\n");
        } else {
            env->vmp_state.vmp[vmp_index].cfg_reg = val;
            vmp_update_rule(env, vmp_index);
        }
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring vmpcfg write - out of bounds\n");
    }
}

static void vmp_decode_napot(target_ulong a, target_ulong *sa, target_ulong *ea)
{
    /*
       aaaa...aaa0   8-byte NAPOT range
       aaaa...aa01   16-byte NAPOT range
       aaaa...a011   32-byte NAPOT range
       ...
       aa01...1111   2^XLEN-byte NAPOT range
       a011...1111   2^(XLEN+1)-byte NAPOT range
       0111...1111   2^(XLEN+2)-byte NAPOT range
       1111...1111   Reserved
    */
    a = (a << 2) | 0x3;
    *sa = a & (a + 1);
    *ea = a | (a + 1);
}

void vmp_update_rule_addr(CPURISCVState *env, uint32_t vmp_index)
{
    uint8_t this_cfg = env->vmp_state.vmp[vmp_index].cfg_reg;
    target_ulong this_addr = env->vmp_state.vmp[vmp_index].addr_reg;
    target_ulong prev_addr = 0u;
    target_ulong sa = 0u;
    target_ulong ea = 0u;

    if (vmp_index >= 1u) {
        prev_addr = env->vmp_state.vmp[vmp_index - 1].addr_reg;
    }

    switch (vmp_get_a_field(this_cfg)) {
    case VMP_AMATCH_OFF:
        sa = 0u;
        ea = -1;
        break;

    case VMP_AMATCH_TOR:
        sa = prev_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (this_addr << 2) - 1u;
        if (sa > ea) {
            sa = ea = 0u;
        }
        break;

    case VMP_AMATCH_NA4:
        sa = this_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (sa + 4u) - 1u;
        break;

    case VMP_AMATCH_NAPOT:
        vmp_decode_napot(this_addr, &sa, &ea);
        break;

    default:
        sa = 0u;
        ea = 0u;
        break;
    }

    env->vmp_state.addr[vmp_index].sa = sa;
    env->vmp_state.addr[vmp_index].ea = ea;
}

void vmp_update_rule_nums(CPURISCVState *env)
{
    int i;

    env->vmp_state.num_rules = 0;
    for (i = 0; i < MAX_RISCV_VMPS; i++) {
        const uint8_t a_field =
            vmp_get_a_field(env->vmp_state.vmp[i].cfg_reg);
        if (VMP_AMATCH_OFF != a_field) {
            env->vmp_state.num_rules++;
        }
    }
}

/* Convert cfg/addr reg values here into simple 'sa' --> start address and 'ea'
 *   end address values.
 *   This function is called relatively infrequently whereas the check that
 *   an address is within a vmp rule is called often, so optimise that one
 */
static void vmp_update_rule(CPURISCVState *env, uint32_t vmp_index)
{
    vmp_update_rule_addr(env, vmp_index);
    vmp_update_rule_nums(env);
}

static int vmp_is_in_range(CPURISCVState *env, int vmp_index, target_ulong addr)
{
    int result = 0;

    if ((addr >= env->vmp_state.addr[vmp_index].sa)
        && (addr <= env->vmp_state.addr[vmp_index].ea)) {
        result = 1;
    } else {
        result = 0;
    }

    return result;
}

/*
 * Check if the address has required RWX privs when no VMP entry is matched.
 * when no vmp feature is available or no matching rules, we should allow
 * all permissions to the given virtual address, with access control left
 * to the default page table checks.
 */
static bool vmp_hart_has_privs_default(CPURISCVState *env, target_ulong addr,
    target_ulong size, vmp_priv_t privs, vmp_priv_t *allowed_privs,
    target_ulong mode)
{
    bool ret;
    ret = true;
    *allowed_privs = VMP_READ | VMP_WRITE | VMP_EXEC;
    return ret;
}

/*
 *  check if vmp permissions deny access to this address.
 *  when all permissions are denied to this address, then there is no
 *  need to do further checks.
 */

static bool  vmp_hart_zero_access(CPURISCVState *env, target_ulong addr,
    target_ulong size)
{
    int i = 0;
    int ret = 0;
    int vmp_size = 0;
    target_ulong s = 0;
    target_ulong e = 0;
    vmp_priv_t privs = VMP_READ|VMP_WRITE|VMP_EXEC;

    if ( !riscv_feature(env, RISCV_FEATURE_MMU) ) {
        return false;
    }

    if (0 == vmp_get_num_rules(env)) {
        return false;
    }
    
    if (size == 0) {
        if (riscv_feature(env, RISCV_FEATURE_MMU)) {
            /*
             * If size is unknown (0), assume that all bytes
             * from addr to the end of the page will be accessed.
             */
            vmp_size = -(addr | TARGET_PAGE_MASK);
        } else {
            vmp_size = sizeof(target_ulong);
        }
    } else {
        vmp_size = size;
    }

    /* 1.10 draft priv spec states there is an implicit order
         from low to high */
    for (i = 0; i < MAX_RISCV_VMPS; i++) {
        s = vmp_is_in_range(env, i, addr);
        e = vmp_is_in_range(env, i, addr + vmp_size - 1);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "vmp violation - access is partially inside\n");
            ret = 0;
            break;
        }

        /* fully inside */
        const uint8_t a_field =
            vmp_get_a_field(env->vmp_state.vmp[i].cfg_reg);

        /*
         * If the VMP entry is not off and the address is in range, do the priv
         * check
         */
        if (((s + e) == 2) && (VMP_AMATCH_OFF != a_field)) {
            ret = ( (allowed_privs & env->vmp_state.vmp[i].cfg_reg) == 0) ? 1: 0;
            break;
        }
    }
    return ret == 1 ? true : false;
}

/*
 * Public Interface
 */

/*
 * Check if the address has required RWX privs to complete desired operation
 */
bool vmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, vmp_priv_t privs, vmp_priv_t *allowed_privs,
    target_ulong mode)
{
    int i = 0;
    int ret = -1;
    int vmp_size = 0;
    target_ulong s = 0;
    target_ulong e = 0;

    /* Short cut if no rules */
    if (0 == vmp_get_num_rules(env)) {
        return vmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    if (size == 0) {
        if (riscv_feature(env, RISCV_FEATURE_MMU)) {
            /*
             * If size is unknown (0), assume that all bytes
             * from addr to the end of the page will be accessed.
             */
            vmp_size = -(addr | TARGET_PAGE_MASK);
        } else {
            vmp_size = sizeof(target_ulong);
        }
    } else {
        vmp_size = size;
    }

    /* 1.10 draft priv spec states there is an implicit order
         from low to high */
    for (i = 0; i < MAX_RISCV_VMPS; i++) {
        s = vmp_is_in_range(env, i, addr);
        e = vmp_is_in_range(env, i, addr + vmp_size - 1);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "pmp violation - access is partially inside\n");
            ret = 0;
            break;
        }

        /* fully inside */
        const uint8_t a_field =
            vmp_get_a_field(env->vmp_state.vmp[i].cfg_reg);

        /*
         * If the VMP entry is not off and the address is in range, do the priv
         * check
         */
        if (((s + e) == 2) && (VMP_AMATCH_OFF != a_field)) {
            *allowed_privs = VMP_READ | VMP_WRITE | VMP_EXEC;
            if ((mode != PRV_M) || vmp_is_locked(env, i)) {
                *allowed_privs &= env->vmp_state.vmp[i].cfg_reg;
            }

            ret = ((privs & *allowed_privs) == privs);
            break;
        }
    }

    /* No rule matched */
    if (ret == -1) {
        return vmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    return ret == 1 ? true : false;
}

/*
 * Handle a write to a vmpcfg CSR
 */
void vmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val)
{
    int i;
    uint8_t cfg_val;
    int vmpcfg_nums = 2 << riscv_cpu_mxl(env);

    trace_vmpcfg_csr_write(env->mhartid, reg_index, val);

    for (i = 0; i < vmpcfg_nums; i++) {
        cfg_val = (val >> 8 * i)  & 0xff;
        vmp_write_cfg(env, (reg_index * 4) + i, cfg_val);
    }

    /* If VMP permission of any addr has been changed, flush TLB pages. */
    tlb_flush(env_cpu(env)); /*TODO: Confirm this feature*/
}

/*
 * Handle a read from a vmpcfg CSR
 */
target_ulong vmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    int i;
    target_ulong cfg_val = 0;
    target_ulong val = 0;
    int vmpcfg_nums = 2 << riscv_cpu_mxl(env);

    for (i = 0; i < vmpcfg_nums; i++) {
        val = vmp_read_cfg(env, (reg_index * 4) + i);
        cfg_val |= (val << (i * 8));
    }
    trace_vmpcfg_csr_read(env->mhartid, reg_index, cfg_val);

    return cfg_val;
}


/*
 * Handle a write to a vmpaddr CSR
 */
void vmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val)
{
    trace_vmpaddr_csr_write(env->mhartid, addr_index, val);

    if (addr_index < MAX_RISCV_VMPS) {
        /*
         * In TOR mode, need to check the lock bit of the next vmp
         * (if there is a next).
         */
        if (addr_index + 1 < MAX_RISCV_VMPS) {
            uint8_t vmp_cfg = env->vmp_state.vmp[addr_index + 1].cfg_reg;

            if (vmp_cfg & VMP_LOCK &&
                VMP_AMATCH_TOR == vmp_get_a_field(vmp_cfg)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "ignoring vmpaddr write - vmpcfg + 1 locked\n");
                return;
            }
        }

        if (!vmp_is_locked(env, addr_index)) {
            env->vmp_state.vmp[addr_index].addr_reg = val;
            vmp_update_rule(env, addr_index);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "ignoring vmpaddr write - locked\n");
        }
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring vmpaddr write - out of bounds\n");
    }
}


/*
 * Handle a read from a vmpaddr CSR
 */
target_ulong vmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < MAX_RISCV_VMPS) {
        val = env->vmp_state.vmp[addr_index].addr_reg;
        trace_vmpaddr_csr_read(env->mhartid, addr_index, val);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring vmpaddr read - out of bounds\n");
    }

    return val;
}


/*
 * Calculate the TLB size if the start address or the end address of
 * VMP entry is presented in the TLB page.
 */
static target_ulong vmp_get_tlb_size(CPURISCVState *env, int vmp_index,
                                     target_ulong tlb_sa, target_ulong tlb_ea)
{
    target_ulong vmp_sa = env->vmp_state.addr[vmp_index].sa;
    target_ulong vmp_ea = env->vmp_state.addr[vmp_index].ea;

    if (vmp_sa >= tlb_sa && vmp_ea <= tlb_ea) {
        return vmp_ea - vmp_sa + 1;
    }

    if (vmp_sa >= tlb_sa && vmp_sa <= tlb_ea && vmp_ea >= tlb_ea) {
        return tlb_ea - vmp_sa + 1;
    }

    if (vmp_ea <= tlb_ea && vmp_ea >= tlb_sa && vmp_sa <= tlb_sa) {
        return vmp_ea - tlb_sa + 1;
    }

    return 0;
}

/*
 * Check is there a VMP entry which range covers this page. If so,
 * try to find the minimum granularity for the TLB size.
 */
bool vmp_is_range_in_tlb(CPURISCVState *env, hwaddr tlb_sa,
                         target_ulong *tlb_size)
{
    int i;
    target_ulong val;
    target_ulong tlb_ea = (tlb_sa + TARGET_PAGE_SIZE - 1);

    for (i = 0; i < MAX_RISCV_VMPS; i++) {
        val = vmp_get_tlb_size(env, i, tlb_sa, tlb_ea);
        if (val) {
            if (*tlb_size == 0 || *tlb_size > val) {
                *tlb_size = val;
            }
        }
    }

    if (*tlb_size != 0) {
        return true;
    }

    return false;
}

/*
 * Convert VMP privilege to TLB page privilege.
 */
int vmp_priv_to_page_prot(vmp_priv_t vmp_priv)
{
    int prot = 0;

    if (vmp_priv & VMP_READ) {
        prot |= PAGE_READ;
    }
    if (vmp_priv & VMP_WRITE) {
        prot |= PAGE_WRITE;
    }
    if (vmp_priv & VMP_EXEC) {
        prot |= PAGE_EXEC;
    }

    return prot;
}
