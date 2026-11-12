// Copyright (C) 2023 Intel Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
// OR OTHER DEALINGS IN THE SOFTWARE.
//
// SPDX-License-Identifier: MIT

/**
 * @file tdh_sys_init.c
 * @brief TDHSYSINIT API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "tdx_vmm_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER

#include "data_structures/tdx_global_data.h"
#include "data_structures/loader_data.h"
#include "data_structures/preserving_defs.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/virt_msr_helpers.h"

#include "helpers/smrrs.h"
#include CPUID_CONFIGURATIONS_HEADER
#include TD_VMCS_FIELDS_LOOKUP_HEADER
#include "helpers/fatal_info.h"
#include "helpers/preserving.h"


/*
 * check_allowed_vmx_ctls
 */
_STATIC_INLINE_ bool_t check_allowed_vmx_ctls(uint32_t* dest,
                                              ia32_vmx_allowed_bits_t src,
                                              uint32_t init,
                                              uint32_t variable_mask,
                                              uint32_t unknown_mask)
{
    // Sanity check on the MSR values returned by the CPU:
    // Any bit can't be both fixed-1 (bits that are 1 in NOT_ALLOWED0) and fixed-0 (bits that are 0 in ALLOWED1)
    tdx_sanity_check((src.not_allowed0 & ~src.allowed1) == 0, FATAL_ERROR_ID_289, 0);

    // Sanity check on the TDX-SEAM module's constants:
    // Any unknown bits must be 0 in the init value and must not be variable
    tdx_sanity_check(((init | variable_mask) & unknown_mask) == 0, FATAL_ERROR_ID_290, 1);

    // Check bits that are fixed-1 (bits that are 1 in NOT_ALLOWED0).
    // Any fixed-1 bit must be initialized to 1.  For this check, ignore bits in the init value that are unknown.
    // Per Intel SDM:
    // Bits 31:0 indicate the allowed 0-settings of these controls.
    // VM entry allows control X to be 0 if bit X in the MSR is cleared to 0;
    // if bit X in the MSR is set to 1, VM entry fails if control X is 0.
    if ((src.not_allowed0 & ~(init | unknown_mask)) != 0)
    {
        return false;
    }

    // Check bits that are fixed-0 (bits that are 0 in ALLOWED1).
    // Any fixed-0 bit must be initialized to 0.
    // Per Intel SDM:
    // Bits 63:32 indicate the allowed 1-settings of these controls.
    // VM entry allows control X to be 1 if bit 32+X in the MSR is set to 1;
    // if bit 32+X in the MSR is cleared to 0, VM entry fails if control X is 1.
    if ((~src.allowed1 & init) != 0)
    {
        return false;
    }

    // Any fixed-1 bit (that is 1 in NOT_ALLOWED0) or fixed-0 bit (that is 0 in ALLOWED1) must not be variable
    if (((src.not_allowed0 | ~src.allowed1) & variable_mask) != 0)
    {
        return false;
    }

    // Return the value used for initializing the TD VMCS field (incl. unknown bits) Set fixed-1 (NOT_ALLOWED0) bits to 1.
    *dest = (init | src.not_allowed0);

    return true;
}

_STATIC_INLINE_ bool_t check_allowed64_vmx_ctls(uint64_t not_allowed0, uint64_t allowed1,
                                                uint64_t init, uint64_t variable_mask)
{
    tdx_sanity_check((not_allowed0 & ~allowed1) == 0, FATAL_ERROR_ID_291, 2);

    if ((not_allowed0 & ~init) || (~allowed1 & init) || ((not_allowed0 | ~allowed1) & variable_mask))
    {
        return false;
    }

    return true;
}

/*
 * check_allowed1_vmx_ctls
 */
_STATIC_INLINE_ bool_t check_allowed1_vmx_ctls(uint64_t* dest,
                                              uint64_t  allowed1,
                                              uint64_t  init,
                                              uint64_t  variable_mask,
                                              uint64_t  unknown_mask)
{
    /* Sanity check on the TDX-SEAM module's constants:
           Any unknown bits must be 0 in the init value and must not be variable */
    tdx_sanity_check(((init | variable_mask) & unknown_mask) == 0, FATAL_ERROR_ID_292, 3);

    /* Check bits that are fixed-0 (bits that are 0 in ALLOWED1).  Any fixed-0
       bit must be initialized to 0. */
    if ((~allowed1 & init) != 0)
    {
        return false;
    }

    // Any fixed-0 bit (that is 0 in ALLOWED1) must not be variable.
    if ((~allowed1 & variable_mask) != 0)
    {
        return false;
    }

    // Return the value used for initializing the TD VMCS field (incl. unknown bits)
    *dest = init;

    return true;
}

_STATIC_INLINE_ bool_t is_tdx_io_supported(void)
{
    return get_sysinfo_table()->mcheck_fields.io_sys_info_table_version > 0;
}


_STATIC_INLINE_ bool_t is_smrr_mask_valid_for_tdx(smrr_base_t smrr_base, smrr_mask_t smrr_mask)
{
    // Create a bit mask from the first LSB which is 1 in the mask, until the uppermost bit 31
    // XOR it with the mask value to see if there are any "hole" bits in the mask
    uint32_t actual_mask = (uint32_t)(smrr_mask.raw & BITS(31, 12));

    uint64_t mask_lsb;

    if (!bit_scan_forward64(actual_mask, &mask_lsb))
    {
        return false; // Don't allow mask 0
    }

    uint32_t bitmask = (uint32_t)(BITS(31, mask_lsb));

    if ((actual_mask ^ bitmask) != 0)
    {
        return false;
    }

    // Check that the base is aligned on the range size
    uint32_t actual_base = (uint32_t)(smrr_base.raw & BITS(31, 12));

    if ((actual_base & ~bitmask) != 0)
    {
        return false;
    }

    return true;
}

_STATIC_INLINE_ api_error_type check_and_store_smrr_smrr2(tdx_module_global_t* tdx_global_data_ptr)
{
    uint8_t num_of_smrrs = 1;

    tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.raw = ia32_rdmsr(MTRR_CAP_MSR_ADDR);

    if (tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr == 0)
    {
        TDX_ERROR("SMRR not enabled\n");
        return TDX_SMRR_NOT_SUPPORTED;
    }

    if (tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr_lock == 0)
    {
            TDX_ERROR("SMRR Lock not enabled\n");
            return TDX_SMRR_LOCK_NOT_SUPPORTED;
    }

    tdx_global_data_ptr->plt_common_config.smrr[0].smrr_mask.raw = ia32_rdmsr(SMRR_MASK_MSR_ADDR);
    tdx_global_data_ptr->plt_common_config.smrr[0].smrr_base.raw = ia32_rdmsr(SMRR_BASE_MSR_ADDR);

    sysinfo_table_t * sysinfo_table_ptr = get_sysinfo_table();

    // Determine whether SMRR2 is supported
    if (sysinfo_table_ptr->mcheck_fields.smrr2_not_supported == 0 && tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr2 != 0)
    {
        tdx_global_data_ptr->plt_common_config.smrr[1].smrr_mask.raw = ia32_rdmsr(SMRR2_MASK_MSR_ADDR);
        tdx_global_data_ptr->plt_common_config.smrr[1].smrr_base.raw = ia32_rdmsr(SMRR2_BASE_MSR_ADDR);
        num_of_smrrs = 2U;
    }

    //SMRR and SMRR2 must be locked
    for (uint8_t smrr_idx = 0; smrr_idx < num_of_smrrs; smrr_idx++)
    {
        if (tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.lock == 0)
        {
            TDX_ERROR("SMRR %d not locked\n", smrr_idx+1);
            return api_error_with_operand_id(TDX_SMRR_NOT_LOCKED, (uint64_t)smrr_idx);
        }
    }

    //SMRR and SMRR2 must not overlap with any CMR

    for (uint8_t smrr_idx = 0; smrr_idx < num_of_smrrs; smrr_idx++)
    {
        if (tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.vld == 0)
        {
            continue;
        }
        smrr_base_t smrr_base = { .raw = 0 };
        smrr_base.base = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_base.base;
        smrr_mask_t smrr_mask = { .raw = 0 };
        smrr_mask.mask = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.mask;

        if (!is_smrr_mask_valid_for_tdx(smrr_base, smrr_mask))
        {
            TDX_ERROR("SMRR %d mask is corrupt 0x%llx (base 0x%llx)\n",
                    smrr_idx+1, smrr_mask.raw, smrr_base.raw);
            return api_error_with_operand_id(TDX_INVALID_SMRR_CONFIGURATION, (uint64_t)smrr_idx);
        }

        uint64_t smrr_size = mask_to_size(smrr_mask.raw);

        tdx_debug_assert(is_valid_integer_range(smrr_base.raw, smrr_size));

        // Check SMRRs don't overlap with CMRs - at this point CMR ranges should be checked
        // for integer overflow
        for (uint8_t cmr_i = 0; cmr_i < MAX_CMR; cmr_i++)
        {
            if (sysinfo_table_ptr->cmr_data[cmr_i].cmr_size != 0 &&
                    is_overlap(smrr_base.raw, smrr_size, sysinfo_table_ptr->cmr_data[cmr_i].cmr_base,
                    sysinfo_table_ptr->cmr_data[cmr_i].cmr_size))
            {
                TDX_ERROR("SMRR %d overlap with CMR %d \n", smrr_idx+1, cmr_i);
                return api_error_with_multiple_info(TDX_SMRR_OVERLAPS_CMR, smrr_idx, cmr_i, 0, 0);
            }
        };

    }
    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_key_management_config(tdx_module_global_t* tdx_global_data_ptr)
{
    tdx_global_data_ptr->plt_common_config.ia32_tme_capability.raw = ia32_rdmsr(IA32_TME_CAPABILITY_MSR_ADDR);
    tdx_global_data_ptr->plt_common_config.ia32_tme_activate.raw = ia32_rdmsr(IA32_TME_ACTIVATE_MSR_ADDR);

    uint32_t msr_addr = check_mem_enc_alg(tdx_global_data_ptr->plt_common_config.ia32_tme_capability, tdx_global_data_ptr->plt_common_config.ia32_tme_activate);
    if (msr_addr != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, msr_addr);
    }

    tdx_global_data_ptr->hkid_start_bit = (uint32_t)(tdx_global_data_ptr->max_pa - (uint64_t)tdx_global_data_ptr->plt_common_config.ia32_tme_activate.mk_tme_keyid_bits);

    tdx_global_data_ptr->hkid_mask = BITS(tdx_global_data_ptr->max_pa - 1, tdx_global_data_ptr->hkid_start_bit);

    tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.raw = ia32_rdmsr(IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);

    tdx_global_data_ptr->private_hkid_min = tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_mktme_kids + 1;

    tdx_global_data_ptr->private_hkid_max =
            tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_mktme_kids +
            tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_tdx_priv_kids;

    if (tdx_global_data_ptr->private_hkid_max >= MAX_HKIDS)
    {
        return api_error_with_operand_id(TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORTED, MAX_HKIDS);
    }

    // INIT SEAMRR base and size
    tdx_global_data_ptr->seamrr_base = ia32_rdmsr(IA32_SEAMRR_BASE_MSR_ADDR) & IA32_SEAMRR_BASE_AND_MASK_MASK;

    uint64_t seamrr_mask = ia32_rdmsr(IA32_SEAMRR_MASK_MSR_ADDR) & IA32_SEAMRR_BASE_AND_MASK_MASK;
    tdx_global_data_ptr->seamrr_size = mask_to_size(seamrr_mask);

    /* Get the number of cache sub-blocks for TDWBINVD
    */
    // INIT number of cached blocks for WBINVD cycle
    tdx_global_data_ptr->num_of_cached_sub_blocks = ia32_rdmsr(IA32_WBINVDP_MSR_ADDR);

    // WBNOINVDP should return the same value
    if (ia32_rdmsr(IA32_WBNOINVDP_MSR_ADDR) != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_WBNOINVDP_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_cpuid_configurations(tdx_module_global_t* global_data_ptr)
{
    /**
     * Sample and Check Native CPUID Values
     */

    cpuid_config_t cpuid_config;
    sysinfo_table_t *sysinfo_table_ptr = get_sysinfo_table();
    uint32_t lpids_sharing_l3_cache = (uint32_t)-1; //Initialized to invalid value.
    bool_t core_level_scanned = false;
    uint32_t shift_count = (uint32_t)-1; //Initialized to invalid value.
    uint32_t prev_level_type = LEVEL_TYPE_INVALID;

    bool_t perfmon_ext_leaf_checked = false;
    bool_t perfmon_ext_leaf_supported = false;
    cpuid_23_0_eax_t leaf_eax = { .raw = 0 };

    global_data_ptr->xfd_faulting_mask = 0; // Updated later per CPUID leaf 0xD
    global_data_ptr->x2apic_core_id_shift_count = 0;  // Updated later per CPUID leaf 0x1F

    ia32_misc_enable_t misc_enable = {.raw = ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR)};
    // Boot NT4 bit should not be set
    if (misc_enable.limit_cpuid_maxval)
    {
    	return TDX_LIMIT_CPUID_MAXVAL_SET;
    }

    if ((!misc_enable.perfmon_available) || (misc_enable.bts_unavailable))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_MISC_ENABLES_MSR_ADDR);
    }

    global_data_ptr->plt_common_config.ia32_misc_enable.raw = misc_enable.raw;

    uint32_t last_base_leaf, last_extended_leaf;
    uint32_t ebx, ecx, edx;

    // Last base leaves need to be taken before
    ia32_cpuid(CPUID_MAX_INPUT_VAL_LEAF, 0, &last_base_leaf, &ebx, &ecx, &edx);
    if (last_base_leaf < CPUID_MIN_LAST_CPU_BASE_LEAF)
    {
        return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_MIN_LAST_CPU_BASE_LEAF);
    }
    global_data_ptr->cpuid_last_base_leaf = CPUID_LAST_BASE_LEAF;

    ia32_cpuid(CPUID_MAX_EXTENDED_VAL_LEAF, 0, &last_extended_leaf, &ebx, &ecx, &edx);
    if (last_extended_leaf < CPUID_LAST_EXTENDED_LEAF)
    {
        return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_LAST_EXTENDED_LEAF);
    }
    tdx_sanity_check(last_extended_leaf >= CPUID_MAX_EXTENDED_VAL_LEAF, FATAL_ERROR_ID_293, 4);
    global_data_ptr->cpuid_last_extended_leaf = last_extended_leaf;

    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        if (!cpuid_lookup[i].valid_entry)
        {
            continue;
        }

        cpuid_config.leaf_subleaf = cpuid_lookup[i].leaf_subleaf;

        if (!is_not_gnr_a0_stepping())
        {
            if (cpuid_config.leaf_subleaf.leaf == CPUID_EXT_FEATURES_LEAF && cpuid_config.leaf_subleaf.subleaf == 2)
            {
                ia32_cpuid(cpuid_config.leaf_subleaf.leaf, cpuid_config.leaf_subleaf.subleaf,
                           &cpuid_config.values.eax, &cpuid_config.values.ebx,
                           &cpuid_config.values.ecx, &cpuid_config.values.edx);

                global_data_ptr->cpuid_values[i] = cpuid_config;

                cpuid_07_02_edx_t cpuid_07_02_edx;
                cpuid_07_02_edx.raw = cpuid_config.values.edx;
                global_data_ptr->ddpd_supported = cpuid_07_02_edx.ddpd;

                continue;
            }
        }

        if ((cpuid_config.leaf_subleaf.leaf <= last_base_leaf) ||
            ((cpuid_config.leaf_subleaf.leaf >= CPUID_FIRST_EXTENDED_LEAF) &&
             (cpuid_config.leaf_subleaf.leaf <= last_extended_leaf)))
        {
            ia32_cpuid(cpuid_config.leaf_subleaf.leaf, cpuid_config.leaf_subleaf.subleaf,
                    &cpuid_config.values.eax, &cpuid_config.values.ebx,
                    &cpuid_config.values.ecx, &cpuid_config.values.edx);
        }
        else
        {
            // Leaf is not supported by the CPU, use all-0 values as default
            cpuid_config.values.low = 0;
            cpuid_config.values.high = 0;
        }

        if (cpuid_config.leaf_subleaf.leaf == 0x6 &&
            (!is_not_gnr_a0_stepping()))
        {
            continue;
        }

        if (!(((cpuid_config.values.low & cpuid_lookup[i].verify_mask.low)
                == cpuid_lookup[i].verify_value.low)
                && ((cpuid_config.values.high
                        & cpuid_lookup[i].verify_mask.high)
                        == cpuid_lookup[i].verify_value.high)))
        {
            tdx_module_local_t *tdx_local_data_ptr = get_local_data();
            tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
            tdx_local_data_ptr->vmm_regs.rdx = cpuid_lookup[i].verify_mask.low;
            tdx_local_data_ptr->vmm_regs.r8 = cpuid_lookup[i].verify_mask.high;
            tdx_local_data_ptr->vmm_regs.r9 = cpuid_lookup[i].verify_value.low;
            tdx_local_data_ptr->vmm_regs.r10 = cpuid_lookup[i].verify_value.high;

            TDX_ERROR("CPUID 0x%x.0x%x doesn't match expected value!\n",
                    cpuid_config.leaf_subleaf.leaf, cpuid_config.leaf_subleaf.subleaf);
            TDX_ERROR("Verify mask: EAX = 0x%x, EBX = 0x%x, ECX = 0x%x, EDX = 0x%x\n",
                    cpuid_lookup[i].verify_mask.eax, cpuid_lookup[i].verify_mask.ebx,
                    cpuid_lookup[i].verify_mask.ecx, cpuid_lookup[i].verify_mask.edx);
            TDX_ERROR("Verify value: EAX = 0x%x, EBX = 0x%x, ECX = 0x%x, EDX = 0x%x\n",
                    cpuid_lookup[i].verify_value.eax, cpuid_lookup[i].verify_value.ebx,
                    cpuid_lookup[i].verify_value.ecx, cpuid_lookup[i].verify_value.edx);
            TDX_ERROR("Platform value: EAX = 0x%x, EBX = 0x%x, ECX = 0x%x, EDX = 0x%x\n",
                    cpuid_config.values.eax, cpuid_config.values.ebx,
                    cpuid_config.values.ecx, cpuid_config.values.edx);

            return TDX_INCORRECT_CPUID_VALUE;
        }

        /**
         * Special Handling of selected CPUIDs
         */

        uint32_t leaf = cpuid_config.leaf_subleaf.leaf;
        uint32_t subleaf = cpuid_config.leaf_subleaf.subleaf;

        /* CPUID Leaf 1 is a special case.  The Stepping ID field, returned in RAX
           should be set to the minimal F/M/S of all packages in the platform.
           F/M/S values are read by MCHECK, which also assures Family and Model are
           the same in all packages.
           SEAMLDR verifies Family and Model compatibility with the TDX-SEAM module.
        */
        if (leaf == CPUID_VER_INFO_LEAF)
        {
            global_data_ptr->platform_fms.raw = sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[0].raw;
            for (uint32_t pkg_index = 1; pkg_index < sysinfo_table_ptr->mcheck_fields.tot_num_sockets; pkg_index++)
            {
                if (global_data_ptr->platform_fms.stepping_id >
                    sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[pkg_index].stepping_id)
                {
                    global_data_ptr->platform_fms.stepping_id = sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[pkg_index].stepping_id;
                }
            }
            cpuid_config.values.eax = global_data_ptr->platform_fms.raw;
        }
        /* Get the number of LPIDs sharing the L3 cache. This is used later to verify
           the scope of WBINVD, which TDX-SEAM currently assumes to be package.
        */
        else if (leaf == CPUID_DET_CACHE_PARAMS_LEAF && subleaf == CPUID_DET_CACHE_PARAMS_SUBLEAF)
        {
            lpids_sharing_l3_cache =
                    ((cpu_cache_params_t)cpuid_config.values.eax).max_num_of_lps_sharing_cache;
        }

        /* Check Extended Features Support
        */
        else if (leaf == CPUID_EXT_FEATURES_LEAF)
        {
            if (subleaf == CPUID_EXT_FEATURES_SUBLEAF)
            {
                //Sample the TSX support bits.
                cpuid_07_00_ebx_t cpuid_07_00_ebx = {.raw = cpuid_config.values.ebx};
                global_data_ptr->hle_supported = cpuid_07_00_ebx.hle;
                global_data_ptr->rtm_supported = cpuid_07_00_ebx.rtm;

                cpuid_07_00_ecx_t cpuid_07_00_ecx = { .raw = cpuid_config.values.ecx };
                global_data_ptr->waitpkg_supported = cpuid_07_00_ecx.waitpkg;
                global_data_ptr->la57_supported = cpuid_07_00_ecx.la57;
            }
            else if (subleaf == CPUID_EXT_FEATURES2_SUBLEAF)
            {
                // get some CPUID values needed for later checks
                cpuid_07_01_eax_t cpuid_7_1_eax = {.raw = cpuid_config.values.eax};
                perfmon_ext_leaf_supported = cpuid_7_1_eax.perfmon_ext_leaf;
                perfmon_ext_leaf_checked = true;

                global_data_ptr->lam_supported = cpuid_7_1_eax.lam;
                global_data_ptr->is_nmi_source_supported = cpuid_7_1_eax.nmi_source_ident;
                global_data_ptr->lass_supported = cpuid_7_1_eax.lass;
                global_data_ptr->perfmon_ext_leaf_supported = perfmon_ext_leaf_supported;
            }
            else if (subleaf == 2)
            {
                // Check CPU side channel protection support
                cpuid_07_02_edx_t cpuid_07_02_edx;
                cpuid_07_02_edx.raw = cpuid_config.values.edx;
                global_data_ptr->ddpd_supported = cpuid_07_02_edx.ddpd;
            }
        }

        else if (leaf == CPUID_PERFMON_LEAF)
        {
            tdx_module_local_t *tdx_local_data_ptr = get_local_data();

            cpuid_0a_eax_t cpuid_0a_eax = { .raw = cpuid_config.values.eax};
            uint32_t cpuid_0a_ecx = cpuid_config.values.ecx;
            cpuid_0a_edx_t cpuid_0a_edx = { .raw = cpuid_config.values.edx};

            if (cpuid_0a_eax.version < 5)  // not supported
            {
                tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                tdx_local_data_ptr->vmm_regs.rdx = CPUID_PERFMON_EAX_MASK_LOW;
                tdx_local_data_ptr->vmm_regs.r8  = CPUID_PERFMON_EAX_MASK_HIGH;
                tdx_local_data_ptr->vmm_regs.r9  = CPUID_PERFMON_EAX_EXPECTED_LOW;
                tdx_local_data_ptr->vmm_regs.r10 = CPUID_PERFMON_EAX_EXPECTED_HIGH;

                TDX_ERROR("Failed CPUID_PERFMON_LEAF (0xA) check, version %d is lower than supported",
                           cpuid_0a_eax.version);

                return TDX_INCORRECT_CPUID_VALUE;
            }

            // CPUs with Perfmon version >= 6 support the new MSR range starting @ 0x1900
            global_data_ptr->perfmon_new_msrs = (cpuid_0a_eax.version >= 6);

            // Read and check actual number of fixed-function counters
            global_data_ptr->num_fixed_ctrs = cpuid_0a_edx.num_fcs;

            // Per Intel SDM, Vol. 3, 19.2.5.2:
            // FxCtr[i]_is_supported := ECX[i] || (EDX[4:0] > i)
            // So, set all bitmap bits per EDX[4:0] and OR with the bitmap in ECX.
            global_data_ptr->fc_bitmap = (uint32_t)((BIT(cpuid_0a_edx.num_fcs) - 1) | cpuid_0a_ecx);

            if ((BIT(MAX_FIXED_CTRS) - 1) < global_data_ptr->fc_bitmap)
            {
                tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                tdx_local_data_ptr->vmm_regs.rdx = CPUID_PERFMON_EDX_MASK_LOW;
                tdx_local_data_ptr->vmm_regs.r9  = CPUID_PERFMON_EDX_EXPECTED_LOW;
                tdx_local_data_ptr->vmm_regs.r8 = CPUID_PERFMON_ECX_EDX_MASK_HIGH;
                tdx_local_data_ptr->vmm_regs.r10 = CPUID_PERFMON_ECX_EDX_EXPECTED_HIGH;

                TDX_ERROR("Failed CPUID_PERFMON_LEAF (0xA) check, num_fixed_ctrs %d is higher than supported",
                        cpuid_0a_edx.num_fcs);

                return TDX_INCORRECT_CPUID_VALUE;
            }

            // Set default value for PMC_BITMAP as all-1, e.g. if num_pmcs = 8 then pmc_bitmap = 0xFF
            // Will be overwritten by leaf 0x23 if supported.
            global_data_ptr->pmc_bitmap = (uint32_t)BIT(cpuid_0a_eax.num_gp_counters) - 1;
        }

        /* Get the supported extended features.  Allow only features that are recognized
           by TDX-SEAM (as specified by XCR0_USER_BIT_MASK and XCR0_SUPERVISOR_BIT_MASK to avoid surprises. */
        else if (leaf == CPUID_EXT_STATE_ENUM_LEAF)
        {
            if (subleaf == CPUID_EXT_STATE_ENUM_MAIN_SUBLEAF)
            {
                global_data_ptr->xcr0_supported_mask = cpuid_config.values.eax & XCR0_USER_BIT_MASK;
            }
            else if (subleaf == CPUID_EXT_STATE_ENUM_XSAVES_SUBLEAF)
            {
                cpuid_0d_01_eax_t cpuid_0D_01_eax;
                cpuid_0D_01_eax.raw = cpuid_config.values.eax;
                global_data_ptr->xfd_supported = cpuid_0D_01_eax.xfd_support;
                global_data_ptr->ia32_xss_supported_mask = cpuid_config.values.ecx & XCR0_SUPERVISOR_BIT_MASK;

                // Sanity check: Masks for user and system extended features must be mutually exclusive
                tdx_sanity_check((global_data_ptr->xcr0_supported_mask & global_data_ptr->ia32_xss_supported_mask) == 0, FATAL_ERROR_ID_294, 5);
            }
            else
            {
                // For sub-leaf > 1, collect extended state component size and alignment information.
                cpuid_0d_ecx_t cpuid_0d_ecx = { .raw = cpuid_config.values.ecx };

                global_data_ptr->xsave_comp[subleaf].size  = cpuid_config.values.eax;
                global_data_ptr->xsave_comp[subleaf].align = cpuid_0d_ecx.align_64;

                // Update the XFD faulting mask for this sub-leaf
                if (global_data_ptr->xfd_supported && cpuid_0d_ecx.xfd_faulting)
                {
                    global_data_ptr->xfd_faulting_mask |= (1 << subleaf);
                }

                // Sanity checks on the extended features masks
                if (cpuid_0d_ecx.ia32_xss)
                {
                    // This is a system feature and must not be in the XCR0 supported mask
                    if ((uint64_t)global_data_ptr->xcr0_supported_mask & (BIT(subleaf)))
                    {
                        // FATAL_ERROR
                        fatal_error(FATAL_ERROR_ID_60, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
                    }
                }
                else
                {
                    // This is a user feature and must not be in the IA32_XSS supported mask
                    if ((uint64_t)global_data_ptr->ia32_xss_supported_mask & (BIT(subleaf)))
                    {
                        // FATAL_ERROR
                        fatal_error(FATAL_ERROR_ID_61, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
                    }
                }
            }
        }

        else if (leaf == CPUID_TSC_ATTRIBUTES_LEAF)
        {
            // Get TSC attributes

            if (cpuid_config.values.ebx == 0)
            {
                return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_TSC_ATTRIBUTES_LEAF);
            }

            global_data_ptr->crystal_clock_frequency = cpuid_config.values.ecx;

            // Calculate native TSC frequency. Calculation is done as unsigned 64b and
            //   in the proper order.
            global_data_ptr->native_tsc_frequency =
                    ((uint64_t)cpuid_config.values.ecx * (uint64_t)cpuid_config.values.ebx) /
                     (uint64_t)cpuid_config.values.eax;

            // Sanity check on native TSC frequency, to guarantee no overflow when TSC virtualization
            // params are calculated.
            if (global_data_ptr->native_tsc_frequency < NATIVE_TSC_FREQUENCY_MIN)
            {
                // Fatal Error
                fatal_error(FATAL_ERROR_ID_63, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
            }
        }
        else if (leaf == 0x1A)
        {
            // Store the native model information for later reference
            global_data_ptr->native_model_info.raw = cpuid_config.values.eax;
        }
        else if (leaf == CPUID_LBR_CAPABILITIES_LEAF)
        {
            uint32_t cpuid_1c_eax;
            cpuid_1c_eax = (uint32_t)cpuid_config.values.eax;
            tdx_debug_assert((cpuid_1c_eax & (BIT(8)-1)) > 0);
            // get the index of the most significant bit set to '1' int lower 8 bits of cpuid_1c_eax
            uint64_t msb;

            if (!bit_scan_reverse64(cpuid_1c_eax & (BIT(8)-1), &msb))
            {
                fatal_error(FATAL_ERROR_ID_114, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
            }

            global_data_ptr->max_lbr_depth = 8 * ((uint32_t)msb + 1);
        }
        /**
         * Get topology information and verify that the scope of WBINVD is package
         *
         * Notes:  1. The following algorithm assumes we scan sub-leaves sequentially, starting
         *            from 0.  The lookup tables must be built this way.
         *         2. The algorithm assumes that the sub-leaves are organized in order of level
         *            types.  Although the Intel SDM does not require it, actual CPU
         *            implementations work this way and it simplifies out life.
         */
        else if (leaf == CPUID_GET_TOPOLOGY_LEAF)
        {
            // Check that ECX provides the correct subleaf number.
            if (cpuid_config.leaf_subleaf.subleaf != ((cpuid_topology_level_t)cpuid_config.values.ecx).level_number)
            {
                TDX_ERROR("CPUID_GET_TOPOLOGY_LEAF subleaf %d does not match expected value %d\n",
                    cpuid_config.leaf_subleaf.subleaf, ((cpuid_topology_level_t)cpuid_config.values.ecx).level_number);

                return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
            }

            if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type != (uint32_t)LEVEL_TYPE_INVALID)
            {
                /* This is a valid leaf.  Checks that level type higher than the last one
                   (initialized to INVALID, which is 0) but does not reach the max.
                 */
                if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type <= prev_level_type ||
                    ((cpuid_topology_level_t)cpuid_config.values.ecx).level_type >= (uint32_t)LEVEL_TYPE_MAX)
                {
                    return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
                }

                /* Get the shift count.  Per the Intel SDM, this is the "number of
                   bits to shift right on x2APIC ID to get a unique topology ID of
                   the next level type.  All logical processors with the same next
                   level ID share current level."
                 */
                shift_count = ((cpuid_topology_shift_t)cpuid_config.values.eax).shift_count;

                if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type == LEVEL_TYPE_SMT)
                {
                    // For the SMT level, save the core (which is the next level) shift count
                    global_data_ptr->x2apic_core_id_shift_count = shift_count;
                }
                else if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type == LEVEL_TYPE_CORE)
                {
                    core_level_scanned = true;   // Prepare a flag for a sanity check later
                }
            }
            else
            {
                /* The current sub-leaf is invalid, it marks the end of topology info.
                   Make sure we had at least one valid sub-leaf, otherwise
                   CPUID leaf 1F is not supported.
                 */
                if (cpuid_config.leaf_subleaf.subleaf == CPUID_GET_TOPOLOGY_INVALID_SUBLEAF)
                {
                    return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, OPERAND_ID_RAX);
                }
                // Sanity check: core level must have been scanned.
                if (!core_level_scanned)
                {
                    return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, OPERAND_ID_RAX);
                }

                /* Check if this is the first invalid topology sub-leaf.  The shift count
                    saved from the previous level indicates the shift count for
                    getting the package number.
                 */
                if (prev_level_type != LEVEL_TYPE_INVALID)
                {

                    tdx_sanity_check(shift_count != (uint32_t)-1, FATAL_ERROR_ID_295, 6);
                    tdx_sanity_check(lpids_sharing_l3_cache != (uint32_t)-1, FATAL_ERROR_ID_296, 7);

                    /* This is the first invalid topology sub-leaf.  The shift count
                       saved from the previous level indicates the shift count for
                       getting the package number.
                     */
                    global_data_ptr->x2apic_pkg_id_shift_count = shift_count;

                    // Calculate the core ID mask
                    tdx_sanity_check((shift_count - global_data_ptr->x2apic_core_id_shift_count) < 32, FATAL_ERROR_ID_297, 8);
                    global_data_ptr->x2apic_core_id_mask = (uint32_t)(BIT(shift_count - global_data_ptr->x2apic_core_id_shift_count)) - 1U;

                    /* Verify that L3 cache is shared across package:
                       According to the Intel SDM description of CPUID leaf 4:
                       "The nearest power-of-2 integer that is not smaller than
                       (1 + EAX[25:14]) is the number of unique initial APIC IDs
                       reserved for addressing different logical processors sharing
                       this cache."
                       Thus, the value of lpids_sharing_l3_cache must fit within
                       shift_count bits, and its most significant bit must
                       be 1.
                     */
                    if ((lpids_sharing_l3_cache >> (shift_count - 1)) != (uint32_t)0x00000001)
                    {
                        TDX_ERROR("invalid wbinvd scope\n");
                        return TDX_INVALID_WBINVD_SCOPE;
                    }
                }
            }

            prev_level_type = ((cpuid_topology_level_t)cpuid_config.values.ecx).level_type;
        }
        else if (cpuid_config.leaf_subleaf.leaf == 0x23) // Extended Perfmon leaf
        {
            tdx_sanity_check(perfmon_ext_leaf_checked == true, FATAL_ERROR_ID_298, 9);

            if (perfmon_ext_leaf_supported)
            {
                if (cpuid_config.leaf_subleaf.subleaf == 0)
                {
                    leaf_eax.raw = cpuid_config.values.eax;
                    global_data_ptr->is_arch_pebs_supported = leaf_eax.leaf_5_supported;
                }
                else
                {
                    if ((leaf_eax.raw & (BIT(cpuid_config.leaf_subleaf.subleaf))) == 0)
                    {
                        // The CPU doesn't support this sub-leaf of 0x23
                        if (cpuid_config.values.low != 0 ||
                            cpuid_config.values.high != 0)
                        {
                            tdx_module_local_t *tdx_local_data_ptr = get_local_data();
                            tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                            tdx_local_data_ptr->vmm_regs.rdx = (uint64_t)-1; // mask low
                            tdx_local_data_ptr->vmm_regs.r8 = (uint64_t)-1;  // mask high
                            tdx_local_data_ptr->vmm_regs.r9 = 0x0;           // expected low
                            tdx_local_data_ptr->vmm_regs.r10 = 0x0;          // expected high
                            return TDX_INCORRECT_CPUID_VALUE;
                        }
                    }
                    else // Sub-leaf is supported by the CPU
                    {
                        if (cpuid_config.leaf_subleaf.subleaf == 1)
                        {
                            global_data_ptr->pmc_bitmap = cpuid_config.values.eax;
                            // EBX contains fixed counters bitmap, should be the same as the one derived above
                            if (cpuid_config.values.ebx != global_data_ptr->fc_bitmap)
                            {
                                tdx_module_local_t *tdx_local_data_ptr = get_local_data();

                                tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                                tdx_local_data_ptr->vmm_regs.rdx = 0xFFFFFFFF00000000;                        // mask low:  EBX bits 31:0
                                tdx_local_data_ptr->vmm_regs.r8 = 0x0;                                        // mask high
                                tdx_local_data_ptr->vmm_regs.r9 = (uint64_t)global_data_ptr->fc_bitmap << 32; // expected low
                                tdx_local_data_ptr->vmm_regs.r10 = 0x0;                                       // expected high

                                TDX_ERROR("ebx (=%llx) is not equal to FC bitmap (=%llx)", cpuid_config.values.ebx, global_data_ptr->fc_bitmap);

                                return TDX_INCORRECT_CPUID_VALUE;
                            }
                        }

                    }
                }
            }
            else
            {
                // The CPU doesn't support leaf 0x23, set the sampled values to 0
                cpuid_config.values.low = 0;
                cpuid_config.values.high = 0;
            }
        }
        else if (cpuid_config.leaf_subleaf.leaf == CPUID_GET_MAX_PA_LEAF)
        {
            // Get MAX_PA
            tdx_module_local_t *tdx_local_data_ptr = get_local_data();

            cpuid_80000008_eax_t cpuid_80000008_eax = { .raw = cpuid_config.values.eax };

            global_data_ptr->max_pa = cpuid_80000008_eax.pa_bits;
            tdx_sanity_check(global_data_ptr->max_pa <= 52, FATAL_ERROR_ID_299, 10);

            // Check that LA_BITS is compatible with LA57 from CPUID(7, 0).ECX[16]
            if (global_data_ptr->la57_supported)
            {
                if (cpuid_80000008_eax.la_bits != 57)
                {
                    tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                    tdx_local_data_ptr->vmm_regs.rdx = CPUID_MAXPA_EAX_MASK_LOW;
                    tdx_local_data_ptr->vmm_regs.r8  = CPUID_MAXPA_EAX_MASK_HIGH;
                    tdx_local_data_ptr->vmm_regs.r9  = CPUID_MAXPA_EAX_EXPECTED_LOW_57;
                    tdx_local_data_ptr->vmm_regs.r10 = CPUID_MAXPA_EAX_EXPECTED_HIGH;

                    TDX_ERROR("LA bits are not 57 - %d", cpuid_80000008_eax.la_bits);

                    return TDX_INCORRECT_CPUID_VALUE;
                }
            }
            else
            {
                if (cpuid_80000008_eax.la_bits != 48)
                {
                    tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
                    tdx_local_data_ptr->vmm_regs.rdx = CPUID_MAXPA_EAX_MASK_LOW;
                    tdx_local_data_ptr->vmm_regs.r8  = CPUID_MAXPA_EAX_MASK_HIGH;
                    tdx_local_data_ptr->vmm_regs.r9  = CPUID_MAXPA_EAX_EXPECTED_LOW_48;
                    tdx_local_data_ptr->vmm_regs.r10 = CPUID_MAXPA_EAX_EXPECTED_HIGH;

                    TDX_ERROR("LA bits are not 48 - %d", cpuid_80000008_eax.la_bits);

                    return TDX_INCORRECT_CPUID_VALUE;
                }
            }
        }

        global_data_ptr->cpuid_values[i] = cpuid_config;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ bool_t check_cmrs()
{
    /*----------------------------------------------------------------
      Defense-in-depth sanity check on the CMR list provided by MCHECK
      ----------------------------------------------------------------*/
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    uint64_t prev_cmr_area_start = 0;
    uint64_t prev_cmr_area_end = 0;


    for (uint32_t i = 0; i < MAX_CMR; i++)
    {
        if (sysinfo_table->cmr_data[i].cmr_size > 0)
        {
            if (!is_valid_integer_range(sysinfo_table->cmr_data[i].cmr_base,
                                        sysinfo_table->cmr_data[i].cmr_size))
            {
                return false;
            }

            uint64_t cmr_area_start = sysinfo_table->cmr_data[i].cmr_base;
            uint64_t cmr_area_end = sysinfo_table->cmr_data[i].cmr_base
                    + sysinfo_table->cmr_data[i].cmr_size-1;

            // CMR ranges should be within the boundaries of the physical address range.
            // taking into account MAX_PA and HKID partitioning (HKID bits must be 0).
            if ( ((cmr_area_start & tdx_global_data_ptr->hkid_mask) != 0) ||
                 ((cmr_area_end & tdx_global_data_ptr->hkid_mask) != 0) ||
                  (cmr_area_end > BIT(MAX_PA))
               )
            {
                return false;
            }

            // CMR range should be 4KB-aligned and range size should be a multiple of 4KB (range size is not required to be a power of two)
            if (!is_addr_aligned_any(cmr_area_start, _4KB) ||
                !is_addr_aligned_any(sysinfo_table->cmr_data[i].cmr_size,_4KB))
            {
                return false;
            }

            // CMR ranges must be ordered by a start address and must not overlap each other
            if (prev_cmr_area_end > 0 && (prev_cmr_area_start > cmr_area_start ||
                                          prev_cmr_area_end > cmr_area_start))
            {
                return false;
            }

            prev_cmr_area_start = cmr_area_start;
            prev_cmr_area_end = cmr_area_end;
        }

    }
    return true;
}

_STATIC_INLINE_ api_error_type check_msrs(tdx_module_global_t* tdx_global_data_ptr, bool_t* tsx_ctrl_modified_flag,
                                          ia32_tsx_ctrl_t* tsx_ctrl_original, ia32_tsx_ctrl_t* tsx_ctrl_modified)
{
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    // Sample and Check Capabilities MSRs
    msr_values_ptr->ia32_core_capabilities.raw = ia32_rdmsr(IA32_CORE_CAPABILITIES);

    msr_values_ptr->ia32_arch_capabilities.raw = ia32_rdmsr(IA32_ARCH_CAPABILITIES_MSR_ADDR);

    if (!check_native_ia32_arch_capabilities(msr_values_ptr->ia32_arch_capabilities))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_ARCH_CAPABILITIES_MSR_ADDR);
    }


        if (is_not_gnr_a0_stepping())
        {
            // Sanity Check of IA32_XAPIC_DISABLE_STATUS
            msr_values_ptr->ia32_xapic_disable_status.raw = ia32_rdmsr(IA32_XAPIC_DISABLE_STATUS_MSR_ADDR);
            if ((msr_values_ptr->ia32_xapic_disable_status.legacy_xapic_disabled != 1) ||
                (msr_values_ptr->ia32_xapic_disable_status.reserved != 0))
            {
                return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_XAPIC_DISABLE_STATUS_MSR_ADDR);
            }
        }

    if (msr_values_ptr->ia32_arch_capabilities.tsx_ctrl)
    {
    	tsx_ctrl_original->raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR);
        if (tsx_ctrl_original->tsx_cpuid_clear)
        {
            // TSX_CPUID_CLEAR forces CPUID(7,0).EBX bits 4 and 11 to 0.
            // In order to get their real values, clear this bit.
            // It will be restored later, after we sample CPUID.
            tsx_ctrl_modified->raw = tsx_ctrl_original->raw;
            tsx_ctrl_modified->tsx_cpuid_clear = 0;
            ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tsx_ctrl_modified->raw);
            *tsx_ctrl_modified_flag = true;
        }
    }

    msr_values_ptr->ia32_misc_package_ctls.raw = ia32_rdmsr(IA32_MISC_PACKAGE_CTLS_MSR_ADDR);
    if (!msr_values_ptr->ia32_misc_package_ctls.energy_filtering_enable)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_MISC_PACKAGE_CTLS_MSR_ADDR);
    }

    // Check Performance Monitoring - Support of IA32_A_PMC MSRs
    msr_values_ptr->ia32_perf_capabilities.raw = ia32_rdmsr(IA32_PERF_CAPABILITIES_MSR_ADDR);
    if ((msr_values_ptr->ia32_perf_capabilities.freeze_while_smm_supported != 1) ||
        (msr_values_ptr->ia32_perf_capabilities.full_write != 1))
    {
        TDX_ERROR("Check of IA32 PERF MSRs failed\n");
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_PERF_CAPABILITIES_MSR_ADDR);
    }


    /*--------------------------------------------
                  Time Stamp Counter
    --------------------------------------------*/
    // Sample IA32_TSC_ADJUST
    // This MSR should read the same value on all LP on TDSYSINITLP and during
    // TDX-SEAM operation on TDHVPENTER and other flows that rely on rdtsc.
    msr_values_ptr->ia32_tsc_adjust = ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR);

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_l2_vmx_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;
    td_vmcs_values_t* l2_vmcs_values_ptr = &tdx_global_data_ptr->l2_vmcs_values;

    if (!check_allowed_vmx_ctls(&l2_vmcs_values_ptr->pinbased_ctls, msr_values_ptr->ia32_vmx_true_pinbased_ctls,
            PINBASED_CTLS_L2_INIT, PINBASED_CTLS_L2_VARIABLE, PINBASED_CTLS_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    }

    if (!check_allowed_vmx_ctls(&l2_vmcs_values_ptr->procbased_ctls, msr_values_ptr->ia32_vmx_true_procbased_ctls,
            PROCBASED_CTLS_L2_INIT, PROCBASED_CTLS_L2_VARIABLE, PROCBASED_CTLS_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    }

    vmx_procbased_ctls2_t procbased_ctls2_init = { .raw = PROCBASED_CTLS2_L2_INIT };

    procbased_ctls2_init.en_guest_wait_pause = tdx_global_data_ptr->waitpkg_supported;
    vmx_procbased_ctls2_t procbased_ctls2_allowed1 = { .raw = msr_values_ptr->ia32_vmx_procbased_ctls2.allowed1 };
    if (!procbased_ctls2_allowed1.en_enclv_exiting)
    {
        procbased_ctls2_init.en_enclv_exiting = 0;
    }

    if (!check_allowed_vmx_ctls(&l2_vmcs_values_ptr->procbased_ctls2, msr_values_ptr->ia32_vmx_procbased_ctls2,
            (uint32_t)procbased_ctls2_init.raw, PROCBASED_CTLS2_L2_VARIABLE, PROCBASED_CTLS2_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    }

    vmx_procbased_ctls3_t procbased_ctls3_init = { .raw = PROCBASED_CTLS3_L2_INIT };

    vmx_procbased_ctls3_t procbased_ctls3_variable = { .raw = PROCBASED_CTLS3_L2_VARIABLE };
    // The L2 VMCS spreadsheet generates the VARIABLE mask for the VIRTUALIZE_IA32_SPEC_CTRL as 1,
    // however this bit is only set if the CPU supports it. Therefore don't check it.
    procbased_ctls3_variable.virt_ia32_spec_ctrl = 0;

    if (!is_not_gnr_a0_stepping())
    {
        procbased_ctls3_variable.raw &= (uint64_t)~0x80;
    }

    if (!check_allowed1_vmx_ctls(
        &l2_vmcs_values_ptr->procbased_ctls3,
        msr_values_ptr->ia32_vmx_procbased_ctls3.raw,
        (uint32_t)procbased_ctls3_init.raw,
        (uint32_t)procbased_ctls3_variable.raw,
        PROCBASED_CTLS3_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    }

    if (!check_allowed_vmx_ctls(&l2_vmcs_values_ptr->exit_ctls, msr_values_ptr->ia32_vmx_true_exit_ctls,
            EXIT_CTLS_L2_INIT, EXIT_CTLS_L2_VARIABLE, EXIT_CTLS_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    }

    vmx_vm_entry_ctls_t l2_variable_mask = {.raw = ENTRY_CTLS_L2_VARIABLE};
    // Remove the TD Telemetry bit(25) as the TDH.SYS.INIT should not fail if this bit is not supported although it is defined as variable
    l2_variable_mask.td_telemetry = 0;

    if (!check_allowed_vmx_ctls(&l2_vmcs_values_ptr->entry_ctls, msr_values_ptr->ia32_vmx_true_entry_ctls, ENTRY_CTLS_L2_INIT, l2_variable_mask.raw, ENTRY_CTLS_L2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    }

    ia32_cr0_t cr0_fixed0;
    cr0_fixed0.raw = msr_values_ptr->ia32_vmx_cr0_fixed0.raw;
    cr0_fixed0.pe = 0;
    cr0_fixed0.pg = 0;

    // CR0 checks for L2 don't depend on each TD configuration, thus they are done here
    if (!check_allowed64_vmx_ctls(cr0_fixed0.raw, msr_values_ptr->ia32_vmx_cr0_fixed1.raw,
                                  GUEST_CR0_L2_INIT, GUEST_CR0_L2_VARIABLE))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR0_FIXED0_MSR_ADDR);
    }

    // CR4 checks for L2 are only for the init values.
    // Actual variable bits mask depend on each TD configuration and is therefore calculated on TD init and import.
    if ((msr_values_ptr->ia32_vmx_cr4_fixed0.raw & (uint64_t)~GUEST_CR4_L2_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED0_MSR_ADDR);
    }

    if ((~msr_values_ptr->ia32_vmx_cr4_fixed1.raw & GUEST_CR4_L2_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED1_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_vmx_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    td_vmcs_values_t* td_vmcs_values_ptr = &tdx_global_data_ptr->td_vmcs_values;

    msr_values_ptr->ia32_vmx_basic.raw = ia32_rdmsr(IA32_VMX_BASIC_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_basic.vmcs_region_size > TD_VMCS_SIZE) ||
        (msr_values_ptr->ia32_vmx_basic.vmexit_info_on_ios != 1) ||
        (msr_values_ptr->ia32_vmx_basic.ia32_vmx_true_available != 1))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_BASIC_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_pinbased_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->pinbased_ctls, msr_values_ptr->ia32_vmx_true_pinbased_ctls,
            PINBASED_CTLS_INIT, PINBASED_CTLS_VARIABLE, PINBASED_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_procbased_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->procbased_ctls, msr_values_ptr->ia32_vmx_true_procbased_ctls,
            PROCBASED_CTLS_INIT, PROCBASED_CTLS_VARIABLE, PROCBASED_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    }

    /* procbased_ctls2 is a special case:
       - It depends on WAITPKG support.
       - It depends on the CPU support of ENCLV exiting
    */
    vmx_procbased_ctls2_t procbased_ctls2_init = {.raw = PROCBASED_CTLS2_INIT};
    procbased_ctls2_init.en_guest_wait_pause = tdx_global_data_ptr->waitpkg_supported;

    msr_values_ptr->ia32_vmx_procbased_ctls2.raw = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);

    vmx_procbased_ctls2_t procbased_ctls2_allowed1 = {.raw = msr_values_ptr->ia32_vmx_procbased_ctls2.allowed1};
    if (!procbased_ctls2_allowed1.en_enclv_exiting)
    {
        procbased_ctls2_init.en_enclv_exiting = 0;
    }

    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->procbased_ctls2, msr_values_ptr->ia32_vmx_procbased_ctls2,
            (uint32_t)procbased_ctls2_init.raw, PROCBASED_CTLS2_VARIABLE, PROCBASED_CTLS2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    }

    vmx_procbased_ctls3_t procbased_ctls3_init = {.raw = PROCBASED_CTLS3_INIT};

    msr_values_ptr->ia32_vmx_procbased_ctls3.raw = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
        // If the CPU supports DDPD, then it must support IA32_SPEC_CTRL virtualization
        if (tdx_global_data_ptr->ddpd_supported &&
            !msr_values_ptr->ia32_vmx_procbased_ctls3.virt_ia32_spec_ctrl)
        {
            return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
        }

    vmx_procbased_ctls3_t procbased_ctls3_variable = { .raw = PROCBASED_CTLS3_VARIABLE };
    // The TD VMCS spreadsheet generates the VARIABLE mask for the VIRTUALIZE_IA32_SPEC_CTRL as 1,
    // however this bit is only set if the CPU supports it. Therefore don't check it.
    procbased_ctls3_variable.virt_ia32_spec_ctrl = 0;

    if (!is_not_gnr_a0_stepping())
    {
        procbased_ctls3_variable.raw &= (uint64_t)~0x80;
    }

    if (!check_allowed1_vmx_ctls(
        &td_vmcs_values_ptr->procbased_ctls3,
        msr_values_ptr->ia32_vmx_procbased_ctls3.raw,
        (uint32_t)procbased_ctls3_init.raw,
        (uint32_t)procbased_ctls3_variable.raw,
        PROCBASED_CTLS3_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_exit_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);

    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->exit_ctls, msr_values_ptr->ia32_vmx_true_exit_ctls,
            EXIT_CTLS_INIT, EXIT_CTLS_VARIABLE, EXIT_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_entry_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);

    vmx_vm_entry_ctls_t variable_mask = {.raw = ENTRY_CTLS_VARIABLE};
    // Remove the TD Telemetry bit(25) as the TDH.SYS.INIT should not fail if this bit is not supported although it is defined as variable
    variable_mask.td_telemetry = 0;

    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->entry_ctls, msr_values_ptr->ia32_vmx_true_entry_ctls, ENTRY_CTLS_INIT, variable_mask.raw, ENTRY_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_misc.raw = ia32_rdmsr(IA32_VMX_MISC_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_misc.unrestricted_guest == 0) ||
        (msr_values_ptr->ia32_vmx_misc.activity_hlt == 0) ||
        (msr_values_ptr->ia32_vmx_misc.activity_shutdown == 0) ||
        (msr_values_ptr->ia32_vmx_misc.pt_in_vmx == 0) ||
        (msr_values_ptr->ia32_vmx_misc.max_cr3_targets < 4) ||
        (msr_values_ptr->ia32_vmx_misc.vmwrite_any_vmcs_field == 0))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_MISC_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_ept_vpid_cap = ia32_rdmsr(IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_ept_vpid_cap & IA32_VMX_EPT_VPID_CAP_MASK) != IA32_VMX_EPT_VPID_CAP_MASK)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    }

    ia32_cr0_t cr0_fixed0;
    cr0_fixed0.raw = ia32_rdmsr(IA32_VMX_CR0_FIXED0_MSR_ADDR);
    msr_values_ptr->ia32_vmx_cr0_fixed0.raw = cr0_fixed0.raw;
    cr0_fixed0.pe = 0;
    cr0_fixed0.pg = 0;
    if ((cr0_fixed0.raw & (uint64_t)~GUEST_CR0_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR0_FIXED0_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr0_fixed1.raw = ia32_rdmsr(IA32_VMX_CR0_FIXED1_MSR_ADDR);
    if ((~msr_values_ptr->ia32_vmx_cr0_fixed1.raw & GUEST_CR0_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR0_FIXED1_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr4_fixed0.raw = ia32_rdmsr(IA32_VMX_CR4_FIXED0_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_cr4_fixed0.raw & (uint64_t)~GUEST_CR4_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED0_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr4_fixed1.raw = ia32_rdmsr(IA32_VMX_CR4_FIXED1_MSR_ADDR);
    if ((~msr_values_ptr->ia32_vmx_cr4_fixed1.raw & GUEST_CR4_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED1_MSR_ADDR);
    }

    return check_l2_vmx_msrs(tdx_global_data_ptr);
}

_STATIC_INLINE_ api_error_type check_platform_config_and_cpu_enumeration(tdx_module_global_t* tdx_global_data_ptr,
                                                                         bool_t* tsx_ctrl_modified_flag,
                                                                         ia32_tsx_ctrl_t* tsx_ctrl_original,
                                                                         ia32_tsx_ctrl_t* tsx_ctrl_modified)
{

    api_error_type err;

    /*---------------------------------------------------
        Sample and Check MSR's
    ---------------------------------------------------*/
    if ((err = check_msrs(tdx_global_data_ptr, tsx_ctrl_modified_flag, tsx_ctrl_original, tsx_ctrl_modified)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of MSR's failed\n");
        return err;
    }

    /*------------------------------------------
      Sample and Check Native CPUID Values
      ------------------------------------------*/
    if ((err = check_cpuid_configurations(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("check_cpuid_configurations failure\n");
        return err;
    }

    /*------------------------------------------
      Sample and Check IA32_VMX_* MSRs
      ------------------------------------------*/
    if ((err = check_vmx_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of IA32 VMX MSRs failed\n");
        return err;
    }

    /*---------------------------------------------------
        Sample and Check Key Management Configuration
    ---------------------------------------------------*/
    if ((err = check_key_management_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of key management configuration failed\n");
        return err;
    }

    /*---------------------------------------------------
        Sanity check on CMR info provided by MCHECK
    ---------------------------------------------------*/
    if (!check_cmrs())
    {
        err = TDX_CMR_LIST_INVALID;
        return err;
    }

    /*---------------------------------------------------
        Check SMRRs and store in global data
    ---------------------------------------------------*/
    if ((err = check_and_store_smrr_smrr2(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("check_and_store_smrr_smrr2 failure\n");
        return err;
    }

    return TDX_SUCCESS;
}


_STATIC_INLINE_ void tdx_init_global_data(tdx_module_global_t* tdx_global_data_ptr)
{

    sysinfo_table_t* sysinfo_table_ptr = get_sysinfo_table();

    //NUM_LPS
    tdx_global_data_ptr->num_of_lps = sysinfo_table_ptr->mcheck_fields.tot_num_lps;

    //NUM_PKGS
    tdx_global_data_ptr->num_of_pkgs = sysinfo_table_ptr->mcheck_fields.tot_num_sockets;

    //NUM_INIT_PKGS
    tdx_global_data_ptr->num_of_init_pkgs = (uint32_t)0;

    tdx_global_data_ptr->pkg_config_bitmap = (uint32_t)0;

    tdx_global_data_ptr->num_of_init_lps = 0;

    tdx_global_data_ptr->global_state.sys_state = SYSINIT_DONE;

    // XBUF
    tdx_global_data_ptr->xbuf.xsave_header.xstate_bv = 0;
    tdx_global_data_ptr->xbuf.xsave_header.xcomp_bv = BIT(63);
    basic_memset_to_zero(&tdx_global_data_ptr->xbuf.xsave_header.reserved, sizeof(tdx_global_data_ptr->xbuf.xsave_header.reserved));

    tdx_global_data_ptr->tdx_io_supported = is_tdx_io_supported();

    // VMCS host fields
    save_vmcs_non_lp_host_fields(&tdx_global_data_ptr->seam_vmcs_host_values);

    tdx_global_data_ptr->num_rdseed_retries = 6;
    tdx_global_data_ptr->num_rdseed_pauses = 32;
    
    tdx_global_data_ptr->twenty_usec_in_tsc = translate_usec_to_tsc(USECOND * 20, (uint32_t)tdx_global_data_ptr->native_tsc_frequency);

    tdx_global_data_ptr->td_build_count = 0;
    tdx_global_data_ptr->mig_interrupted_count = 0;

}

_STATIC_INLINE_ api_error_type tdx_init_stack_canary(void)
{
    uint64_t canary;
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    if (!ia32_rdrand(&canary))
    {
        return TDX_RND_NO_ENTROPY;
    }

    for (uint64_t lp_num = 0; lp_num < get_num_addressable_lps(sysinfo_table); lp_num++)
    {
        get_other_lp_local_data(sysinfo_table, lp_num)->stack_canary = canary;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ bool_t is_td_preserving_available(seam_ops_capabilities_t caps)
{
    if ((caps.raw & TD_PRESERVING_CAPABILITIES) == TD_PRESERVING_CAPABILITIES)
    {
        return true;
    }

    return false;
}

_STATIC_INLINE_ api_error_type check_module_build_time_defs(tdx_module_global_t* tdx_global_data_ptr)
{
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    tdx_global_data_ptr->module_hv         = sysinfo_table->module_hv;
    tdx_global_data_ptr->min_update_hv     = sysinfo_table->min_update_hv;
    tdx_global_data_ptr->no_downgrade      = sysinfo_table->no_downgrade;
    tdx_global_data_ptr->num_handoff_pages = sysinfo_table->num_handoff_pages;

    if ((tdx_global_data_ptr->module_hv != MODULE_HV) ||
        (tdx_global_data_ptr->min_update_hv < MIN_UPDATE_HV) ||
        ((tdx_global_data_ptr->no_downgrade == 0) && (NO_DOWNGRADE == 1)) ||
        ((tdx_global_data_ptr->num_handoff_pages + 1) < TD_PRESERVING_HANDOFF_PAGE_COUNT))
    {
        TDX_ERROR("Incompatible TD preserving defs\n");
        return TDX_SYS_INCOMPATIBLE_SIGSTRUCT;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type configure_fatal_info_diagnostics(bool_t enable_configuration, fatal_error_config_t fatal_error_config)
{
    tdx_module_global_t* global_data = get_global_data();

    global_data->fatal_info_icr = 0;
    global_data->fatal_info_config_hpa = (uint64_t)(-1);

    if (enable_configuration)
    {
        if (fatal_error_config.reserved_0 || fatal_error_config.reserved_1)
        {
            TDX_ERROR("Reserved fields are not 0\n");
            return TDX_OPERAND_INVALID;
        }

        // check whether info logging should be configured
        if (fatal_error_config.fatal_info_hpa != HPA_CODE_NO_LOGGING_REQUIRED)
        {
            // check whether the configured HPA is valid
            if (TDX_SUCCESS == shared_hpa_check_with_pwr_2_alignment((pa_t)(fatal_error_config.raw & BITS(53, 0)), CACHELINE_SIZE))
            {
                // mark for tdh_sys_lp_init that logging is required
                global_data->fatal_info_config_hpa = fatal_error_config.raw & BITS(51, 6); // store only the hpa
            }
            else
            {
                // not a valid HPA
                TDX_ERROR("Fatal info HPA isn't valid, HPA = 0x%lx\n", fatal_error_config.fatal_info_hpa);
                return TDX_OPERAND_INVALID;
            }
        }

        // check whether a notification interrupt should be configured
        if (fatal_error_config.notification_intr)
        {
            ia32_apic_icr_t icr = { .raw = 0 };

            switch (fatal_error_config.notification_intr)
            {
            case 0x1: // interrupt
            {
                if (fatal_error_config.notification_vector < 16)
                {
                    // notification_vector must be in the range 16:255
                    TDX_ERROR("Illegal notification vecor = %d\n", fatal_error_config.notification_vector);
                    return TDX_OPERAND_INVALID;
                }

                icr.icr_low.delivery_mode = APIC_DELIVERY_FIXED;
                icr.icr_low.vector = fatal_error_config.notification_vector;
                break;
            }
            case 0x2: // NMI
            {
                icr.icr_low.delivery_mode = APIC_DELIVERY_NMI;
                icr.icr_low.vector = 2;
                break;
            }
            case 0x3: // SMI
            {
                icr.icr_low.delivery_mode = APIC_DELIVERY_SMI;
                icr.icr_low.vector = 0; // the vector is ignored
                break;
            }
            default:
            {
                // should not happen, currently there are only 3 types supported by fatal error diagnostics configuration
                TDX_ERROR("Unknown notification interrupt type = %d\n", fatal_error_config.notification_intr);
                return TDX_OPERAND_INVALID;
            }
            }

            icr.icr_low.destination_mode = 0; // physical
            icr.icr_low.level            = 1; // assert
            icr.icr_low.trigger_mode     = 0; // edge
            icr.icr_low.dest_shorthand   = 3; // all excluding self
            icr.raw_high                 = 0; // destination
            icr.icr_low.rsvd0            = 0;
            icr.icr_low.rsvd1            = 0;
            icr.icr_low.rsvd2            = 0;

            global_data->fatal_info_icr = icr.raw;
        }
    } // enable_configuration

    return TDX_SUCCESS;
}

__attribute__((no_stack_protector)) api_error_type tdh_sys_init(uint8_t version)
{
    bool_t global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t *tdx_local_data_ptr = get_local_data();
    api_error_type retval = TDX_SYS_BUSY;
    api_error_type err;

    ia32_tsx_ctrl_t tsx_ctrl_original = { .raw = 0 };
    ia32_tsx_ctrl_t tsx_ctrl_modified = { .raw = 0 };
    bool_t tsx_ctrl_modified_flag = false;

    td_param_attributes_t attributes_fixed0;
    td_param_attributes_t attributes_fixed1;

    uint64_t reserved_rcx = tdx_local_data_ptr->vmm_regs.rcx;
    uint64_t reserved_r8 = tdx_local_data_ptr->vmm_regs.r8;

    tdx_local_data_ptr->vmm_regs.rcx = 0;
    tdx_local_data_ptr->vmm_regs.rdx = 0;
    tdx_local_data_ptr->vmm_regs.r8 = 0;
    tdx_local_data_ptr->vmm_regs.r9 = 0;
    tdx_local_data_ptr->vmm_regs.r10 = 0;

    if (version > 1)
    {
        TDX_ERROR("version %d is not supported by TDH.SYS.INIT\n", version);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Acquire an exclusive lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_ex(&tdx_global_data_ptr->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_lock_acquired = true;

    // RCX should be reserved
    if (reserved_rcx != 0)
    {
        TDX_ERROR("RCX should be reserved\n");
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check the system state
    if (tdx_global_data_ptr->global_state.sys_state != SYSINIT_PENDING)
    {
        TDX_ERROR("Wrong sys_init state: %d\n", tdx_global_data_ptr->global_state.sys_state);
        retval = TDX_SYS_INIT_NOT_PENDING;
        goto EXIT;
    }

    if ((err = check_platform_config_and_cpu_enumeration(tdx_global_data_ptr, &tsx_ctrl_modified_flag,
                                                         &tsx_ctrl_original, &tsx_ctrl_modified))!= TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check and config CPU enumeration\n");
        retval = err;
        goto EXIT;
    }

    seam_ops_capabilities_t caps = {.raw = ia32_seamops_capabilities()};

    if (!is_td_preserving_available(caps))
    {
        TDX_ERROR("TD-preserving is not supported on the platform\n");
        retval = TDX_INCOMPATIBLE_SEAM_CAPABILITIES;
        goto EXIT;
    }

    tdx_global_data_ptr->seam_capabilities = caps;
    tdx_global_data_ptr->sealing_supported = caps.seamgetkey;
    // currently only 128-bit sealing keys are supported
    uint8_t sizes_bitmap = 0;
    if (caps.seamgetkey)
    {
        sizes_bitmap |= BIT(SEALKEY_SIZE_128_BIT);
    }
    tdx_global_data_ptr->sealing_supported_sizes_bitmap = sizes_bitmap;

    uint64_t seamdb_size;
    if ((err = check_module_build_time_defs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check module build time defs\n");
        retval = err;
        goto EXIT;
    }

    uint64_t result = ia32_seamops_seamdb_getref(&tdx_global_data_ptr->seamdb_index,
                                                 &tdx_global_data_ptr->seamdb_nonce,
                                                 &seamdb_size);

    tdx_sanity_check((result == SEAMOPS_SUCCESS), FATAL_ERROR_ID_300, 20);

    tdx_global_data_ptr->seamverifyreport_available = ((caps.raw & BIT(SEAMOPS_SEAMVERIFYREPORT_LEAF)) != 0);
    /*
     * Calculate allowed ATTRIBUTES bits.
     */
    attributes_fixed0.raw = TDX_ATTRIBUTES_FIXED0;
    attributes_fixed0.tpa = is_tdx_io_supported();
    attributes_fixed1.raw = TDX_ATTRIBUTES_FIXED1;

    if (!tdx_global_data_ptr->lass_supported)
    {
        attributes_fixed0.raw &= ~TDX_ATTRIBUTES_LASS_SUPPORT;
    }

    tdx_global_data_ptr->attributes_fixed0 = attributes_fixed0.raw;
    tdx_global_data_ptr->attributes_fixed1 = attributes_fixed1.raw;

    config_flags_t config_flags_fixed0 = { .raw = CONFIG_FLAGS_FIXED0 };
    config_flags_t config_flags_fixed1 = { .raw = CONFIG_FLAGS_FIXED1 };

    if(!tdx_global_data_ptr->sealing_supported)
    {
        config_flags_fixed0.sealing = 0;
    }

    if (tdx_global_data_ptr->max_pa <= 48)
    {
        config_flags_fixed1.gpaw = 0;
    }

    tdx_global_data_ptr->config_flags_fixed0.raw = config_flags_fixed0.raw;
    tdx_global_data_ptr->config_flags_fixed1.raw = config_flags_fixed1.raw;

    if (tdx_init_stack_canary() != TDX_SUCCESS)
    {
        retval = TDX_RND_NO_ENTROPY;
        goto EXIT;
    }

    if (TDX_SUCCESS != configure_fatal_info_diagnostics((bool_t)version, (fatal_error_config_t)reserved_r8))
    {
        TDX_ERROR("Illegal fatal info config input. fatal_config = 0x%lx\n", reserved_r8);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    tdx_init_global_data(tdx_global_data_ptr);

    retval = TDX_SUCCESS;

    EXIT:

    // Restore the original value of IA32_TSX_CTRL, if modified above
    if (tsx_ctrl_modified_flag)
    {
        ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tsx_ctrl_original.raw);
    }

    if (global_lock_acquired)
    {
        release_sharex_lock_ex(&tdx_global_data_ptr->global_lock);
    }
    return retval;
}
