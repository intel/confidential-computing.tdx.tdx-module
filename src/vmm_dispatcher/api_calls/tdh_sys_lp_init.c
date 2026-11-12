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
 * @file tdH_sys_lp_init.c
 * @brief TDHSYSLPINIT API handler
 */
#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER

#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/loader_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "tdxio/vtbar.h"
#include "tdxio/kcbar.h"
#include "helpers/smrrs.h"
#include "memory_handlers/keyhole_manager.h"
#include CPUID_CONFIGURATIONS_HEADER

_STATIC_INLINE_ api_error_type check_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    // Check Capabilities MSRs to have the same values as sampled during TDHSYSINIT

    if (ia32_rdmsr(IA32_CORE_CAPABILITIES) !=
            tdx_global_data_ptr->plt_common_config.ia32_core_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_CORE_CAPABILITIES);
    }

    if (ia32_rdmsr(IA32_ARCH_CAPABILITIES_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_arch_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_ARCH_CAPABILITIES_MSR_ADDR);
    }

    if (ia32_rdmsr(IA32_MISC_PACKAGE_CTLS_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_misc_package_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_MISC_PACKAGE_CTLS_MSR_ADDR);
    }


        if (is_not_gnr_a0_stepping())
        {
            if (ia32_rdmsr(IA32_XAPIC_DISABLE_STATUS_MSR_ADDR) !=
                tdx_global_data_ptr->plt_common_config.ia32_xapic_disable_status.raw)
            {
                return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_XAPIC_DISABLE_STATUS_MSR_ADDR);
            }
        }


    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_smrr_smrr2_config(tdx_module_global_t* tdx_global_data_ptr)
{
    ia32_mtrrcap_t local_mtrr_cap = {.raw = ia32_rdmsr(MTRR_CAP_MSR_ADDR)};

    if (local_mtrr_cap.raw != tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.raw)
    {
        TDX_ERROR("local MTRRCAP MSR mismatch with platform\n");
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, MTRR_CAP_MSR_ADDR);
    }

    smrr_mask_t tmp_smrr_mask;
    smrr_base_t tmp_smrr_base;

    //SMRR and SMRR2 must be configured the same on all LPs
    tmp_smrr_mask.raw = ia32_rdmsr(SMRR_MASK_MSR_ADDR);
    tmp_smrr_base.raw = ia32_rdmsr(SMRR_BASE_MSR_ADDR);

    if (tdx_global_data_ptr->plt_common_config.smrr[0].smrr_base.raw != tmp_smrr_base.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR_BASE_MSR_ADDR);
    }

    if (tdx_global_data_ptr->plt_common_config.smrr[0].smrr_mask.raw != tmp_smrr_mask.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR_MASK_MSR_ADDR);
    }

    if (get_sysinfo_table()->mcheck_fields.smrr2_not_supported == 0 && local_mtrr_cap.smrr2 != 0)
    {
        tmp_smrr_mask.raw = ia32_rdmsr(SMRR2_MASK_MSR_ADDR);
        tmp_smrr_base.raw = ia32_rdmsr(SMRR2_BASE_MSR_ADDR);


        if (tdx_global_data_ptr->plt_common_config.smrr[1].smrr_base.raw != tmp_smrr_base.raw)
        {
            return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR2_BASE_MSR_ADDR);
        }
        if (tdx_global_data_ptr->plt_common_config.smrr[1].smrr_mask.raw != tmp_smrr_mask.raw)
        {
            return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR2_MASK_MSR_ADDR);
        }

    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_cpuid_configuration(tdx_module_global_t* tdx_global_data_ptr,
                                                           tdx_module_local_t *tdx_local_data_ptr,
                                                           bool_t* tsx_ctrl_modified_flag,
                                                           ia32_tsx_ctrl_t* tsx_ctrl_original,
                                                           ia32_tsx_ctrl_t* tsx_ctrl_modified)
{

    //Check consistency with global configuration

    cpuid_config_t tmp_cpuid_config;
    cpuid_config_t tmp_verify_same_mask;
    cpuid_config_t pl_verify_same_mask;

    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

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

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_LIMIT_CPUID_MAXVAL_BIT ) != 0)
    {
        return TDX_LIMIT_CPUID_MAXVAL_SET;
    }

    uint32_t last_base_leaf, last_extended_leaf;
    uint32_t ebx, ecx, edx;

    /**
     * Read CPUID leaf 0 to get the last base leaf number.
     * Note that we support base leaf numbers higher than the CPU supports; for such leaf numbers
     * we virtualize the return values as all-0.  This is done later.
     */
    ia32_cpuid(CPUID_MAX_INPUT_VAL_LEAF, 0, &last_base_leaf, &ebx, &ecx, &edx);

    // Read CPUID leaf 0x80000000 to get the last extended leaf number
    ia32_cpuid(CPUID_MAX_EXTENDED_VAL_LEAF, 0, &last_extended_leaf, &ebx, &ecx, &edx);

    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        if (!cpuid_lookup[i].valid_entry)
        {
            continue;
        }

        tmp_cpuid_config.leaf_subleaf =
                cpuid_lookup[i].leaf_subleaf;

        if (tmp_cpuid_config.leaf_subleaf.leaf == 0x6 &&
            (!is_not_gnr_a0_stepping()))
        {
            continue;
        }

        /**
         * We may support base leaf numbers higher than the CPU supports; for such leaf numbers
         * CPUID is virtualized as 0 and there's no need to check vs. the valued sampled by TDH.SYS.INIT.
         */
        if ((tmp_cpuid_config.leaf_subleaf.leaf <= last_base_leaf) ||
            ((tmp_cpuid_config.leaf_subleaf.leaf >= CPUID_FIRST_EXTENDED_LEAF) &&
             (tmp_cpuid_config.leaf_subleaf.leaf <= last_extended_leaf)))
        {

            ia32_cpuid(tmp_cpuid_config.leaf_subleaf.leaf, tmp_cpuid_config.leaf_subleaf.subleaf,
                       &tmp_cpuid_config.values.eax, &tmp_cpuid_config.values.ebx,
                       &tmp_cpuid_config.values.ecx, &tmp_cpuid_config.values.edx);

            tmp_verify_same_mask.values.low = (tmp_cpuid_config.values.low & cpuid_lookup[i].verify_same.low);
            tmp_verify_same_mask.values.high = (tmp_cpuid_config.values.high & cpuid_lookup[i].verify_same.high);

            pl_verify_same_mask.values.low = (tdx_global_data_ptr->cpuid_values[i].values.low &
                                              cpuid_lookup[i].verify_same.low);
            pl_verify_same_mask.values.high = (tdx_global_data_ptr->cpuid_values[i].values.high &
                                               cpuid_lookup[i].verify_same.high);

            if (tmp_verify_same_mask.values.low != pl_verify_same_mask.values.low ||
                tmp_verify_same_mask.values.high != pl_verify_same_mask.values.high)
            {
                tdx_local_data_ptr->vmm_regs.rcx = tmp_cpuid_config.leaf_subleaf.raw;
                tdx_local_data_ptr->vmm_regs.rdx = cpuid_lookup[i].verify_same.low;
                tdx_local_data_ptr->vmm_regs.r8 = cpuid_lookup[i].verify_same.high;

                return TDX_INCONSISTENT_CPUID_FIELD;
            }

            /*------------------------------------------------------
            Special Handling of Selected CPUID Leaves/Sub-Leaves
            ------------------------------------------------------*/

            // Determine current core and package IDs.
            if ((tmp_cpuid_config.leaf_subleaf.leaf == CPUID_GET_TOPOLOGY_LEAF) &&
                (tmp_cpuid_config.leaf_subleaf.subleaf == 0))
            {
                tdx_local_data_ptr->lp_info.core =
                    (tmp_cpuid_config.values.edx >> tdx_global_data_ptr->x2apic_core_id_shift_count) &
                    tdx_global_data_ptr->x2apic_core_id_mask;
                tdx_local_data_ptr->lp_info.pkg =
                    (tmp_cpuid_config.values.edx >> tdx_global_data_ptr->x2apic_pkg_id_shift_count);

                // Sanity check
                if (tdx_local_data_ptr->lp_info.pkg >= MAX_PKGS)
                {
                    return api_error_with_operand_id(TDX_INVALID_PKG_ID, tdx_local_data_ptr->lp_info.pkg);
                }
            }
        }
    }

    // this is a WA for CWF. on DMR, this cpuid should exist in the lut.
    tmp_cpuid_config.leaf_subleaf.leaf = 0x23;
    tmp_cpuid_config.leaf_subleaf.subleaf = 5;
    ia32_cpuid(tmp_cpuid_config.leaf_subleaf.leaf, tmp_cpuid_config.leaf_subleaf.subleaf,
               &tmp_cpuid_config.values.eax, &tmp_cpuid_config.values.ebx,
               &tmp_cpuid_config.values.ecx, &tmp_cpuid_config.values.edx);

    // Save LP ARCH PEBS supported counter bitmaps
    tdx_local_data_ptr->arch_pebs_pmc_gp_cfg_c_bitmap = tmp_cpuid_config.values.eax;
    tdx_local_data_ptr->arch_pebs_pmc_fx_cfg_c_bitmap = tmp_cpuid_config.values.ecx;

    // Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_vmx_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    platform_common_config_t* pl_msr_values_ptr = &tdx_global_data_ptr->plt_common_config;
    uint64_t tmp_msr;

    tmp_msr = ia32_rdmsr(IA32_VMX_BASIC_MSR_ADDR);
    if (pl_msr_values_ptr->ia32_vmx_basic.raw != tmp_msr)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_BASIC_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_pinbased_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_procbased_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_procbased_ctls2.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_procbased_ctls3.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_exit_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_entry_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_MISC_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_misc.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_MISC_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_ept_vpid_cap)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_CR0_FIXED0_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr0_fixed0.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR0_FIXED0_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR0_FIXED1_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr0_fixed1.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR0_FIXED1_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR4_FIXED0_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr4_fixed0.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR4_FIXED0_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR4_FIXED1_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr4_fixed1.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR4_FIXED1_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_key_management_config(tdx_module_global_t* tdx_global_data_ptr)
{

    uint64_t tmp_msr;

    tmp_msr = ia32_rdmsr(IA32_TME_CAPABILITY_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_capability.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TME_CAPABILITY_MSR_ADDR);
    };

    tmp_msr = ia32_rdmsr(IA32_TME_ACTIVATE_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_activate.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TME_ACTIVATE_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);
    }

    /* Check consistency of number of cache sub-blocks for TDWBINVD.
       Implementation may choose to do these checks once per package.
    */
    tmp_msr = ia32_rdmsr(IA32_WBINVDP_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_WBINVDP_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_WBNOINVDP_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_WBNOINVDP_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_enumeration_and_compare_configuration(tdx_module_global_t* tdx_global_data_ptr,
                                                                           bool_t* tsx_ctrl_modified_flag,
                                                                           ia32_tsx_ctrl_t* tsx_ctrl_original,
                                                                           ia32_tsx_ctrl_t* tsx_ctrl_modified)
{

    tdx_module_local_t *tdx_local_data_ptr = get_local_data();
    api_error_type err;

    if ((err = check_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    if ((err = compare_cpuid_configuration(tdx_global_data_ptr, tdx_local_data_ptr, tsx_ctrl_modified_flag,
                                           tsx_ctrl_original, tsx_ctrl_modified)) != TDX_SUCCESS)
    {
        return err;
    }

    /**
     * Check SMRR valid and consistent
     */
    if ((err = check_smrr_smrr2_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    if ((err = compare_vmx_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    /*---------------------------------------------------
        Check Performance Monitoring
      ---------------------------------------------------*/
    if (ia32_rdmsr(IA32_PERF_CAPABILITIES_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_perf_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_PERF_CAPABILITIES_MSR_ADDR);
    }

    if ((err = compare_key_management_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ void map_fatal_info_pointer(void)
{
    tdx_module_global_t* global_data = get_global_data();
    tdx_module_local_t* local_data = get_local_data();

    // verify all checks in tdh_sys_init passed and the fatal error info mem should be mapped
    if ((uint64_t)(-1) != global_data->fatal_info_config_hpa)
    {
        local_data->fatal_info_p = (uint64_t*)map_pa((void*)global_data->fatal_info_config_hpa, TDX_RANGE_RW);
        local_data->fatal_error_mem_mapped = 1;
        zero_cacheline((void*)local_data->fatal_info_p);
    }
}

_STATIC_INLINE_ void increment_num_of_lps(tdx_module_global_t* tdx_global_data_ptr)
{
    (void)_lock_xadd_32b(&tdx_global_data_ptr->num_of_init_lps, 1);
}

_STATIC_INLINE_ void tdx_local_init(tdx_module_local_t* tdx_local_data_ptr,
        tdx_module_global_t* tdx_global_data_ptr)
{
    tdx_local_data_ptr->vp_ctx.active_vmcs = ACTIVE_VMCS_NONE;

    // Read the LP-dependant host state from the VMCS and store it locally
    uint64_t val;
    ia32_vmread(VMX_HOST_RSP_ENCODE, &val);
    tdx_local_data_ptr->host_rsp = val;

    ia32_vmread(VMX_HOST_SSP_ENCODE, &val);
    tdx_local_data_ptr->host_ssp = val;

    ia32_vmread(VMX_HOST_GS_BASE_ENCODE, &val);
    tdx_local_data_ptr->host_gs_base = val;

    tdx_local_data_ptr->lp_is_init = true;

    // Mark the current LP as initialized
    increment_num_of_lps(tdx_global_data_ptr);

    tdx_local_data_ptr->guest_rcx_on_td_entry = 0;
}

/**
 * @brief For each I/O stack with hiop_rp_bit_vector != 0 check the SMRR range doesn't overlap the following ranges:
 *          - MMIOH BASE  -- MMIOH_LIMIT range
 *          - MEMCFG BASE -- MEMCFG_LIMIT range
 *          - VTBAR_BASE  -- VTBAR_SIZE (64KB) range
 *          - KCBAR_ BASE -- KCBAR_SIZE (128KB) range
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t is_smrr_overlap_io_range(void)
{
    socket_io_info_t *socket_io_info_ptr = NULL;
    hiop_info_t *hiop_info_ptr = NULL;
    iommu_id_t iommu_id = {.raw = 0};

    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    if (!tdx_global_data_ptr->tdx_io_supported)
    {
        return false;
    }

    for (uint8_t socket_id = 0; socket_id < NUM_OF_SOCKETS; socket_id++)
    {
        iommu_id.socket_id = socket_id;
        socket_io_info_ptr = get_socket_io_info(iommu_id);

        for (uint8_t hiop_id = 0; hiop_id < NUM_OF_HIOPS; hiop_id++)
        {
            iommu_id.hiop_id = hiop_id;
            hiop_info_ptr = get_hiop_info(iommu_id, socket_io_info_ptr);

            if (hiop_info_ptr->hiop_rp_bit_vector == 0)
            {
                continue;
            }

            uint8_t smrr_count = 1;
            if (get_sysinfo_table()->mcheck_fields.smrr2_not_supported == 0 &&
                tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr2 != 0)
            {
                smrr_count++;
            }

            for (uint8_t smrr_idx = 0; smrr_idx < smrr_count; smrr_idx++)
            {
                if (!tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.vld)
                {
                    continue;
                }

                smrr_base_t smrr_base = {.raw = 0};
                smrr_base.base = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_base.base;

                smrr_mask_t smrr_mask = {.raw = 0};
                smrr_mask.mask = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.mask;
                const uint64_t smrr_size = mask_to_size(smrr_mask.raw);

                const uint64_t mmioh_size = hiop_info_ptr->hiop_mmioh_limit - hiop_info_ptr->hiop_mmioh_base;
                if (is_overlap(smrr_base.raw, smrr_size, hiop_info_ptr->hiop_mmioh_base, mmioh_size))
                {
                    TDX_ERROR("SMRR overlaps MMIOH range\n");
                    return true;
                }

                if (is_overlap(smrr_base.raw, smrr_size, hiop_info_ptr->hiop_mmcfg_base, MMCFG_RANGE_SIZE))
                {
                    TDX_ERROR("SMRR overlaps MMCFG range\n");
                    return true;
                }

                const uint64_t vtbar_pa = get_vtbar_pa(socket_io_info_ptr, hiop_info_ptr);
                if (is_overlap(smrr_base.raw, smrr_size, vtbar_pa, VTBAR_SIZE))
                {
                    TDX_ERROR("SMRR overlaps VTBAR range\n");
                    return true;
                }

                const uint64_t kcbar_pa = get_kcbar_pa(socket_io_info_ptr, hiop_info_ptr);
                if (is_overlap(smrr_base.raw, smrr_size, kcbar_pa, KCBAR_SIZE))
                {
                    TDX_ERROR("SMRR overlaps KCBAR range\n");
                    return true;
                }
            }
        }
    }
    return false;
}

api_error_type tdh_sys_lp_init(void)
{

    bool_t tmp_global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    api_error_type retval = TDX_SYS_BUSY;

    ia32_tsx_ctrl_t tsx_ctrl_original = { .raw = 0 };
    ia32_tsx_ctrl_t tsx_ctrl_modified = { .raw = 0 };
    bool_t tsx_ctrl_modified_flag = false;

    tdx_local_data_ptr->vmm_regs.rcx = 0ULL;
    tdx_local_data_ptr->vmm_regs.rdx = 0ULL;
    tdx_local_data_ptr->vmm_regs.r8 = 0ULL;

    if (acquire_sharex_lock_sh(&tdx_global_data_ptr->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock for LP\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    tmp_global_lock_acquired = true;

    if (tdx_global_data_ptr->global_state.sys_state != SYSINIT_DONE)
    {
        TDX_ERROR("Wrong sys_init state: %d\n", tdx_global_data_ptr->global_state.sys_state);
        retval = TDX_SYS_LP_INIT_NOT_PENDING;
        goto EXIT;
    }

    //Check current LP state
    if (tdx_local_data_ptr->lp_is_init)
    {
        TDX_ERROR("LP is already initialized\n");
        retval = TDX_SYS_LP_INIT_DONE;
        goto EXIT;
    }

    // Explicit LP-scope state initialization
    tdx_local_data_ptr->vp_ctx.last_tdvpr_pa.raw = NULL_PA;

    /* Do a global EPT flush.  This is required to guarantee security in case of
       a TDX-SEAM module update. */
    const ept_descriptor_t zero_descriptor = { 0 };
    ia32_invept(&zero_descriptor, INVEPT_GLOBAL);

    // Verify SEAM capabilities consistency
    seam_ops_capabilities_t caps = { .raw = ia32_seamops_capabilities() };

    if (tdx_global_data_ptr->seam_capabilities.raw != caps.raw)
    {
        TDX_ERROR("SEAM capabilities are inconsistent 0x%llx/0x%llx\n",
                tdx_global_data_ptr->seam_capabilities.raw, caps.raw);
        retval = TDX_INCOMPATIBLE_SEAM_CAPABILITIES;
        goto EXIT;
    }

    if ((retval = check_enumeration_and_compare_configuration(tdx_global_data_ptr, &tsx_ctrl_modified_flag,
                                                              &tsx_ctrl_original, &tsx_ctrl_modified)) != TDX_SUCCESS)
    {
        TDX_ERROR("comparing LP configuration with platform failed\n");
        goto EXIT;
    }

    // Initialize keyhole
    init_keyhole_state();

    // This check can only be done after initializing the keyhole
    if (is_smrr_overlap_io_range())
    {
        TDX_ERROR("SMRR %d overlaps IO range\n");
        tdx_local_data_ptr->lp_info.x2apic_id = 0;
        retval = TDX_SMRR_OVERLAPS_IO_RANGE;
        goto EXIT;
    }

    // ALL CHECKS SUCCEEDED:

    // map the fatal error info memory if needed - only after we initialize the keyhole
    map_fatal_info_pointer();

    tdx_local_init(tdx_local_data_ptr, tdx_global_data_ptr);

    retval = TDX_SUCCESS;
EXIT:

    // Restore the original value of IA32_TSX_CTRL, if modified above
    if (tsx_ctrl_modified_flag)
    {
        ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tsx_ctrl_original.raw);
    }

    if (tmp_global_lock_acquired)
    {
        release_sharex_lock_sh(&tdx_global_data_ptr->global_lock);
    }

    return retval;
}

