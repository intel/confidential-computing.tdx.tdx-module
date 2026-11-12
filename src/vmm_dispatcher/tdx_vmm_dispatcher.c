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
 * @file tdx_vmm_dispatcher.c
 * @brief VMM dispatcher and return sequence
 */
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_vmm_api_handlers.h"
#include "debug/tdx_debug.h"
#include "helpers/helpers.h"
#include "metadata_handlers/metadata_generic.h"


//TDX-IO New APIs
#include "data_structures/tdxio/tdisp_defs.h"
#include "tdxio/tdxio_vmm_api_handlers.h"

_STATIC_INLINE_ void mark_lp_as_busy(tdx_module_local_t* local_data)
{
    local_data->lp_is_busy = true;
}

_STATIC_INLINE_ void mark_lp_as_free(tdx_module_local_t* local_data)
{
    local_data->lp_is_busy = false;
}

_STATIC_INLINE_ void fast_return_to_vmm(tdx_module_local_t* local_data_ptr)
{
    advance_guest_rip();

    mark_lp_as_free(local_data_ptr);

    tdx_seamret_to_vmm(); // Restore GPRs and SEAMRET

    // Shouldn't reach here:
    tdx_arch_fatal_error(); // Use basic fatal error here, to not access local/global data
}

void tdx_vmm_dispatcher(void)
{
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Beginning of sensitive section to account for SYS_DISABLE system state
    //
    // ||||||||||||||||||||| DO NOT ADD ANY CODE BELOW ||||||||||||||||||||||
    //
    // If you still need to add something - follow these rules:
    //
    // - Do not use get_local_data()/get_io_system_info_table()/get_sysinfo_table()/get_global_data()
    //   in this section, or call any functions that use them!
    // - Do not use anything directly from the local data structure, except VMM regs!
    // - Do not use anything directly from the global data structure, except the system state!
    // - Don't do any pointer keyhole mappings!
    // - Do not access the handoff data!
    // - Do not call non-inline functions that will stack canary as it might get erased!
    // - Do not call any debug print functions!
    //

    // Use non-optimized getters here that don't use fast ref pointers
    // This is required to account for possible race with TDH.SYS.DISABLE
    sysinfo_table_t* sysinfo_table = calculate_sysinfo_table();
    tdx_module_global_t* global_data = calculate_global_data(sysinfo_table);
    tdx_module_local_t* local_data = calculate_local_data();

    // Get leaf code from RAX in local data (saved on entry)
    tdx_leaf_and_version_t leaf_opcode;
    leaf_opcode.raw = local_data->vmm_regs.rax;

    // Marking LP as busy ***MUST*** come before the SYS_DISABLE system state check
    mark_lp_as_busy(local_data);

    // Checking the SYS_DISABLE system state ***MUST*** come after marking LP as busy
    IF_RARE (SYS_DISABLE == global_data->global_state.sys_state)
    {
        IF_RARE (leaf_opcode.leaf != TDH_SYS_DISABLE_LEAF)
        {
            local_data->vmm_regs.rax = TDX_SYS_DISABLE;
            fast_return_to_vmm(local_data);
        }
        else
        {
            uint32_t current_lp_id = (uint32_t)get_current_thread_num(sysinfo_table, local_data);

            if (global_data->sys_disable_intr_state.working_lp != current_lp_id)
            {
                local_data->vmm_regs.rax = TDX_RESUME_LP_MISMATCH;
                fast_return_to_vmm(local_data);
            }
        }
    }

    //
    // End of sensitive section to account for SYS_DISABLE system state
    // |||||||||||||||||| DO NOT ADD ANY CODE ABOVE |||||||||||||||||||
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Must be done before accessing local/global data or sysinfo table through optimized data accessors
    init_data_fast_ref_ptrs(local_data);

    TDX_LOG("Module entry start\n");

    TDX_LOG("leaf_opcode = 0x%llx\n", leaf_opcode);


    vm_vmexit_exit_reason_t exit_reason;
    ia32_vmread(VMX_VM_EXIT_REASON_ENCODE, &exit_reason.raw);

    tdx_sanity_check(exit_reason.basic_reason == VMEXIT_REASON_SEAMCALL, FATAL_ERROR_ID_308, 2);

    bhb_drain_sequence(global_data);

    // Save IA32_SPEC_CTRL and set speculative execution variant 4 defense
    // using Speculative Store Bypass Disable (SSBD), which delays speculative
    // execution of a load until the addresses for all older stores are known.
    local_data->vmm_non_extended_state.ia32_spec_ctrl = ia32_rdmsr(IA32_SPEC_CTRL_MSR_ADDR);
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, GET_TDX_MODULE_IA32_SPEC_CTRL(), local_data->vmm_non_extended_state.ia32_spec_ctrl);

    // All IA32_DEBGCTL bits have been cleared by SEAMCALL.
    // Set IA32_DEBUGCTL.ENABLE_UNCORE_PMI to the VMM's value, all other bits remain 0.
    ia32_debugctl_t debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl.raw);
    local_data->ia32_debugctl_value.raw = 0;
    local_data->ia32_debugctl_value.en_uncore_pmi = debugctl.en_uncore_pmi;
    wrmsr_opt(IA32_DEBUGCTL_MSR_ADDR, local_data->ia32_debugctl_value.raw, debugctl.raw);

    ia32_core_capabilities_t core_capabilities;

    // If simplified LAM is supported, save & disable its state
    if (local_data->lp_is_init)
    {
        core_capabilities.raw = global_data->plt_common_config.ia32_core_capabilities.raw;
    }
    else
    {
        core_capabilities.raw = ia32_rdmsr(IA32_CORE_CAPABILITIES);
    }

    local_data->vmm_non_extended_state.ia32_lam_enable = 0;
    if (core_capabilities.lam_supported != 0)
    {
        local_data->vmm_non_extended_state.ia32_lam_enable = ia32_rdmsr(IA32_LAM_ENABLE_MSR_ADDR);
        if (local_data->vmm_non_extended_state.ia32_lam_enable != 0)
        {
            ia32_wrmsr(IA32_LAM_ENABLE_MSR_ADDR, 0);
        }
    }

    // Set bits 34:33 (IA32_FIXED_CTR1/2 enable) of the IA32_PERF_GLOBAL_CTRL MSR to the value of
    // bits 34:33 of the SEAM VMCS "Guest Perf Global Control" field, if needed.
    uint64_t tdx_module_perf_global_ctrl;
    ia32_vmread(VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, &tdx_module_perf_global_ctrl);

    tdx_module_perf_global_ctrl &= IA32_PERF_GLOBAL_CTRL_FIXED_CTR12_EN_MASK;

    if (local_data->vmm_ia32_perf_global_ctrl != tdx_module_perf_global_ctrl)
    {
        local_data->vmm_ia32_perf_global_ctrl = tdx_module_perf_global_ctrl;
        ia32_wrmsr(IA32_PERF_GLOBAL_CTRL_MSR_ADDR, tdx_module_perf_global_ctrl);
        ia32_vmwrite(VMX_HOST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, tdx_module_perf_global_ctrl);
    }

    if ((leaf_opcode.reserved0 != 0) || (leaf_opcode.reserved1 != 0))
    {
        TDX_ERROR("Leaf and version not supported 0x%llx\n", leaf_opcode.raw);
        // update RAX in local data with error code
        local_data->vmm_regs.rax = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    if (!is_valid_tdx_io_host_call(leaf_opcode))
    {
        TDX_ERROR("tdx_vmm_dispatcher - TDX-IO not supported, invalid leaf = %d\n", leaf_opcode);
        local_data->vmm_regs.rax = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Only a few functions have multiple versions
    if (leaf_opcode.version > 0)
    {
        switch (leaf_opcode.leaf)
        {
            case TDH_MEM_PAGE_PROMOTE_LEAF:
            case TDH_MEM_SEPT_ADD_LEAF:
            case TDH_MEM_SEPT_REMOVE_LEAF:
            case TDH_MNG_RD_LEAF:
            case TDH_VP_RD_LEAF:
            case TDH_VP_INIT_LEAF:
            case TDH_SYS_INIT_LEAF:
            case TDH_SYS_CONFIG_LEAF:
            case TDH_SYS_UPDATE_LEAF:
            case TDH_EXPORT_MEM_LEAF:
            case TDH_EXPORT_BLOCKW_LEAF:
            case TDH_EXPORT_RESTORE_LEAF:
            case TDH_IMPORT_MEM_LEAF:
            case TDH_MEM_SHARED_SEPT_WR_LEAF:
                break;
            default:
                TDX_ERROR("Version greater than zero not supported for current leaf 0x%llx\n", leaf_opcode.raw);
                // update RAX in local data with error code
                local_data->vmm_regs.rax = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
                goto EXIT;
        }
    }

    if ((SYS_SHUTDOWN == global_data->global_state.sys_state)
       )
    {
        if (leaf_opcode.leaf != TDH_SYS_LP_SHUTDOWN_LEAF)
        {
            TDX_ERROR("Module in shutdown state\n");
            // update RAX in local data with error code
            local_data->vmm_regs.rax = TDX_SYS_SHUTDOWN;
            goto EXIT;
        }
    }

    // Check if module is in ready state, if not
    // only some leaf functions are allowed to run
    if ((global_data->global_state.sys_state != SYS_READY)     &&
        (leaf_opcode.leaf != TDH_SYS_INFO_LEAF)                &&
        (leaf_opcode.leaf != TDH_SYS_RD_LEAF)                  &&
        (leaf_opcode.leaf != TDH_SYS_RDALL_LEAF)               &&
        (leaf_opcode.leaf != TDH_SYS_INIT_LEAF)                &&
        (leaf_opcode.leaf != TDH_SYS_LP_INIT_LEAF)             &&
        (leaf_opcode.leaf != TDH_SYS_CONFIG_LEAF)              &&
        (leaf_opcode.leaf != TDH_SYS_KEY_CONFIG_LEAF)          &&
        (leaf_opcode.leaf != TDH_SYS_LP_SHUTDOWN_LEAF)         &&
        (leaf_opcode.leaf != TDH_SYS_DISABLE_LEAF)             &&
        (leaf_opcode.leaf != TDH_SYS_UPDATE_LEAF)
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        && (leaf_opcode.leaf != TDDEBUGCONFIG_LEAF)
#endif // DEBUGFEATURE_TDX_DBG_TRACE
        )
    {
        TDX_ERROR("Module system not ready, can't execute leaf 0x%llx\n", leaf_opcode.leaf);
        // update RAX in local data with error code
        local_data->vmm_regs.rax = TDX_SYS_NOT_READY;
        goto EXIT;
    }

    // switch over leaf opcodes
    switch (leaf_opcode.leaf)
    {
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    case TDDEBUGCONFIG_LEAF:
    {
        local_data->vmm_regs.rax = td_debug_config(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx,
                                                   local_data->vmm_regs.r8);
        break;
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE
    case TDH_MNG_ADDCX_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_add_cx(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_PAGE_ADD_LEAF:
    {
        page_info_api_input_t gpa_page_info;
        gpa_page_info.raw = local_data->vmm_regs.rcx;
        local_data->vmm_regs.rax = tdh_mem_page_add(gpa_page_info,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8,
                                               local_data->vmm_regs.r9);
        break;
    }
    case TDH_MEM_SEPT_ADD_LEAF:
    {
        page_info_api_input_t sept_level_and_gpa;
        sept_level_and_gpa.raw = local_data->vmm_regs.rcx;

        td_handle_and_flags_t target_tdr_and_flags = { .raw = local_data->vmm_regs.rdx };

        local_data->vmm_regs.rax = tdh_mem_sept_add(sept_level_and_gpa,
                                                    target_tdr_and_flags,
                                                    local_data->vmm_regs.r8,
                                                    leaf_opcode.version);
        break;
    }
    case TDH_VP_ADDCX_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_addcx(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_PAGE_RELOCATE:
    {
        local_data->vmm_regs.rax = tdh_mem_page_relocate(local_data->vmm_regs.rcx,
                local_data->vmm_regs.rdx, local_data->vmm_regs.r8);

        break;
    }
    case TDH_MEM_PAGE_AUG_LEAF:
    {
        page_info_api_input_t gpa_page_info;
        gpa_page_info.raw = local_data->vmm_regs.rcx;
        local_data->vmm_regs.rax = tdh_mem_page_aug(gpa_page_info,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8);
        break;
    }
    case TDH_MEM_RANGE_BLOCK_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_range_block(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_KEY_CONFIG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_config(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_CREATE_LEAF:
    {
        hkid_api_input_t hkid_info;
        hkid_info.raw = local_data->vmm_regs.rdx;

        local_data->vmm_regs.rax = tdh_mng_create(local_data->vmm_regs.rcx, hkid_info);
        break;
    }
    case TDH_VP_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_create(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_init(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx, local_data->vmm_regs.r8);
        break;
    }
    case TDH_VP_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_init(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_rd(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx, leaf_opcode.version);
        break;
    }
    case TDH_MEM_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_rd(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_WR_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_wr(local_data->vmm_regs.rcx,
                                              local_data->vmm_regs.rdx,
                                              local_data->vmm_regs.r8,
                                              local_data->vmm_regs.r9);
        break;
    }
    case TDH_MEM_WR_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_wr(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx, local_data->vmm_regs.r8);
        break;
    }
    case TDH_MEM_PAGE_DEMOTE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        td_handle_and_flags_t target_tdr_and_flags = { .raw = local_data->vmm_regs.rdx };

        local_data->vmm_regs.rax = tdh_mem_page_demote(page_info, target_tdr_and_flags, local_data->vmm_regs.r12, local_data->vmm_regs.r13);
        break;
    }
    case TDH_VP_ENTER_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_enter(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MR_EXTEND_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mr_extend(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MR_FINALIZE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mr_finalize(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_VP_FLUSH_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_flush(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_VPFLUSHDONE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_vpflushdone(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_KEY_FREEID_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_freeid(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_PAGE_PROMOTE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_page_promote(page_info, local_data->vmm_regs.rdx, leaf_opcode.version);
        break;
    }
    case TDH_PHYMEM_PAGE_RDMD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_rdmd(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_SEPT_RD_LEAF:
    {
        page_info_api_input_t sept_page_info;
        sept_page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_sept_rd(sept_page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_VP_RD_LEAF:
    {
        md_field_id_t field_code = {.raw = local_data->vmm_regs.rdx};
        local_data->vmm_regs.rax = tdh_vp_rd(local_data->vmm_regs.rcx, field_code, leaf_opcode.version);
        break;
    }
    case TDH_MNG_KEY_RECLAIMID_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_reclaimid(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_PHYMEM_PAGE_RECLAIM_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_reclaim(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_PAGE_REMOVE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_page_remove(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_SEPT_REMOVE_LEAF:
    {
        page_info_api_input_t sept_page_info;
        sept_page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_sept_remove(sept_page_info, local_data->vmm_regs.rdx,
                                                       leaf_opcode.version);
        break;
    }
    case TDH_SYS_CONFIG_LEAF:
    {
        sys_config_options_t sysconfig_options;
        sysconfig_options.raw = local_data->vmm_regs.r8;

        local_data->vmm_regs.rax = tdh_sys_config(local_data->vmm_regs.rcx,
                                                  local_data->vmm_regs.rdx,
                                                  sysconfig_options,
                                                  (uint8_t)leaf_opcode.version,
                                                  local_data->vmm_regs.r9,
                                                  local_data->vmm_regs.r10);
        break;
    }
    case TDH_SYS_KEY_CONFIG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_key_config();
        break;
    }
    case TDH_SYS_DISABLE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_disable();
        break;
    }
    case TDH_SYS_INFO_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_info(local_data->vmm_regs.rcx,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8,
                                               local_data->vmm_regs.r9);
        break;
    }
    case TDH_SYS_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_init((uint8_t)leaf_opcode.version);
        break;
    }
    case TDH_SYS_RD_LEAF:
    {
        md_field_id_t field_code = {.raw = local_data->vmm_regs.rdx};
        local_data->vmm_regs.rax = tdh_sys_rd(field_code);
        break;
    }
    case TDH_SYS_LP_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_lp_init();
        break;
    }
    case TDH_SYS_TDMR_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_tdmr_init(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_SYS_RDALL_LEAF:
    {
        md_field_id_t field_code = {.raw = local_data->vmm_regs.r8};
        local_data->vmm_regs.rax = tdh_sys_rdall(local_data->vmm_regs.rdx, field_code);
        break;
    }
    case TDH_SYS_LP_SHUTDOWN_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_lp_shutdown();
        break;
    }
    case TDH_SYS_SHUTDOWN_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_shutdown(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_SYS_UPDATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_update((uint8_t)leaf_opcode.version, local_data->vmm_regs.r9, local_data->vmm_regs.r10);
        break;
    }
    case TDH_MEM_TRACK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_track(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_RANGE_UNBLOCK_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_range_unblock(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_PHYMEM_CACHE_WB_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_cache_wb(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_PHYMEM_PAGE_WBINVD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_wbinvd(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_VP_WR_LEAF:
    {
        md_field_id_t field_code = {.raw = local_data->vmm_regs.rdx};
        local_data->vmm_regs.rax = tdh_vp_wr(local_data->vmm_regs.rcx,
                                             field_code,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9);
        break;
    }
    case TDH_PHYMEM_PAMT_ADD_LEAF:
    {
        page_size_api_input_t page_info = { .raw = local_data->vmm_regs.rcx };

        local_data->vmm_regs.rax = tdh_phymem_pamt_add(page_info,
                                             local_data->vmm_regs.rdx,
                                             local_data->vmm_regs.r8);

        break;
    }
    case TDH_PHYMEM_PAMT_REMOVE_LEAF:
    {
        page_size_api_input_t page_info = { .raw = local_data->vmm_regs.rcx };

        local_data->vmm_regs.rax = tdh_phymem_pamt_remove(page_info);

        break;
    }
    case TDH_SERVTD_BIND_LEAF:
    {
            servtd_attributes_t servtd_attr = {.raw = local_data->vmm_regs.r10};
            local_data->vmm_regs.rax = tdh_servtd_bind(local_data->vmm_regs.rcx,
                                                 local_data->vmm_regs.rdx,
                                                 local_data->vmm_regs.r8,
                                                 local_data->vmm_regs.r9,
                                                 servtd_attr);
            break;
    }
    case TDH_SERVTD_PREBIND_LEAF:
    {
        servtd_attributes_t servtd_attr = {.raw = local_data->vmm_regs.r10};
        local_data->vmm_regs.rax = tdh_servtd_prebind(local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.rdx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             servtd_attr);
        break;
    }
    case TDH_EXPORT_ABORT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_abort(
                                         local_data->vmm_regs.rcx,
                                         local_data->vmm_regs.r8,
                                         local_data->vmm_regs.r10);

        break;
    }
    case TDH_EXPORT_BLOCKW_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_blockw((gpa_list_info_t)local_data->vmm_regs.rcx,
                                                     local_data->vmm_regs.rdx,
                                                     (uint8_t)leaf_opcode.version);

        break;
    }
    case TDH_EXPORT_RESTORE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_restore((gpa_list_info_t)local_data->vmm_regs.rcx,
                                                      local_data->vmm_regs.rdx,
                                                      (uint8_t)leaf_opcode.version);

        break;
    }
    case TDH_EXPORT_PAUSE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_pause(local_data->vmm_regs.rcx);

        break;
    }
    case TDH_EXPORT_TRACK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_track(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_EXPORT_STATE_IMMUTABLE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_state_immutable(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_EXPORT_STATE_TD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_state_td(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_EXPORT_STATE_VP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_state_vp(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_EXPORT_UNBLOCKW_LEAF:
    {
        local_data->vmm_regs.rax = tdh_export_unblockw(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.rdx);

        break;
    }
    case TDH_IMPORT_TRACK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_track(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_IMPORT_STATE_IMMUTABLE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_state_immutable(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_IMPORT_STATE_TD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_state_td(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_IMPORT_STATE_VP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_state_vp(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9,
                                             local_data->vmm_regs.r10);

        break;
    }
    case TDH_MIG_STREAM_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mig_stream_create(
                                             local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.rdx);
        break;
    }
    case TDH_IMPORT_ABORT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_abort(local_data->vmm_regs.rcx,
                                            local_data->vmm_regs.r8,
                                            local_data->vmm_regs.r10);

        break;
    }
    case TDH_IMPORT_COMMIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_commit(local_data->vmm_regs.rcx);

        break;
    }
    case TDH_IMPORT_END_LEAF:
    {
        local_data->vmm_regs.rax = tdh_import_end(local_data->vmm_regs.rcx);

        break;
    }
    case TDH_EXPORT_MEM_LEAF:
    {
        gpa_list_info_t gpa_list_info = { .raw = local_data->vmm_regs.rcx};
        local_data->vmm_regs.rax = tdh_export_mem(
                                            gpa_list_info,
                                            local_data->vmm_regs.rdx,
                                            local_data->vmm_regs.r8,
                                            local_data->vmm_regs.r9,
                                            local_data->vmm_regs.r10,
                                            local_data->vmm_regs.r11,
                                            local_data->vmm_regs.r12,
                                            (uint8_t)leaf_opcode.version);
        break;
    }
    case TDH_IMPORT_MEM_LEAF:
    {
        gpa_list_info_t gpa_list_info = { .raw = local_data->vmm_regs.rcx};
        local_data->vmm_regs.rax = tdh_import_mem(
                                            gpa_list_info,
                                            local_data->vmm_regs.rdx,
                                            local_data->vmm_regs.r8,
                                            local_data->vmm_regs.r9,
                                            local_data->vmm_regs.r10,
                                            local_data->vmm_regs.r11,
                                            local_data->vmm_regs.r12,
                                            local_data->vmm_regs.r13,
                                            (uint8_t)leaf_opcode.version);
        break;
    }
    case TDH_MEM_SCAN_RANGE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_scan_range(local_data->vmm_regs.rcx,
                                                      local_data->vmm_regs.rdx,
                                                      local_data->vmm_regs.r8,
                                                      local_data->vmm_regs.r9,
                                                      local_data->vmm_regs.r10,
                                                      local_data->vmm_regs.r11);
        break;
    }
    case TDH_MEM_SCAN_COMP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_scan_comp(local_data->vmm_regs.rcx,
                                                     local_data->vmm_regs.rdx,
                                                     local_data->vmm_regs.r8,
                                                     local_data->vmm_regs.r11);
        break;
    }
    case TDH_MEM_SCAN_CONFIG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_scan_config(local_data->vmm_regs.rcx,
                                                       local_data->vmm_regs.rdx,
                                                       local_data->vmm_regs.r8,
                                                       local_data->vmm_regs.r9,
                                                       local_data->vmm_regs.r10,
                                                       local_data->vmm_regs.r11);
        break;
    }
    case TDH_MEM_SCAN_RESET_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_scan_reset(local_data->vmm_regs.rdx);
        break;
    }

    case TDH_IOMMU_SETREG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_iommu_setreg((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              (iommu_register_id_e)local_data->vmm_regs.rdx,
                                              local_data->vmm_regs.r8);
        break;
    }
    case TDH_IOMMU_GETREG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_iommu_getreg(local_data->vmm_regs.rcx,
                                              (iommu_register_id_e)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_SPDM_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_spdm_create((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8);
        break;
    }
    case TDH_SPDM_DELETE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_spdm_delete((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              local_data->vmm_regs.rdx);
        break;
    }
    case TDH_IDE_STREAM_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_ide_stream_create((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              local_data->vmm_regs.rdx,
                                              (ide_stream_cfg_reg_t)local_data->vmm_regs.r8,
                                              (ide_stream_ctrl_reg_t)local_data->vmm_regs.r9,
                                              (rid_assoc_1_reg_t)local_data->vmm_regs.r10,
                                              (rid_assoc_2_reg_t)local_data->vmm_regs.r11,
                                              (ide_addr_assoc_1_reg_t)local_data->vmm_regs.r12,
                                              (ide_addr_assoc_2_reg_t)local_data->vmm_regs.r13,
                                              (ide_addr_assoc_3_reg_t)local_data->vmm_regs.r14,
                                              (pa_t)local_data->vmm_regs.r15);
        break;
    }
    case TDH_IDE_STREAM_BLOCK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_ide_stream_block((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              (stream_id_reg_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_IDE_STREAM_DELETE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_ide_stream_delete((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              (stream_id_reg_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_IDE_STREAM_IDEKMREQ_LEAF:
    {
        local_data->vmm_regs.rax = tdh_ide_stream_idekmreq((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              (stream_id_reg_t)local_data->vmm_regs.rdx,
                                              (ide_object_id_t)local_data->vmm_regs.r8,
                                              (ide_km_param_reg_t)local_data->vmm_regs.r9,
                                              local_data->vmm_regs.r10,
                                              (pa_t)local_data->vmm_regs.r11);
        break;
    }
    case TDH_IDE_STREAM_IDEKMRSP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_ide_stream_idekmrsp((iommu_id_reg_t)local_data->vmm_regs.rcx,
                                              (stream_id_reg_t)local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8);
        break;
    }
    case TDH_DEVIF_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_create((devif_id_t)local_data->vmm_regs.rcx,
                                              (pa_t)local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8,
                                              (pa_t)local_data->vmm_regs.r9,
                                              (pa_t)local_data->vmm_regs.r10);
        break;
    }
    case TDH_DEVIF_REMOVE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_remove((function_id_reg_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_DEVIF_REQUEST_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_request((function_id_reg_t)local_data->vmm_regs.rcx,
                                              (devif_req_in_t)local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8,
                                              local_data->vmm_regs.r9);
        break;
    }
    case TDH_DEVIF_RESPONSE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_response((function_id_reg_t)local_data->vmm_regs.rcx,
                                              (devif_rsp_in_t)local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8,
                                              local_data->vmm_regs.r9);
        break;
    }
    case TDH_DMAR_ADD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_dmar_add((dmar_idx_t)local_data->vmm_regs.rcx,
                                              local_data->vmm_regs.rdx,
                                              local_data->vmm_regs.r8,
                                              local_data->vmm_regs.r9,
                                              local_data->vmm_regs.r10,
                                              local_data->vmm_regs.r11,
                                              local_data->vmm_regs.r12,
                                              local_data->vmm_regs.r13,
                                              local_data->vmm_regs.r14);
        break;
    }
    case TDH_DMAR_BLOCK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_dmar_block((dmar_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_DMAR_READ_LEAF:
    {
        local_data->vmm_regs.rax = tdh_dmar_read((dmar_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_DMAR_REMOVE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_dmar_remove((dmar_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MMIO_MT_ADD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_mt_add((mmiomt_idx_t)local_data->vmm_regs.rcx,
                                              (pa_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MMIO_MT_SET_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_mt_set((mmiomt_idx_t)local_data->vmm_regs.rcx,
                                              (mmiomt_set_info_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MMIO_MT_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_mt_rd((mmiomt_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MMIO_MT_REMOVE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_mt_remove((mmiomt_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MMIO_MAP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_map((page_info_api_input_t)local_data->vmm_regs.rcx,
                                              (pa_t)local_data->vmm_regs.rdx,
                                              (pa_t)local_data->vmm_regs.r8);
        break;
    }
    case TDH_MMIO_BLOCK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_block((page_info_api_input_t)local_data->vmm_regs.rcx,
                                              (pa_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MMIO_UNMAP_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mmio_unmap((page_info_api_input_t)local_data->vmm_regs.rcx,
                                              (pa_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_IQ_INV_REQUEST_LEAF:
    {
        local_data->vmm_regs.rax = tdh_iq_inv_request((iommu_id_reg_t)local_data->vmm_regs.rcx,
                (inv_req_type_t) local_data->vmm_regs.rdx,
                local_data->vmm_regs.r8,
                local_data->vmm_regs.r9,
                local_data->vmm_regs.r10,
                local_data->vmm_regs.r11,
                local_data->vmm_regs.r12);
        break;
    }
    case TDH_IQ_INV_PROCESS_LEAF:
    {
        local_data->vmm_regs.rax = tdh_iq_inv_process((iommu_id_reg_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_SHARED_SEPT_WR_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_shared_sept_wr((page_info_api_input_t)local_data->vmm_regs.rcx,
                                                        (pa_t)local_data->vmm_regs.rdx,
                                                        (ia32e_sept_t)local_data->vmm_regs.r8,
                                                        (ia32e_sept_t)local_data->vmm_regs.r9,
                                                        (ia32e_sept_t)local_data->vmm_regs.r10,
                                                        (ia32e_sept_t)local_data->vmm_regs.r11,
                                                        leaf_opcode.version);
        break;
    }
    case TDH_DEVIF_MT_ADD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_mt_add((devifmt_idx_t)local_data->vmm_regs.rcx,
                                                        (pa_t)local_data->vmm_regs.rdx);
        break;
    }
    case TDH_DEVIF_MT_REMOVE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_mt_remove((devifmt_idx_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_DEVIF_MT_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_devif_mt_rd((devifmt_idx_t)local_data->vmm_regs.rcx);
        break;
    }


    default:
    {
        TDX_ERROR("tdx_vmm_dispatcher - TDX_OPERAND_INVALID - invalid leaf = %d\n", leaf_opcode);
        local_data->vmm_regs.rax = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        break;
    }
    }

    tdx_sanity_check(local_data->vmm_regs.rax != UNINITIALIZE_ERROR, FATAL_ERROR_ID_310, 1);

    restore_xcr0_and_avx_states(false);

EXIT:
    // No return after calling the post dispatching operations
    // Eventually call SEAMRET
    tdx_vmm_post_dispatching();
}


void tdx_vmm_post_dispatching(void)
{
    advance_guest_rip();

    tdx_module_local_t* local_data_ptr = get_local_data();

    // Restore IA32_SPEC_CTRL
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_spec_ctrl,
                                       GET_TDX_MODULE_IA32_SPEC_CTRL());

    // If simplified LAM was saved & disabled, restore its state
    if (local_data_ptr->vmm_non_extended_state.ia32_lam_enable != 0)
    {
        ia32_wrmsr(IA32_LAM_ENABLE_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_lam_enable);
    }

    mark_lp_as_free(local_data_ptr);

    // Check that we have no mapped keyholes left
    tdx_sanity_check(local_data_ptr->keyhole_state.total_ref_count - local_data_ptr->fatal_error_mem_mapped == 0, FATAL_ERROR_ID_311, 20);

    TDX_LOG("tdx_vmm_post_dispatching - preparing to do SEAMRET\n");


    tdx_seamret_to_vmm(); // Restore GPRs and SEAMRET

    // Shouldn't reach here:
    tdx_sanity_check(0, FATAL_ERROR_ID_312, 0);
}
