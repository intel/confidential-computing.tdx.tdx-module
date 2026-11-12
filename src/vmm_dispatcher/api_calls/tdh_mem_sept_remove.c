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
 * @file tdh_mem_sept_remove
 * @brief TDHMEMSEPTREMOVE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"


api_error_type tdh_mem_sept_remove(page_info_api_input_t gpa_page_info, uint64_t target_tdr_pa, uint64_t version)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa = {.raw = 0};        // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info; // GPA and level
    ia32e_sept_t        * sept_entry_ptr[MAX_VMS] = { 0 };        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached entry of the page
    ept_level_t           sept_level_entry = gpa_mappings.level; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;    // Indicate SEPT entry is locked

    // Removed Secure-EPT page
    pa_t                  removed_page_pa[MAX_VMS];
    pamt_entry_t        * removed_page_pamt_entry_ptr[MAX_VMS] = { 0 };
    pamt_non_leaf_entry_t* removed_page_pamt_nl_entry_ptr[MAX_VMS] = { 0 };
    bool_t                removed_page_pamt_locked_flag[MAX_VMS] = { 0 };
    ia32e_paging_table_t* removed_page_sept_page_ptr = NULL;

    api_error_type        return_val = UNINITIALIZE_ERROR;


    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    if (version > 0)
    {
        local_data_ptr->vmm_regs.r9  = NULL_PA;
        local_data_ptr->vmm_regs.r10 = NULL_PA;
        local_data_ptr->vmm_regs.r11 = NULL_PA;
    }

    // Only versions 0 and 1 are supported
    if (version > 1)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_walk_result,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_MEM_SEPT_REMOVE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (is_non_blocking_export_configured() && OP_STATE_PAUSED_EXPORT == tdcs_ptr->management_fields.op_state)
    {
        TDX_ERROR("TDH.MEM.SEPT.REMOVE is not allowed when the export is paused\n");
        return_val = api_error_with_operand_id(TDX_OP_STATE_INCORRECT,(uint64_t)tdcs_ptr->management_fields.op_state);
        goto EXIT;
    }

    return_val = check_td_for_export_mode(tdr_ptr, tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("TD state check for export mode failed - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PD, tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Step #1:
    // L1 SEPT tree walk and state checks

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &sept_entry_ptr[0],
                                                      &sept_level_entry,
                                                      &sept_entry_copy,
                                                      &sept_locked_flag,
                                                      false);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry
    return_val = sept_lock_acquire_host(sept_entry_ptr[0]);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry after being locked
    sept_entry_copy.raw = sept_entry_ptr[0]->raw;

    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_SEPT_REMOVE_LEAF, sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, gpa_mappings.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("TDH_MEM_SEPT_REMOVE_LEAF is not allowed in current SEPT entry state - 0x%llx\n", sept_entry_copy.raw);
        goto EXIT;
    }

    // Step #2:
    // Check and lock the new L1 and L2 SEPT physical pages.

    // Get removed page L1 SEPT HPA PAMT entry
    removed_page_pa[0].raw = (uint64_t)sept_entry_copy.base << IA32E_4K_PAGE_OFFSET;
    removed_page_pa[0] = set_hkid_to_pa(removed_page_pa[0], tdr_ptr->key_management_fields.hkid);

    if ((return_val = pamt_implicit_get_with_nl_entry_and_lock(removed_page_pa[0], PT_4KB,
                      TDX_LOCK_EXCLUSIVE,
                      &removed_page_pamt_entry_ptr[0],
                      &removed_page_pamt_nl_entry_ptr[0], false)) != TDX_SUCCESS)
    {
        TDX_ERROR("Can't acquire lock on removed page pamt entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    removed_page_pamt_locked_flag[0] = true;

    if (sept_state_is_tlb_tracking_required(sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, gpa_mappings.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
            TDX_ERROR("Removed SEPT entry is not blocked - 0x%llx\n", sept_entry_copy.raw);
            goto EXIT;
        }

        return_val = is_tlb_and_iotlb_tracked(tdcs_ptr, removed_page_pamt_entry_ptr[0]->bepoch);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Scan the Secure-EPT page to be removed, and verify all its entries are at
    // SEPT_FREE state.  Map the merged Secure-EPT page
    removed_page_sept_page_ptr = map_pa(removed_page_pa[0].raw_void, TDX_RANGE_RO);

    if (op_state_is_import_in_progress(tdcs_ptr->management_fields.op_state))
    {
        // If an import session is in progress, all entries must be FREE.
        for (uint32_t i = 0; i < 512; i++)
        {
            if (!is_sept_free(&removed_page_sept_page_ptr->sept[i]))
            {
                TDX_ERROR("SEPT entry [%d] is not FREE\n", i);
                return_val = api_error_with_operand_id(TDX_EPT_PAGE_NOT_FREE, OPERAND_ID_RCX);
                set_arch_septe_details_in_vmm_regs(sept_entry_copy, gpa_mappings.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
                goto EXIT;
            }
        }
    }
    else
    {
        // Else, all entries must be either FREE or REMOVED.
        for (uint32_t i = 0; i < 512; i++)
        {
            if (!sept_state_is_free_or_removed(removed_page_sept_page_ptr->sept[i]))
            {
                TDX_ERROR("SEPT entry [%d] is not FREE/REMOVED\n", i);
                return_val = api_error_with_operand_id(TDX_EPT_PAGE_NOT_FREE, OPERAND_ID_RCX);
                set_arch_septe_details_in_vmm_regs(sept_entry_copy, gpa_mappings.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
                goto EXIT;
            }
        }
    }

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (!sept_state_is_aliased(sept_entry_copy, vm_id))
        {
            continue;
        }

        // Walk the L2 SEPT tree to locate the parent entry for the removed SEPT page
        return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &sept_level_entry, &sept_entry_ptr[vm_id]);
        if (return_val != TDX_SUCCESS)
        {
            // Should not happen - no need to free the L2 SEPT PTR's
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_sept_td_handle(target_tdr_pa, vm_id, sept_level_entry, page_gpa.raw, *sept_entry_ptr[vm_id]);
            fatal_error(FATAL_ERROR_ID_15, FATAL_INFO_FORMAT_SEPT_TD_HANDLE_INFO, &extended_fatal_info);
        }

        if (is_l2_sept_free(sept_entry_ptr[vm_id]))
        {
            // Should not happen - no need to free the L2 SEPT PTR's
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_sept_td_handle(target_tdr_pa, vm_id, sept_level_entry, page_gpa.raw, *sept_entry_ptr[vm_id]);
            fatal_error(FATAL_ERROR_ID_16, FATAL_INFO_FORMAT_SEPT_TD_HANDLE_INFO, &extended_fatal_info);
        }

        // Get removed page HPA PAMT entry
        removed_page_pa[vm_id].raw = (uint64_t)sept_entry_ptr[vm_id]->base << IA32E_4K_PAGE_OFFSET;
        removed_page_pa[vm_id] = set_hkid_to_pa(removed_page_pa[vm_id], tdr_ptr->key_management_fields.hkid);

        // Get the PAMT node entry of the L2 SEPT page that will be removed, and lock it
        if ((return_val = pamt_implicit_get_with_nl_entry_and_lock(removed_page_pa[vm_id], PT_4KB,
                          TDX_LOCK_EXCLUSIVE,
                          &removed_page_pamt_entry_ptr[vm_id],
                          &removed_page_pamt_nl_entry_ptr[vm_id], false)) != TDX_SUCCESS)
        {
            TDX_ERROR("Can't acquire lock on L2 removed page pamt entry (VM %d)\n", vm_id);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }

        removed_page_pamt_locked_flag[vm_id] = true;
    }

    // Step #3:  Commit
    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    // the loop runs backwards in order to release lock on L2 before L1
    for (int16_t vm_id = (int16_t)tdcs_ptr->management_fields.num_l2_vms; vm_id >= 0; vm_id--)
    {
        if ((vm_id == 0) || sept_state_is_aliased(sept_entry_copy, (uint16_t)vm_id))
        {
            if (vm_id == 0)
            {
                atomically_update_sept_state_keep_tdhp(sept_entry_ptr[vm_id], SEPTE_INIT_VALUE);
            }
            else
            {
                atomic_mem_write_64b(&sept_entry_ptr[vm_id]->raw, SEPTE_L2_INIT_VALUE);
            }
            (void)_lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, (uint64_t)-1);
            removed_page_pamt_entry_ptr[vm_id]->pt = PT_NDA; // PT = PT_NDA, OWNER = 0

            if (vm_id > 0)
            {
                uint64_t hint = pamt_dec_nl_page_count_and_get_hint(removed_page_pamt_nl_entry_ptr[vm_id]);
                if (version > 0)
                {
                    local_data_ptr->vmm_regs.gprs[GPR_LIST_R9_INDEX + (vm_id - 1)] =
                            remove_hkid_from_pa(removed_page_pa[vm_id]).raw;
                    local_data_ptr->vmm_regs.gprs[GPR_LIST_R9_INDEX + (vm_id - 1)] |= hint;
                }
            }
        }
    }

    if (sept_state_is_any_blocked(sept_entry_copy))
    {
        (void)_lock_xadd_64b(&tdcs_ptr->executions_ctl2_fields.blocked_count, (uint64_t)-(BIT(9 * sept_level_entry)));
    }

    septe_locked_flag = false;

    // Update RCX with the removed page HPA
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(removed_page_pa[0]).raw;

    local_data_ptr->vmm_regs.rcx |= pamt_dec_nl_page_count_and_get_hint(removed_page_pamt_nl_entry_ptr[0]);

EXIT:

    // Release all acquired locks and free keyhole mappings
    if (septe_locked_flag)
    {
        sept_lock_release(sept_entry_ptr[0]);
    }

    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if (sept_entry_ptr[vm_id] != NULL)
        {
            free_la(sept_entry_ptr[vm_id]);
        }

        if (removed_page_pamt_locked_flag[vm_id])
        {
            pamt_implicit_release_lock(removed_page_pamt_entry_ptr[vm_id], TDX_LOCK_EXCLUSIVE);
        }

        if (removed_page_pamt_nl_entry_ptr[vm_id])
        {
            free_la(removed_page_pamt_nl_entry_ptr[vm_id]);
        }
    }

    if (removed_page_sept_page_ptr != NULL)
    {
        free_la(removed_page_sept_page_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_hp_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
    }

    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }

    return return_val;
}
