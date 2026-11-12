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
 * @file tdh_mem_page_demote
 * @brief TDHMEMPAGEDEMOTE API handler
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
#include "helpers/mem_scan.h"

static void sept_split_entry(tdr_t* tdr_ptr, pa_t sept_page_pa, pa_t split_page_pa, ept_level_t split_page_level_entry,
                             ia32e_sept_t split_page_sept_entry_copy
                             , bool_t set_a_d_bits
                             )
{
    ALIGN(64) ia32e_sept_t sept_8_entries_chunk[8];
    ia32e_sept_t* sept_page_ptr;

    uint64_t page_size = ((split_page_level_entry == LVL_PDPT) ? _2MB : _4KB);
    sept_page_ptr = map_pa_with_hkid(sept_page_pa.raw_void,
                                     tdr_ptr->key_management_fields.hkid, TDX_RANGE_RW);

    for (uint32_t i = 0; i < NUM_CACHELINES_IN_PAGE; i++)
    {
        for (uint32_t j = 0; j < NUM_SEPT_ENTRIES_IN_CACHELINE; j++)
        {
            pa_t page_pa;
            page_pa.raw = split_page_pa.raw + (((i * 8) + j) * page_size);

            sept_8_entries_chunk[j] = split_page_sept_entry_copy;

            if (is_non_blocking_export_configured())
            {
                sept_8_entries_chunk[j].d = set_a_d_bits;
                sept_8_entries_chunk[j].a = set_a_d_bits;
            }

            sept_8_entries_chunk[j].base = page_pa.page_4k_num;
        }

        // Using MOVDIR64
        movdir64b((void*)sept_8_entries_chunk, (uint64_t)&sept_page_ptr[i*8]);
    }
    mfence();

    free_la(sept_page_ptr);
}

api_error_type tdh_mem_page_demote(page_info_api_input_t gpa_page_info,
                                   td_handle_and_flags_t target_tdr_and_flags,
                                   uint64_t pamt_hpa0,
                                   uint64_t pamt_hpa1)
{
    // Local data for return values
    tdx_module_local_t* local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa = { .raw = 0 };     // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t*               tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa = { .raw = 0 };          // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info;     // GPA and level
    ia32e_sept_t*         split_page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          split_page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           split_page_level_entry = gpa_mappings.level; // SEPT entry level of the page
    pa_t                  split_page_pa;
    pamt_entry_t*         split_page_pamt_entry_ptr = NULL; // Pointer to the to-be-split page PAMT entry
    bool_t                sept_locked_flag = false;         // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;        // Indicate SEPT entry is locked

    // New Secure-EPT page variables
    pa_t                  sept_page_pa[MAX_VMS];                     // Physical address of the new SEPT page
    pamt_walk_result_t    sept_page_pamt_walk_result[MAX_VMS];
    bool_t                sept_page_locked_flag[MAX_VMS] = { 0 };    // Indicate SEPT page is locked

    bool_t                unblock_required_flag = false;

    ia32e_sept_t* l2_sept_entry_ptr[MAX_VMS] = { 0 };

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.page_4k_num = target_tdr_and_flags.tdr_hpa_51_12;

    uint64_t original_rcx = local_data_ptr->vmm_regs.rcx;
    uint64_t original_rdx = local_data_ptr->vmm_regs.rdx;

    sept_page_pa[0].raw = local_data_ptr->vmm_regs.r8;
    sept_page_pa[1].raw = local_data_ptr->vmm_regs.r9;
    sept_page_pa[2].raw = local_data_ptr->vmm_regs.r10;
    sept_page_pa[3].raw = local_data_ptr->vmm_regs.r11;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check the TD handle in RDX
    if (target_tdr_and_flags.reserved_0 || target_tdr_and_flags.reserved_1)
    {
        TDX_ERROR("Input TD handle (0x%llx) is not valid\n", target_tdr_and_flags.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
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
        false, TDH_MEM_PAGE_DEMOTE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = check_td_for_export_mode(tdr_ptr, tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("TD state check for export mode failed - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PD, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Step #1:

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &split_page_sept_entry_ptr,
                                                      &split_page_level_entry,
                                                      &split_page_sept_entry_copy,
                                                      &sept_locked_flag,
                                                      false);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(split_page_sept_entry_copy, split_page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    /* 1308552267 - suppress check
        //TDX_IO_SUPPORT
        // Verify page mem_type is WB, fail otherwise
        if (split_page_sept_entry_copy.fields_4k.mt != MT_WB)
        {
            TDX_ERROR("Page memory type is not WB.\n");
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID,OPERAND_ID_RCX);
            goto EXIT;
        }
    */

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(split_page_sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(split_page_sept_entry_copy, split_page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    split_page_sept_entry_copy = *split_page_sept_entry_ptr;

    // Verify that the parent entry is leaf entry
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_DEMOTE_LEAF, split_page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(split_page_sept_entry_copy, split_page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("Not leaf entry, or not allowed in current SEPT entry - 0x%llx!\n", split_page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Clean INIT_COUNTER bits of PENDING pages
    sept_cleanup_if_pending(&split_page_sept_entry_copy, gpa_mappings.level);

    // Verify the TLB tacking of the blocked page has been completed
    split_page_pa.raw = leaf_ept_entry_to_hpa(split_page_sept_entry_copy, page_gpa.raw, split_page_level_entry);
    split_page_pamt_entry_ptr = pamt_implicit_get(split_page_pa, (page_size_t)split_page_level_entry);

    if (sept_state_is_tlb_tracking_required(split_page_sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(split_page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(split_page_sept_entry_copy, gpa_mappings.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
            TDX_ERROR("Demoted SEPT entry is not blocked - 0x%llx\n", split_page_sept_entry_copy.raw);
            goto EXIT;
        }

        return_val = is_tlb_and_iotlb_tracked(tdcs_ptr, split_page_pamt_entry_ptr->bepoch);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }

    }

    // Step #2:

    // At this point we know that either the SEPT entry is blocked, so that the guest TD is not running.
    // Therefore, we can assume that the guest TD will not modify the SEPT entry (including not acquiring its guest-side lock).

    return_val = check_and_lock_explicit_4k_private_hpa(sept_page_pa[0],
                                                         OPERAND_ID_R8,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_NDA,
                                                         &sept_page_pamt_walk_result[0],
                                                         &sept_page_locked_flag[0]);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new SEPT page - error = %llx\n", return_val);
        goto EXIT;
    }

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        // Check and lock the new L2 Secure EPT pages in PAMT.
        // - If a NULL_PA was provided, don't check & lock
        // - Else, ignore bit 63
        // - If L2_SEPT_ADD_MODE is SPARSE (1), do this only if there's an L2 alias.

        if (sept_page_pa[vm_id].raw == NULL_PA)
        {
            // No new SEPT page, this is only valid if no alias exists
            if (sept_state_is_aliased(split_page_sept_entry_copy, vm_id))
            {
                TDX_ERROR("No new SEPT page, this is only valid if no alias existse\n");
                return_val = api_error_with_operand_id(TDX_L2_SEPT_PAGE_NOT_PROVIDED, OPERAND_ID_R8 + vm_id);
                goto EXIT;
            }
        }
        else if ((!target_tdr_and_flags.l2_sept_add_mode) ||
            sept_state_is_aliased(split_page_sept_entry_copy, vm_id))
        {
            return_val = check_and_lock_explicit_4k_private_hpa((pa_t)(sept_page_pa[vm_id].raw & ~BIT(63)), // Ignore bit 63
                                                                OPERAND_ID_R8 + vm_id,
                                                                TDX_LOCK_EXCLUSIVE,
                                                                PT_NDA,
                                                                &sept_page_pamt_walk_result[vm_id],
                                                                &sept_page_locked_flag[vm_id]);

            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Failed to check/lock/map the new L2 (%d) SEPT page - error = %llx\n",
                    vm_id, return_val);
                goto EXIT;
            }
        }
        else
        {
            // Set bit 63 of the SEPT PA to indicate it is not used
            sept_page_pa[vm_id].raw |= BIT(63);
        }
    }

    // Step #3
    // Prepare the new L1 and L2 SEPT pages that will map the 512 small pages.
    // This can fail; in this case the new SEPT pages are modified but their PAMT entries are not yet updated.

    // Prepare the SEPT entry for the small pages:  non-blocked, non-locked
    if (sept_state_is_any_blocked(split_page_sept_entry_copy))
    {
        unblock_required_flag = true;
        sept_unblock(&split_page_sept_entry_copy);
    }

    // If the page state before the demote operation was MAPPED and a non-blocking export session is in the LIVE_EXPORT phase, set all the small pages Dirty bits.
    // Otherwise, it clears them.
    bool_t set_a_d_bits = ((is_non_blocking_export_configured()) &&
                           (tdcs_ptr->management_fields.op_state == OP_STATE_LIVE_EXPORT) &&
                           (is_sept_mapped(&split_page_sept_entry_copy)));

    sept_lock_release_local(&split_page_sept_entry_copy); // Local lock release

    // Split the L1 SEPT
    sept_split_entry(tdr_ptr, sept_page_pa[0], split_page_pa, split_page_level_entry, split_page_sept_entry_copy
        , set_a_d_bits
    );

    // Split the L2 SEPT
    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if ((sept_page_pa[vm_id].raw != NULL_PA) &&
            (!target_tdr_and_flags.l2_sept_add_mode || sept_state_is_aliased(split_page_sept_entry_copy, vm_id)))
        {
            // Check for a pending interrupt
            // Interruption is not restartable, no need to save state. We haven't committed anything yet.
            if (is_interrupt_pending_host_side())
            {
                TDX_ERROR("Pending interrupt identified\n");

                // Restore the original RCX and RDX values and terminate the flow
                local_data_ptr->vmm_regs.rcx = original_rcx;
                local_data_ptr->vmm_regs.rdx = original_rdx;
                return_val = TDX_INTERRUPTED_RESTARTABLE;
                goto EXIT;
            }
            return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &split_page_level_entry, &l2_sept_entry_ptr[vm_id]);
            if (return_val != TDX_SUCCESS)
            {
                return_val = api_error_with_l2_details(TDX_L2_SEPT_WALK_FAILED, vm_id, (uint16_t)split_page_level_entry);
                set_arch_l2_septe_details_in_vmm_regs(*l2_sept_entry_ptr[vm_id], vm_id,
                    tdcs_ptr->executions_ctl_fields.attributes.debug, split_page_level_entry, local_data_ptr);
                TDX_ERROR("Failed on L2 SEPT walk for VM %d\n", vm_id);
                goto EXIT;
            }

            if (sept_state_is_aliased(split_page_sept_entry_copy, vm_id))
            {
                // Prepare the L2 SEPT entry image for the small page.
                // If the page was blocked, it gets unblocked.
                // For L2, it means that if the page is not pending, the L2 entry gets unblocked.
                // Else, it remains blocked (L2 has a single blocked state that applies for pending too)
                ia32e_sept_t l2_sept_entry = *l2_sept_entry_ptr[vm_id];
                // If the page state before the demote operation was MAPPED and a non-blocking export session is in the LIVE_EXPORT phase,
                // set all the small pages Dirty bits. Otherwise, it clears them.
                set_a_d_bits = ((is_non_blocking_export_configured()) &&
                    (tdcs_ptr->management_fields.op_state == OP_STATE_LIVE_EXPORT) &&
                    (is_l2_sept_mapped(&l2_sept_entry)));
                if (unblock_required_flag && !sept_state_is_any_pending(split_page_sept_entry_copy))
                {
                    sept_l2_unblock(&l2_sept_entry);
                }

                // Map the L2 new Secure EPT page and fill it with small page SEPT entries
                sept_split_entry(tdr_ptr, sept_page_pa[vm_id], split_page_pa, split_page_level_entry,
                    l2_sept_entry
                    , set_a_d_bits
                );
            }
            else
            {
                // Map the new L2 secure EPT page and fill if with L2_SEPT_FREE entries
                ia32e_sept_t* l2_sept_page_ptr;
                l2_sept_page_ptr = map_pa_with_hkid(sept_page_pa[vm_id].raw_void,
                    tdr_ptr->key_management_fields.hkid, TDX_RANGE_RW);

                fill_area_cacheline(l2_sept_page_ptr, TDX_PAGE_SIZE_IN_BYTES, SEPTE_L2_INIT_VALUE);

                free_la(l2_sept_page_ptr);
            }
        }
    }

    // Step #4:
    // Split the PAMT of the demoted page

	// Check for a pending interrupt (required only if L2 VMs exist)
    // Interruption is not restartable, no need to save state. We haven't committed anything yet.
    if (tdcs_ptr->management_fields.num_l2_vms && is_interrupt_pending_host_side())
    {
        TDX_ERROR("Pending interrupt identified\n");
        // Restore the original RCX and RDX values and terminate the flow
        local_data_ptr->vmm_regs.rcx = original_rcx;
        local_data_ptr->vmm_regs.rdx = original_rdx;
        return_val = TDX_INTERRUPTED_RESTARTABLE;
        goto EXIT;
    }

    // Split PAMT of the demoted page
    if ((return_val = pamt_demote(split_page_pa, (page_size_t)split_page_level_entry,
        pamt_hpa0, pamt_hpa1)) != TDX_SUCCESS)
    {
        TDX_ERROR("Couldn't not split the destined page in PAMT\n");
        goto EXIT;
    }

    // Step #5:
    // Commit

    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    sept_set_mapped_non_leaf_given_hpa_with_hkid(split_page_sept_entry_ptr,
        set_hkid_to_pa(sept_page_pa[0], tdr_ptr->key_management_fields.hkid),
        true, true); // Keep locked

    if (unblock_required_flag)
    {
        if(!sept_state_is_any_pending(split_page_sept_entry_copy))
        {
            (void)_lock_xadd_64b(&tdcs_ptr->executions_ctl2_fields.blocked_count, (uint64_t)-(BIT(9 * split_page_level_entry)));
        }
        else
        {
            (void)_lock_xadd_64b(&tdcs_ptr->executions_ctl2_fields.pending_blocked_count, (uint64_t)-(BIT(9 * split_page_level_entry)));
	    }
	}

    // Update the new L1 Secure EPT page PAMT entry
    sept_page_pamt_walk_result[0].pamt_entry_p->owner = tdr_pa.page_4k_num;
    sept_page_pamt_walk_result[0].pamt_entry_p->pt = PT_EPT;
    pamt_inc_nl_page_count(sept_page_pamt_walk_result[0].pamt_walk_path_nl[PT_2MB]);
    // Increment TDR child count by 1 using atomic operation.
    (void)_lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, 1);

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if ((sept_page_pa[vm_id].raw != NULL_PA) &&
            (!target_tdr_and_flags.l2_sept_add_mode || sept_state_is_aliased(split_page_sept_entry_copy, vm_id)))
        {
            // Make the current L2 Secure EPT entry a non-leaf entry pointing the new Secure EPT page.
            sept_l2_set_mapped_non_leaf_given_hpa_and_hkid(l2_sept_entry_ptr[vm_id],
                                                           sept_page_pa[vm_id],
                                                           tdr_ptr->key_management_fields.hkid
                                                           , true, is_non_blocking_export_configured()
            );

            // Set the aliased flag in the L1 non-leaf SEPT entry (this is done as a locked operation)
            sept_set_aliased(split_page_sept_entry_ptr, (uint16_t)vm_id);

            // Update the new L2 Secure EPT page PAMT entry
            sept_page_pamt_walk_result[vm_id].pamt_entry_p->owner = tdr_pa.page_4k_num;
            sept_page_pamt_walk_result[vm_id].pamt_entry_p->pt = PT_EPT;
            pamt_inc_nl_page_count(sept_page_pamt_walk_result[vm_id].pamt_walk_path_nl[PT_2MB]);

            // Increment TDR child count by 1 using atomic operation.
            (void)_lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, 1);
        }
    }

    // Return the (possibly updated) L2 SEPT page HPA values
    local_data_ptr->vmm_regs.r9  = sept_page_pa[1].raw;
    local_data_ptr->vmm_regs.r10 = sept_page_pa[2].raw;
    local_data_ptr->vmm_regs.r11 = sept_page_pa[3].raw;

EXIT:

    // Release all acquired locks and free keyhole mappings
    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if (sept_page_locked_flag[vm_id])
        {
            pamt_unwalk(&sept_page_pamt_walk_result[vm_id]);
        }

        if (l2_sept_entry_ptr[vm_id] != NULL)
        {
            free_la(l2_sept_entry_ptr[vm_id]);
        }
    }

    if (septe_locked_flag)
    {
        sept_lock_release(split_page_sept_entry_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (split_page_sept_entry_ptr != NULL)
        {
            free_la(split_page_sept_entry_ptr);
        }
    }

    if (split_page_pamt_entry_ptr != NULL)
    {
        free_la(split_page_pamt_entry_ptr);
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
