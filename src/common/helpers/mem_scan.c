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
 * @file mem_scan.c
 * @brief TDX mem_scan helpers file
 */


#include "helpers/migration.h"
#include "helpers/mem_scan.h"
#include "x86_defs/x86_defs.h"
#include SEPT_STATE_LOOKUP_HEADER
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"

static api_error_type lock_sept_entry(bool_t* sept_entry_locked_flag, ia32e_sept_t* sept_entry_ptr)
{
    // Lock the SEPT entry in memory
    if (!*sept_entry_locked_flag)
    {
        if (TDX_SUCCESS != sept_lock_acquire_host(sept_entry_ptr))
        {
            TDX_ERROR("Failed to acquire SEPT entry lock");
            return GPA_ENTRY_STATUS_SEPT_ENTRY_BUSY_HOST_PRIORITY;
        }
        *sept_entry_locked_flag = true;
    }

    return TDX_SUCCESS;
}

static void unlock_sept_entry(bool_t* sept_entry_locked_flag, ia32e_sept_t* sept_entry_ptr)
{
    // Unlock the SEPT entry.
    if (*sept_entry_locked_flag)
    {
        sept_lock_release(sept_entry_ptr);
        *sept_entry_locked_flag = false;
    }
}

static void update_bepoch(ia32e_sept_t* sept_entry_ptr, tdcs_t* tdcs_p, ept_level_t level)
{
    tdx_sanity_check((level <= LVL_PDPT), FATAL_ERROR_ID_100, 0);

    pa_t td_page_pa = { .raw = (sept_entry_ptr->raw & BITS(51, 12)) };
    pamt_entry_t* td_page_pamt_entry_ptr = pamt_implicit_get(td_page_pa, (page_size_t)level);
    tdx_sanity_check(NULL != td_page_pamt_entry_ptr, FATAL_ERROR_ID_381, 0);

    td_page_pamt_entry_ptr->bepoch.raw = tdcs_p->epoch_tracking.epoch_and_refcount.td_epoch;

    // Release all acquired locks
    free_la(td_page_pamt_entry_ptr);
}

api_error_type initialize_lists(gpa_list_info_t list_of_lists_info_hpa, lists_tracker_t* lists_tracker)
{
    // map the list of lists and initialize tracking variables
    lists_tracker->overall_last_entry = ((list_of_lists_info_hpa.last_entry + 1) * 512) - 1;
    lists_tracker->next_gpa_list_info_entry = (uint64_t)(lists_tracker->overall_next_entry >> BITS_NUM_IN_LIST_ENTRY);
    lists_tracker->next_gpa_list_entry = lists_tracker->overall_next_entry & BITS(BITS_NUM_IN_LIST_ENTRY - 1, 0);

    // map the GPA list info
    api_error_type return_val = check_and_map_gpa_list_info(list_of_lists_info_hpa, &lists_tracker->gpa_list_info_p);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("List of lists info is incorrect = 0x%llx\n", list_of_lists_info_hpa.raw);
        return api_error_with_operand_id(return_val, OPERAND_ID_RCX);
    }

    // validate the GPA list (ignore first_entry and last_entry)
    if ((lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].reserved_0) ||
        (GPA_LIST_FORMAT_GPA_ONLY != lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].format) ||
        (0 != lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].first_entry) ||
        (0 != lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].last_entry))
    {
        TDX_ERROR("GPA list is incorrect = 0x%llx\n", lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].raw);
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_INFO_ENTRY);
    }

    // map the GPA list
    pa_t gpa_list_pa = { .raw = 0 };
    gpa_list_pa.page_4k_num = lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].hpa;
    // Verify that the GPA list physical address is canonical and shared (it is aligned to 4KB by definition)
    return_val = shared_hpa_check(gpa_list_pa, _4KB);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("GPA list address is not canonical, shared or aligned on 4KB - gpa_list_pa = 0x%llx\n", gpa_list_pa.raw);
        return api_error_with_operand_id(return_val, OPERAND_ID_GPA_LIST_INFO_ENTRY);
    }

    lists_tracker->gpa_list_p = (gpa_list_entry_t*)map_pa(gpa_list_pa.raw_void, TDX_RANGE_RW);

    return TDX_SUCCESS;
}

void prepare_context_for_interrupt(mem_scan_context_entry_t* contexts_entry, uint64_t range_id, uint64_t curr_gpa, uint64_t end_gpa)
{
    // Save RANGE_ID
    contexts_entry->range_id = range_id;
    // Save CURRENT_GPA to the context's START_GPA.
    contexts_entry->start_gpa = (curr_gpa >> 12);
    // Save RANGE_END to the context's END_GPA.
    contexts_entry->end_gpa = end_gpa;
    // Set INTERRUPTED to indicate a valid context.
    contexts_entry->interrupted = 1;
}

api_error_type check_for_pending_interrupt(tdcs_t* tdcs_p,
                                           uint64_t* start_tsc,
                                           pa_t gpa,
                                           pa_t range_end_pa,
                                           mem_scan_context_entry_t* contexts_entry,
                                           scan_controls_t scan_controls)
{
    api_error_type return_val = TDX_SUCCESS;
    uint64_t end_tsc = ia32_rdtsc();

    if ((end_tsc - *start_tsc) > get_global_data()->twenty_usec_in_tsc)
    {
        if (is_interrupt_pending_host_side())
        {
            return_val = TDX_INTERRUPTED_RESUMABLE;
        }
        else if ((DCHECK != scan_controls.operation) && is_lock_hp_set(&tdcs_p->executions_ctl_fields.secure_ept_lock))
        {
            // If TDH.MEM_SCAN_RANGE detects that a concurrent function has failed to acquire an exclusive lock on the SEPT trees,
            // it may yield and return with a TDX_INTERRUPTED_BUSY status in RAX.
            return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
        }

        if (TDX_SUCCESS != return_val)
        {
            if (DCHECK == scan_controls.operation)
            {
                prepare_context_for_interrupt(contexts_entry, scan_controls.range_id, gpa.raw, range_end_pa.raw);
            }
        }
        else
        {
            // reset the count
            *start_tsc = end_tsc;
        }
    }

    return return_val;
}

static void advance_gpa_to_next_page(pa_t* gpa, ept_level_t level)
{
    // promote the GPA according to the page level
    uint64_t size = (_4KB << (9 * level));
    gpa->raw = (gpa->raw + size) & ~(size - 1);
}

api_error_type find_first_non_free_gpa(tdr_t* tdr_p,
                                       tdcs_t* tdcs_p,
                                       pa_t* gpa,
                                       ept_level_t current_lvl,
                                       ia32e_paging_table_t* root,
                                       pa_t end_gpa,
                                       scan_controls_t scan_controls,
                                       mem_scan_context_entry_t* contexts_entry,
                                       uint64_t* start_tsc)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // validate pointer
    tdx_sanity_check(((DSCAN == scan_controls.operation) || (EXPORT_RESTORE == scan_controls.operation)) && (NULL == contexts_entry) ||
                     (DCHECK == scan_controls.operation) && (NULL != contexts_entry), FATAL_ERROR_ID_20, 0);

    // scan all entries in the sept root
    for (uint32_t i = (uint32_t)get_ept_entry_idx(*gpa, current_lvl); (i < ENTRIES_NUM_IN_PAGE_TABLE) && (gpa->raw < end_gpa.raw); i++)
    {
        return_val = recursive_find_first_non_free_gpa(tdr_p, tdcs_p, gpa, current_lvl, root, end_gpa, scan_controls, contexts_entry, start_tsc);

        // If there was an error or we reached the end of the range, exit the loop
        if (UNINITIALIZE_ERROR != return_val)
        {
            break;
        }
    }

    return return_val;
}

api_error_type recursive_find_first_non_free_gpa(tdr_t* tdr_p,
                                                 tdcs_t* tdcs_p,
                                                 pa_t* gpa,
                                                 ept_level_t current_lvl,
                                                 ia32e_paging_table_t* root,
                                                 pa_t end_gpa,
                                                 scan_controls_t scan_controls,
                                                 mem_scan_context_entry_t* contexts_entry,
                                                 uint64_t* start_tsc)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    uint32_t entry_index = (uint32_t)get_ept_entry_idx(*gpa, current_lvl);

    if (is_sept_free(&root->sept[entry_index]))
    {
        advance_gpa_to_next_page(gpa, current_lvl);

        return UNINITIALIZE_ERROR;
    }

    if (is_secure_ept_leaf_entry(&root->sept[entry_index], false))
    {
        return TDX_SUCCESS;
    }

    if (is_sept_nl_blocked(&root->sept[entry_index]))
	{
		if (DSCAN == scan_controls.operation)
		{
            advance_gpa_to_next_page(gpa, current_lvl);

            return UNINITIALIZE_ERROR;
		}
        else if (EXPORT_RESTORE == scan_controls.operation)
        {
            gpa->raw &= ~((_4KB << (9 * current_lvl)) - 1);
            return TDX_GPA_RANGE_BLOCKED;
        }
        else
        {
			tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_FAILED;
            return TDX_MEM_SCAN_FAILED_BLOCKED_RANGE;
        }
	}

    // continue the scan if the current L1 SEPT entry is a mapped non-leaf entry (NL_MAPPED),
    // and either the non-leaf entry Dirty bit is 1, or TDCS.FIELD_SUPPORT_AT_INIT.NL_SEPT_DIRTY is 0.
    // otherwise, advance the GPA to the next page and go back to the previous level.
    if (!(is_sept_nl_mapped(&root->sept[entry_index]) &&
        ((is_sept_entry_dirty(&root->sept[entry_index])) ||
        !(tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_NL_SEPT_DIRTY)))))
    {
        advance_gpa_to_next_page(gpa, current_lvl);

        return UNINITIALIZE_ERROR;
    }

    tdx_sanity_check((current_lvl > LVL_PT) && (current_lvl <= LVL_PML5), FATAL_ERROR_ID_350, 0);
    current_lvl--;

    pa_t pt_pa = { .raw = root->sept[entry_index].raw & IA32E_PAGING_STRUCT_ADDR_MASK };
    ia32e_paging_table_t* pt = (ia32e_paging_table_t*)map_pa_with_hkid((void*)(pt_pa.full_pa), tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    // iterate starting from the index of the sub-tree entry
    for (uint32_t i = (uint32_t)get_ept_entry_idx(*gpa, current_lvl); (i < ENTRIES_NUM_IN_PAGE_TABLE) && (gpa->raw < end_gpa.raw); i++)
    {
        return_val = recursive_find_first_non_free_gpa(tdr_p, tdcs_p, gpa, current_lvl, pt, end_gpa, scan_controls, contexts_entry, start_tsc);

        // if the first non-free entry was found
        if (UNINITIALIZE_ERROR != return_val)
        {
            goto EXIT;
        }
    }

    // the algorithm reaches here only if non-free entry is yet to be found (return_val = UNINITIALIZE_ERROR)
    if (gpa->raw < end_gpa.raw)
    {
        // check for pending interrupt only if the scan is not done yet
        return_val = check_for_pending_interrupt(tdcs_p, start_tsc, *gpa, end_gpa, contexts_entry, scan_controls);
        if(TDX_SUCCESS == return_val)
        {
            return_val = UNINITIALIZE_ERROR;
        }
        else
        {
            TDX_ERROR("Pending interrupt identified\n");
        }
    }

EXIT:
    free_la(pt);
    return return_val;
}

static api_error_type update_gpa_list_ptr(pa_t current_gpa,
                                          pa_t range_end_gpa,
                                          lists_tracker_t* lists_tracker,
                                          mem_scan_context_entry_t* contexts_entry,
                                          scan_controls_t scan_controls)
{
    api_error_type return_val = TDX_SUCCESS;

    if (lists_tracker->is_gpa_list_updated)
    {
        // check if the list is full
		lists_tracker->overall_next_entry++;

        if (lists_tracker->overall_next_entry > lists_tracker->overall_last_entry)
        {
            // report LIST_FULL only if the scan is not finished
            if (current_gpa.raw < range_end_gpa.raw)
            {
                // If doing a comprehensive scan, save the current context in MEM_SCAN_CONTEXT[CONTEXT_ID]
                if (DCHECK == scan_controls.operation)
                {
                    prepare_context_for_interrupt(contexts_entry, scan_controls.range_id, current_gpa.raw, range_end_gpa.raw);
                }

                // Terminate with a TDX_INTERRUPTED_LIST_FULL status
                return_val = TDX_INTERRUPTED_LIST_FULL;
            }
        }
        else // update the indices to point to the next entries
        {
            lists_tracker->next_gpa_list_info_entry = (uint64_t)(lists_tracker->overall_next_entry >> BITS_NUM_IN_LIST_ENTRY);
            lists_tracker->next_gpa_list_entry = lists_tracker->overall_next_entry & BITS(BITS_NUM_IN_LIST_ENTRY - 1, 0);

            // If there are no more entries in the GPA list page
            if (0 == lists_tracker->next_gpa_list_entry)
            {
                // release previous (finished) gpa list pointer
                if (NULL != lists_tracker->gpa_list_p)
                {
                    free_la(lists_tracker->gpa_list_p);
                    lists_tracker->gpa_list_p = NULL;
                }

                pa_t gpa_list_pa = { .raw = 0 };
                gpa_list_pa.page_4k_num = lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].hpa;

                // format, first_entry and last_entry must be 0
                if ((lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].reserved_0) ||
                    (GPA_LIST_FORMAT_GPA_ONLY != lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].format) ||
                    (lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].first_entry) ||
                    (lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].last_entry) ||
                    (TDX_SUCCESS != shared_hpa_check(gpa_list_pa, _4KB)))
                {
                    TDX_ERROR("GPA list is incorrect = 0x%llx\n", lists_tracker->gpa_list_info_p[lists_tracker->next_gpa_list_info_entry].raw);
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_INFO_ENTRY);
                }

                // map the GPA list
                lists_tracker->gpa_list_p = (gpa_list_entry_t*)map_pa(gpa_list_pa.raw_void, TDX_RANGE_RW);
            }
        }

        lists_tracker->is_gpa_list_updated = false;
    }

    return return_val;
}

static void add_gpa_to_gpa_list_as_state(lists_tracker_t* lists_tracker, pa_t gpa, gpa_list_entry_state_e state, ept_level_t level, ia32e_sept_t sept_entry)
{
    tdx_sanity_check(level <= LVL_PDPT, FATAL_ERROR_ID_356, 0);
    lists_tracker->gpa_list_p[lists_tracker->next_gpa_list_entry].raw = gpa.raw & BITS(51, 12);
    lists_tracker->gpa_list_p[lists_tracker->next_gpa_list_entry].level = (level & 0x3);
    lists_tracker->gpa_list_p[lists_tracker->next_gpa_list_entry].pending = sept_state_is_any_pending(sept_entry);
    lists_tracker->gpa_list_p[lists_tracker->next_gpa_list_entry].state = state;
    lists_tracker->gpa_list_p[lists_tracker->next_gpa_list_entry].operation = GPA_ENTRY_OP_MIGRATE;
    lists_tracker->is_gpa_list_updated = true;
}

static api_error_type process_dcheck_operation(tdcs_t* tdcs_p,
                                               ia32e_paging_table_t** sept_roots,
                                               uint64_t entry_index,
                                               pa_t* gpa,
                                               ept_level_t level,
                                               mem_scan_qualifier_t qualifier,
                                               lists_tracker_t* lists_tracker,
                                               uint32_t* written_entries_count,
                                               mem_scan_context_entry_t* contexts_entry,
                                               uint64_t range_id,
                                               uint64_t end_gpa)
{
    api_error_type return_val = TDX_SUCCESS;
    bool_t is_entry_processed = false;
    bool_t sept_entry_locked_flag = false;
    ia32e_sept_t* sept_entry_ptr = &sept_roots[0]->sept[entry_index];

    do {
        if (is_sept_mapped(sept_entry_ptr) ||
            is_sept_pending(sept_entry_ptr))
        {
            // If QUALIFIER is EXPORT, add to GPA list as NOT_EXPORTED.
            if (MEM_SCAN_QUALIFIER_EXPORT == qualifier)
            {
                add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, NOT_EXPORTED, level, *sept_entry_ptr);
                (*written_entries_count)++;
            }

            is_entry_processed = true;
        }
        else if (is_sept_exported(sept_entry_ptr))
        {
            bool_t execute_operation = false;

            for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
            {
                // note: L2 entries are not necessarily exist
                if (sept_roots[vm_id])
                {
                    if (((0 == vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])) ||
                        ((vm_id > 0) && sept_state_is_aliased(sept_roots[0]->sept[entry_index], vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])))
                    {
                        // perform the operation only if "L1 or any L2 D bit is 1"
                        execute_operation = true;
                        break;
                    }
                }
            }

            if (execute_operation)
            {
                return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
                if (TDX_SUCCESS != return_val)
                {
                    // If tdh_mem_scan_comp fails to acquire a lock on SEPT entry, it returns with TDX_INTERRUPTED_BUSY
                    return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                    break;
                }

                // At this stage, the SEPT entry cannot be in a different state
                tdx_debug_assert(is_sept_exported(sept_entry_ptr));

                // Set EXPORTED_MODIFIED state
                sept_update_state(sept_entry_ptr, SEPT_STATE_EXPORTED_MODIFIED_MASK, true, true);

                unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

                // Atomically increment DIRTY_COUNT.
                (void)_lock_xadd_64b(&tdcs_p->migration_fields.dirty_count, 1);

                // Add to GPA list as EXPORTED_MODIFIED.
                add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_MODIFIED, level, *sept_entry_ptr);
                (*written_entries_count)++;
            }

            is_entry_processed = true;
        }
        else if (is_sept_exported_modified(sept_entry_ptr) ||
                 is_sept_pending_exported_modified(sept_entry_ptr))
        {
            // Add to GPA list as EXPORTED_MODIFIED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_MODIFIED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_exported_removed(sept_entry_ptr)
                 )
        {
            // Add to GPA list as EXPORTED_REMOVED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_REMOVED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_blocked(sept_entry_ptr) ||
                 is_sept_exported_blocked(sept_entry_ptr) ||
                 is_sept_pending_exported_blocked(sept_entry_ptr) ||
                 is_sept_pending_blocked(sept_entry_ptr))
        {
            // Set MEM_SCAN_STATUS = MEM_SCAN_FAILED
            tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_FAILED;

            // Abort the scan with a TDX_MEM_SCAN_FAILED_BLOCKED_RANGE status.
            return_val = TDX_MEM_SCAN_FAILED_BLOCKED_RANGE;
            is_entry_processed = true;
        }
        else if (is_sept_pending_exported(sept_entry_ptr))
        {
            is_entry_processed = true;
        }
        else
        {
            fatal_error(FATAL_ERROR_ID_383, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
    } while (!is_entry_processed);

    // Advance to next gpa only if entry is processed
    // This prevents skipping the GPA if the corresponding SEPT is locked
    if (is_entry_processed)
    {
        advance_gpa_to_next_page(gpa, level);
    }

    if (TDX_INTERRUPTED_BUSY == (return_val & BITS(63,32)))
    {
        prepare_context_for_interrupt(contexts_entry, range_id, gpa->raw, end_gpa);
    }

    unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

    return return_val;
}

static api_error_type process_dscan_operation(tdcs_t* tdcs_p,
                                              ia32e_paging_table_t** sept_roots,
                                              uint64_t entry_index,
                                              pa_t* gpa,
                                              ept_level_t level,
                                              mem_scan_qualifier_t qualifier,
                                              lists_tracker_t* lists_tracker,
                                              uint32_t* written_entries_count)
{
    api_error_type return_val = TDX_SUCCESS;
    bool_t is_entry_processed = false;
    bool_t sept_entry_locked_flag = false;
    ia32e_sept_t* sept_entry_ptr = &sept_roots[0]->sept[entry_index];
    // Note: For a DSCAN operation, TDH.MEM.SCAN.RANGE skips the busy SEPT entry.

    do {
        if (is_sept_mapped(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = TDX_SUCCESS;
                break;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_mapped(sept_entry_ptr))
            {
                continue;
            }

            // Clear L1 and any L2 D bits.
            for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
            {
                // note: L2 entries are not necessarily exist
                if (sept_roots[vm_id])
                {
                    if (((0 == vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])) ||
                        ((vm_id > 0) && sept_state_is_aliased(sept_roots[0]->sept[entry_index], vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])))
                    {
                        atomically_clear_d_bit(&sept_roots[vm_id]->sept[entry_index]);
                    }
                }
            }

            update_bepoch(sept_entry_ptr, tdcs_p, level);

            unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

            // If QUALIFIER is EXPORT, add to GPA list as NOT_EXPORTED.
            if (MEM_SCAN_QUALIFIER_EXPORT == qualifier)
            {
                add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, NOT_EXPORTED, level, *sept_entry_ptr);
                (*written_entries_count)++;
            }

            is_entry_processed = true;
        }
        else if (is_sept_exported(sept_entry_ptr))
        {
            bool_t execute_operation = false;

            for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
            {
                // note: L2 entries are not necessarily exist
                if (sept_roots[vm_id])
                {
                    if (((0 == vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])) ||
                        ((vm_id > 0) && sept_state_is_aliased(sept_roots[0]->sept[entry_index], vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])))
                    {
                        // perform the operation only if "L1 or any L2 D bit is 1"
                        execute_operation = true;
                        break;
                    }
                }
            }

            if (execute_operation)
            {
                return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
                if (TDX_SUCCESS != return_val)
                {
                    return_val = TDX_SUCCESS;
                    break;
                }

                // Recheck L1 state and D bits.  If state is still EXPORTED and L1 or any L2 D bit is 1, continue.  Else, process per the new SEPT state.
                execute_operation = false;
                for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
                {
                    // note: L2 entries are not necessarily exist
                    if (sept_roots[vm_id])
                    {
                        if (((0 == vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])) ||
                            ((vm_id > 0) && sept_state_is_aliased(sept_roots[0]->sept[entry_index], vm_id) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])))
                        {
                            // perform the operation only if "L1 or any L2 D bit is 1"
                            execute_operation = true;
                            break;
                        }
                    }
                }

                if (!is_sept_exported(sept_entry_ptr) || !execute_operation)
                {
                    continue;
                }

                // Set EXPORTED_MODIFIED state.
                sept_update_state(sept_entry_ptr, SEPT_STATE_EXPORTED_MODIFIED_MASK, false, true);

                // Clear L1 and any L2 D bits that were set.
                for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
                {
                    // note: L2 entries are not necessarily exist
                    if (sept_roots[vm_id])
                    {
                        if (is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index]))
                        {
                            atomically_clear_d_bit(&sept_roots[vm_id]->sept[entry_index]);
                        }
                    }
                }

                // Set BEPOCH in PAMT entry.
                update_bepoch(sept_entry_ptr, tdcs_p, level);

                unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

                // Atomically increment DIRTY_COUNT.
                (void)_lock_xadd_64b(&tdcs_p->migration_fields.dirty_count, 1);

                // Add to GPA list as EXPORTED_MODIFIED.
                add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_MODIFIED, level, *sept_entry_ptr);
                (*written_entries_count)++;
            }

            is_entry_processed = true;
        }
        else if (is_sept_exported_modified(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = TDX_SUCCESS;
                break;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_exported_modified(sept_entry_ptr))
            {
                continue;
            }

            bool_t is_dirty = false;

            // Clear L1 and any L2 D bits.
            for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
            {
                // note: L2 entries are not necessarily exist
                if (sept_roots[vm_id])
                {
                    if (is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index]))
                    {
                        is_dirty = true;
                        atomically_clear_d_bit(&sept_roots[vm_id]->sept[entry_index]);
                    }
                }
            }

            if (is_dirty)
            {
                update_bepoch(sept_entry_ptr, tdcs_p, level);
            }

            unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

            // Add to GPA list as EXPORTED_MODIFIED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_MODIFIED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_exported_blocked(sept_entry_ptr) ||
                 is_sept_pending_exported_blocked(sept_entry_ptr))
        {
            // Add to GPA list as EXPORTED_BLOCKED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_BLOCKED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_exported_removed(sept_entry_ptr)
            )
        {
            // Add to GPA list as EXPORTED_REMOVED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_REMOVED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_pending(sept_entry_ptr))
        {
            // If QUALIFIER is EXPORT, add to GPA list as NOT_EXPORTED.
            if (MEM_SCAN_QUALIFIER_EXPORT == qualifier)
            {
                add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, NOT_EXPORTED, level, *sept_entry_ptr);
                (*written_entries_count)++;
            }

            is_entry_processed = true;
        }
        else if (is_sept_pending_exported_modified(sept_entry_ptr))
        {
            // Add to GPA list as EXPORTED_MODIFIED.
            add_gpa_to_gpa_list_as_state(lists_tracker, *gpa, EXPORTED_MODIFIED, level, *sept_entry_ptr);
            (*written_entries_count)++;

            is_entry_processed = true;
        }
        else if (is_sept_blocked(sept_entry_ptr) ||
                 is_sept_pending_blocked(sept_entry_ptr) ||
                 is_sept_pending_exported(sept_entry_ptr))
        {
            is_entry_processed = true;
        }
        else
        {
            fatal_error(FATAL_ERROR_ID_384, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
    } while (!is_entry_processed);

    advance_gpa_to_next_page(gpa, level);

    unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

    return return_val;
}

static api_error_type process_export_restore_operation(tdcs_t* tdcs_p,
                                                       ia32e_paging_table_t** sept_roots,
                                                       uint64_t entry_index,
                                                       uint32_t* written_entries_count,
                                                       pa_t* gpa,
                                                       ept_level_t level)
{
    api_error_type return_val = TDX_SUCCESS;
    bool_t is_entry_processed = false;
    bool_t sept_entry_locked_flag = false;
    ia32e_sept_t* sept_entry_ptr = &sept_roots[0]->sept[entry_index];

    do {
        if (is_sept_exported(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_exported(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_MAPPED_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_exported_modified(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_exported_modified(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_MAPPED_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_exported_blocked(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_exported_blocked(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_BLOCKED_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_exported_removed(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_exported_removed(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            (void)_lock_xadd_64b(&tdcs_p->executions_ctl2_fields.mem_count, -(BIT(9 * level)));
            sept_update_state(sept_entry_ptr, SEPT_STATE_FREE_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_pending_exported(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_pending_exported(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_PEND_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_pending_exported_modified(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_pending_exported_modified(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_PEND_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_pending_exported_blocked(sept_entry_ptr))
        {
            return_val = lock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_SEPT_ENTRY);
                goto EXIT;
            }

            // Recheck L1 state.  If same as before, continue.  Else, process per the new SEPT state
            if (!is_sept_pending_exported_blocked(sept_entry_ptr))
            {
                continue;
            }

            // Atomically decrease MIG_COUNT.
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            sept_update_state(sept_entry_ptr, SEPT_STATE_PEND_BLOCKED_MASK, false, true);
            (*written_entries_count)++;
            is_entry_processed = true;
        }
        else if (is_sept_free(sept_entry_ptr))
        {
            // Atomically decrement TDCS.MEM_COUNT by 1, 512 or 5122 depending on the removed TD private page size (4KB, 2MB or 1GB, respectively).
            (void)_lock_xadd_64b(&(tdcs_p->executions_ctl2_fields.mem_count), -(BIT(9 * level)));
            is_entry_processed = true;
        }
        else if(is_sept_mapped(sept_entry_ptr) ||
                is_sept_blocked(sept_entry_ptr) ||
                is_sept_pending(sept_entry_ptr) ||
                is_sept_pending_blocked(sept_entry_ptr))
        {
            // Do nothing
            is_entry_processed = true;
        }
        else
        {
            fatal_error(FATAL_ERROR_ID_380, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
    } while (!is_entry_processed);

    advance_gpa_to_next_page(gpa, level);

EXIT:

    unlock_sept_entry(&sept_entry_locked_flag, sept_entry_ptr);

    return return_val;
}

api_error_type scan_sept_trees(tdr_t* tdr_p,
                               tdcs_t* tdcs_p,
                               ia32e_paging_table_t** sept_roots,
                               pa_t* gpa,
                               pa_t end_gpa,
                               ept_level_t current_lvl,
                               scan_controls_t scan_controls,
                               uint32_t* written_entries_count,
                               lists_tracker_t* lists_tracker,
                               mem_scan_context_entry_t* contexts_entry,
                               uint64_t* start_tsc)
{
    api_error_type return_val = TDX_SUCCESS;

    // validate pointer
    tdx_sanity_check(((DSCAN == scan_controls.operation) || (EXPORT_RESTORE == scan_controls.operation)) && (NULL == contexts_entry) ||
                     (DCHECK == scan_controls.operation) && (NULL != contexts_entry), FATAL_ERROR_ID_304, 0);

    // scan all entries in the sept root
    for (uint32_t i = (uint32_t)get_ept_entry_idx(*gpa, current_lvl); (i < ENTRIES_NUM_IN_PAGE_TABLE) && (gpa->raw < end_gpa.raw); i++)
    {
        return_val = recursive_scan_sept_trees(tdr_p,
                                               tdcs_p,
                                               sept_roots,
                                               gpa,
                                               end_gpa,
                                               current_lvl,
                                               scan_controls,
                                               written_entries_count,
                                               lists_tracker,
                                               contexts_entry,
                                               start_tsc);

        // If there was an error or we reached the end of the range, exit the loop
        if (TDX_SUCCESS != return_val)
        {
            break;
        }
    }

    return return_val;
}

api_error_type recursive_scan_sept_trees(tdr_t* tdr_p,
                                         tdcs_t* tdcs_p,
                                         ia32e_paging_table_t** sept_roots,
                                         pa_t* gpa,
                                         pa_t end_gpa,
                                         ept_level_t current_lvl,
                                         scan_controls_t scan_controls,
                                         uint32_t* written_entries_count,
                                         lists_tracker_t* lists_tracker,
                                         mem_scan_context_entry_t* contexts_entry,
                                         uint64_t* start_tsc)
{
    api_error_type return_val = TDX_SUCCESS;
    uint32_t entry_index = (uint32_t)get_ept_entry_idx(*gpa, current_lvl);
    ia32e_paging_table_t* sub_sept_roots[MAX_VMS] = { NULL };

    // in case of a leaf entry, process it and all of its' related L2 entries according to the operation and the SEPT state
    if (is_secure_ept_leaf_entry(&sept_roots[0]->sept[entry_index], false))
    {
        // TDX_LOG("GPA: 0x%llx, SEPT level: %d, sept entry index: %d.\n", gpa.raw, current_lvl, entry_index);
        switch (scan_controls.operation)
        {
        case DSCAN:
        {
            return process_dscan_operation(tdcs_p,
                                           sept_roots,
                                           entry_index,
                                           gpa,
                                           current_lvl,
                                           (mem_scan_qualifier_t)scan_controls.qualifier,
                                           lists_tracker,
                                           written_entries_count);
            break;
        }
        case DCHECK:
        {
            return process_dcheck_operation(tdcs_p,
                                            sept_roots,
                                            entry_index,
                                            gpa,
                                            current_lvl,
                                            (mem_scan_qualifier_t)scan_controls.qualifier,
                                            lists_tracker,
                                            written_entries_count,
                                            contexts_entry,
                                            scan_controls.range_id,
                                            end_gpa.raw);
            break;
        }
        case EXPORT_RESTORE:
        {
            return process_export_restore_operation(tdcs_p,
                                                    sept_roots,
                                                    entry_index,
                                                    written_entries_count,
                                                    gpa,
                                                    current_lvl);
            break;
        }
        default:
        {
            // should not happen, already checked before
            fatal_error(FATAL_ERROR_ID_346, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
        }
    }

	// if the current L1 SEPT entry is a blocked non-leaf entry (NL_BLOCKED), terminate with a TDX_MEM_SCAN_FAILED_BLOCKED_RANGE status.
	if (is_sept_nl_blocked(&sept_roots[0]->sept[entry_index]))
	{
		if (DSCAN == scan_controls.operation)
		{
            advance_gpa_to_next_page(gpa, current_lvl);

            return return_val;
		}
        else if (EXPORT_RESTORE == scan_controls.operation)
        {
            gpa->raw &= ~((_4KB << (9 * current_lvl)) - 1);
            return TDX_GPA_RANGE_BLOCKED;
        }
        else
        {
			tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_FAILED;
            return TDX_MEM_SCAN_FAILED_BLOCKED_RANGE;
        }
	}

    // continue the scan if the current L1 SEPT entry is a mapped non-leaf entry (NL_MAPPED),
    // and either the non-leaf entry Dirty bit is 1, or TDCS.FIELD_SUPPORT_AT_INIT.NL_SEPT_DIRTY is 0.
	// otherwise, advance the GPA to the next page and go back to the previous level.
    if (!(is_sept_nl_mapped(&sept_roots[0]->sept[entry_index]) &&
        ((is_sept_entry_dirty(&sept_roots[0]->sept[entry_index])) ||
        !(tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_NL_SEPT_DIRTY)))))
    {
        advance_gpa_to_next_page(gpa, current_lvl);

        return return_val;
    }

    tdx_sanity_check((current_lvl > LVL_PT) && (current_lvl <= LVL_PML5), FATAL_ERROR_ID_344, 0);

    // prepare to the next iteration
    // promote the level for the next scan layer
    current_lvl--;
    bool_t is_l1_dirty = false;
    // map the children SEPT entries. note: L2 children entries do not necessarily exist
    for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
    {
        if (sept_roots[vm_id])
        {
            if (((vm_id == 0) && is_sept_entry_dirty(&sept_roots[vm_id]->sept[entry_index])) ||
                ((vm_id > 0) && is_l1_dirty &&
                ((is_l2_sept_nl_mapped(&sept_roots[vm_id]->sept[entry_index])) && (sept_state_is_aliased(sept_roots[0]->sept[entry_index], vm_id)))) ||
                !(tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_NL_SEPT_DIRTY)))
            {
                if(vm_id == 0)
                {
                    is_l1_dirty = true;
                }

                pa_t pt_pa = { .raw = sept_roots[vm_id]->sept[entry_index].raw & IA32E_PAGING_STRUCT_ADDR_MASK };
                sub_sept_roots[vm_id] = (ia32e_paging_table_t*)map_pa_with_hkid((void*)(pt_pa.full_pa), tdr_p->key_management_fields.hkid, TDX_RANGE_RW);
            }
        }
    }

    // continue to scan all the sub SEPT trees
    // iterate starting from the index of the sub-tree entry
    for (uint32_t i = (uint32_t)get_ept_entry_idx(*gpa, current_lvl); (i < ENTRIES_NUM_IN_PAGE_TABLE) && (gpa->raw < end_gpa.raw); i++)
    {
        return_val = recursive_scan_sept_trees(tdr_p,
                                               tdcs_p,
                                               sub_sept_roots,
                                               gpa,
                                               end_gpa,
                                               current_lvl,
                                               scan_controls,
                                               written_entries_count,
                                               lists_tracker,
                                               contexts_entry,
                                               start_tsc);

        if (TDX_SUCCESS != return_val)
        {
            goto EXIT;
        }

        if ((DCHECK == scan_controls.operation) || (DSCAN == scan_controls.operation))
        {
            // promote entries in the gpa list or the list of lists
            return_val = update_gpa_list_ptr(*gpa,
                                             end_gpa,
                                             lists_tracker,
                                             contexts_entry,
                                             scan_controls);

            if (TDX_SUCCESS != return_val)
            {
                TDX_ERROR("GPA list is full\n");
                goto EXIT;
            }
        }
    }

    if (gpa->raw < end_gpa.raw)
    {
        // check for pending interrupt only if the scan is not done yet
        return_val = check_for_pending_interrupt(tdcs_p, start_tsc, *gpa, end_gpa, contexts_entry, scan_controls);
        if (TDX_SUCCESS != return_val)
        {
            TDX_ERROR("Pending interrupt identified\n");
        }
    }

EXIT:
    // release all mapped pointers
    for (uint8_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
    {
        if (sub_sept_roots[vm_id])
        {
            free_la(sub_sept_roots[vm_id]);
        }
    }

    return return_val;
}

api_error_type mem_scan_reset(tdcs_t* tdcs_p, bool_t is_reconfiguration)
{
    api_error_type return_val = TDX_SUCCESS;
    bool_t mem_scan_locked_flag = false;
    pa_t* cx_hpa_p[MAX_MEM_SCAN_CONFIG_PAGES] = { NULL };
    mem_scan_ranges_t* ranges_p = NULL;

    if (MEM_SCAN_INIT == tdcs_p->migration_fields.mem_scan_state)
    {
        // If memory scan has not been configured by TDH.MEM.SCAN.CONFIG (TDCS.MEM_SCAN_STATE is MEM_SCAN_INIT), there is nothing to do.  Return with a TDX_SUCCESS status
        return return_val;
    }

    if(!is_reconfiguration)
    {
        if (acquire_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_EXCLUSIVE, false) != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MEM_SCAN_STATE);
            TDX_ERROR("Failed to lock TDCS mem scan lock - error = %llx\n", return_val);
            goto EXIT;
        }
        mem_scan_locked_flag = true;
    }

    for (uint8_t i = 0; i < MEM_SCAN_CONFIG_PAGES; i++)
    {
        // Check, lock and map the new cx pages
        cx_hpa_p[i] = map_pa((void*)(tdcs_p->migration_fields.mem_scan_control_page_hpas[i]), TDX_RANGE_RW);
    }

    ranges_p = (mem_scan_ranges_t*)cx_hpa_p[RANGES_PAGE_INDEX];

    // note: the dummy range should not be reset
    for (uint8_t i = 0; i < tdcs_p->migration_fields.num_mem_scan_ranges - 1; i++)
    {
        ranges_p[i].thread_count = 0;
        // Set NEXT_SUB_RANGE to RANGE_START.
        ranges_p[i].next_sub_range = (uint64_t)(ranges_p[i].range_start) << 21;
        // no need to update the last ranges entry
    }

    // Clear INTERRUPTED (or simply clear the whole context structure).
    basic_memset_to_zero((void*)cx_hpa_p[CONTEXTS_PAGE_INDEX], TDX_PAGE_SIZE_IN_BYTES);

    if(!is_reconfiguration)
    {
        // Set TDCS. NUM_MEM_SCAN_RANGES_COMPLETED to 0
        tdcs_p->migration_fields.num_mem_scan_ranges_completed = 0;

        // Set MEM_SCAN_STATE to MEM_SCAN_READY.
        tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_READY;
    }

EXIT:
    // Release all acquired locks
    for (uint8_t i = 0; i < MAX_MEM_SCAN_CONFIG_PAGES; i++)
    {
        if (cx_hpa_p[i])
        {
            free_la(cx_hpa_p[i]);
        }
    }

    if (mem_scan_locked_flag)
    {
        release_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_EXCLUSIVE);
    }

    return return_val;
}

