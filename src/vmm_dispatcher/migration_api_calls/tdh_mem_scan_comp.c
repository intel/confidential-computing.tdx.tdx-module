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
 * @file tdh_mem_scan_comp
 * @brief TDH_MEM_SCAN_COMP API handler
 */


#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include OP_STATE_LOOKUP_HEADER
#include SEPT_STATE_LOOKUP_HEADER
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "helpers/mem_scan.h"
#include "metadata_handlers/metadata_generic.h"
#include "memory_handlers/sept_manager.h"
#include "memory_handlers/keyhole_manager.h"


api_error_type tdh_mem_scan_comp(uint64_t list_of_lists_info, uint64_t tdr, uint64_t controls, uint64_t overall_next_entry)
{
    // TDH.MEM.SCAN.COMP is supported if any of its operations are enumerated as available.
    if (!(is_non_blocking_export_configured()))
    {
        TDX_ERROR("TDH.MEM.SCAN.COMP is supported if any of its operations are enumerated as available. non_blocking_export = %d\n", is_non_blocking_export_configured());
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    tdx_module_local_t* local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t*                    tdr_p = NULL;
    pa_t                      tdr_hpa = { .raw = tdr };
    pamt_walk_result_t        tdr_pamt_walk_result;
    bool_t                    tdr_locked_flag = false;
    tdcs_t*                   tdcs_p = NULL;
    bool_t                    op_state_locked_flag = false;

    // Ranges and Contexts
    mem_scan_context_entry_t* contexts_p = NULL;
    mem_scan_context_entry_t* context_entry_p;
    bool_t                    contexts_locked_flag = false;
    mem_scan_ranges_t*        ranges_p = NULL;

    // List of lists and GPA lists tracker initialization
    lists_tracker_t lists_tracker = { 0 };
    lists_tracker.overall_next_entry = overall_next_entry;

    // Secure-EPT
    bool_t                    sept_tree_locked_flag = false;
    ia32e_paging_table_t*     sept_roots[MAX_VMS] = { NULL };
    uint32_t                  written_entries_count = 0;

    // initializations
    gpa_list_info_t           list_of_lists_info_hpa = { .raw = list_of_lists_info };
    scan_controls_t           scan_controls = { .raw = controls };
    bool_t                    mem_scan_locked_flag = false;
    bool_t                    scan_start_shared_locked_flag = false;
    bool_t                    scan_start_exclusive_locked_flag = false;
    api_error_type            return_val = TDX_OPERAND_INVALID;
    uint64_t                  max_range_end = 0;
    bool_t                    skip_increment_range = scan_controls.resume;

    // TSC
    uint64_t start_tsc = ia32_rdtsc();

    // ####################################################################################
    // ################################## Initial Checks ##################################
    // ####################################################################################

	// FORMAT must be LIST_OF_LISTS (2), and FIRST_ENTRY must be 0.
    if (GPA_LIST_FORMAT_LIST_OF_LISTS != list_of_lists_info_hpa.format || list_of_lists_info_hpa.first_entry)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Invalid LIST_OF_LISTS structure - format = %d, first_entry = 0x%llx\n", list_of_lists_info_hpa.format, list_of_lists_info_hpa.first_entry);
        goto EXIT;
    }

	// The next overall index of the GPA List entry to be written by TDH.MEM.SCAN.COMP must be between 0 and (512 * [LIST_OF_LISTS_INFO.LAST_ENTRY + 1] - 1).
	if (overall_next_entry >= (512 * (list_of_lists_info_hpa.last_entry + 1)))
	{
		return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
		TDX_ERROR("Invalid overall_next_entry = 0x%llx\n", overall_next_entry);
		goto EXIT;
	}

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_hpa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_walk_result,
                                                 &tdr_locked_flag,
                                                 &tdr_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p,
                                               TDX_RANGE_RW,
                                               TDX_LOCK_SHARED,
                                               false,
                                               TDH_MEM_SCAN_COMP_LEAF,
                                               &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    return_val = check_td_for_export_mode(tdr_p, tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("TD state check for export mode failed - error = %llx\n", return_val);
        goto EXIT;
    }

    // move it before the mapping of the ranges and the contexts
    if (acquire_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_SHARED, false) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MEM_SCAN_STATE);
        TDX_ERROR("Failed to lock TDCS mem scan lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mem_scan_locked_flag = true;

    if (MEM_SCAN_INIT == tdcs_p->migration_fields.mem_scan_state)
    {
        TDX_ERROR("Invalid call: the scan is not configured yet.\n");
        return_val = TDX_MEM_SCAN_CONFIG_REQUIRED;
        goto EXIT;
    }

    max_range_end = calc_max_range_end(tdcs_p);

    // 1. RESERVED0/1 - Reserved, must be 0.
    // 2. OPERATION - TDH.MEM.SCAN.COMP supports only DCHECK.
    // 3. QUALIFIER - Only EXPORT/REEXPORT qualifiers are supported by DCHECK.
    // 4. CONTEXT_ID - CONTEXT_ID must be lower than NUM_MEM_SCAN_CONTEXTS
    // 5. RANGE_ID - Must be lower than the number of ranges configured by TDH.MEM.SCAN.CONFIG (take into account also the last entry).
    if (scan_controls.reserved0 || scan_controls.reserved1 ||
        (DCHECK != scan_controls.operation) ||
        (scan_controls.qualifier > MEM_SCAN_QUALIFIER_MAX) ||
        (scan_controls.context_id >= NUM_MEM_SCAN_CONTEXTS) ||
        (scan_controls.range_id >= (tdcs_p->migration_fields.num_mem_scan_ranges - 1)))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        TDX_ERROR("Illegal controls: 0x%llx\n", scan_controls.raw);
        goto EXIT;
    }

    // An export session must be in progress and the TD must have been paused (OP_STATE is PAUSED_EXPORT).
    if (tdcs_p->management_fields.op_state != OP_STATE_PAUSED_EXPORT)
    {
        TDX_ERROR("Incorrect OP state: %d\n", tdcs_p->management_fields.op_state);
        return_val = api_error_with_operand_id(TDX_OP_STATE_INCORRECT,(uint64_t)tdcs_p->management_fields.op_state);
        goto EXIT;
    }

    // map the control structures
    ranges_p = (mem_scan_ranges_t*)map_pa((void*)(tdcs_p->migration_fields.mem_scan_control_page_hpas[RANGES_PAGE_INDEX]), TDX_RANGE_RW);
    contexts_p = (mem_scan_context_entry_t*)map_pa((void*)(tdcs_p->migration_fields.mem_scan_control_page_hpas[CONTEXTS_PAGE_INDEX]), TDX_RANGE_RW);

    // Lock the context.
    context_entry_p = &contexts_p[scan_controls.context_id];
    if (_lock_bts_64b((uint64_t*)context_entry_p, 0))
    {
        TDX_ERROR("Failed to lock scan contexts page.\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MEM_SCAN_CONTEXT);
        goto EXIT;
    }
    contexts_locked_flag = true;

    // map the lists and initialize the lists tracker
    return_val = initialize_lists(list_of_lists_info_hpa, &lists_tracker);
    if (TDX_SUCCESS != return_val)
    {
        goto EXIT;
    }

    // lock the SEPT tree
    if (TDX_SUCCESS != acquire_sharex_lock_hp(&tdcs_p->executions_ctl_fields.secure_ept_lock, TDX_LOCK_SHARED, false))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        TDX_ERROR("Failed to acquire SEPT tree lock");
        goto EXIT;
    }
    sept_tree_locked_flag = true;

    if (scan_controls.resume)
    {
        // Check that this is a valid resumption:  The contexts INTERRUPTED bit must be 1.
        if (!context_entry_p->interrupted)
        {
            TDX_ERROR("Invalid resumption: the contexts INTERRUPTED bit must be 1 on resumed command.\n");
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        // The specified RANGE_ID must be the same as the contexts RANGE_ID.
        if (scan_controls.range_id != context_entry_p->range_id)
        {
            TDX_ERROR("Invalid resumption: the specified RANGE_ID must be the same as the contexts RANGE_ID.\n");
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        // A scan is still in progress:  TDCS.MEM_SCAN_STATE is MEM_SCAN_IN_PROGRESS.
        if (MEM_SCAN_IN_PROGRESS != tdcs_p->migration_fields.mem_scan_state)
        {
            TDX_ERROR("Invalid resumption: a scan is still in progress.\n");
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        // The specified OPERATION and QUALIFIER are the same as used in the current scan (TDCS.MEM_SCAN_OPERATION and TDCS.MEM_SCAN_QUALIFIER).
        if ((scan_controls.operation != tdcs_p->migration_fields.mem_scan_operation) ||
            (scan_controls.qualifier != tdcs_p->migration_fields.mem_scan_qualifier))
        {
            TDX_ERROR("Invalid resumption: the specified OPERATION and QUALIFIER are not the same as used in the current scan.\n");
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        // Set the contexts INTERRUPTED bit to 0.
        context_entry_p->interrupted = 0;
    }
    else // initial invocation
    {
        // Check that an interrupted operation is not in progress.  The contexts INTERRUPTED bit must be 0.
        if (context_entry_p->interrupted)
        {
            TDX_ERROR("An interrupted operation is in progress. The contexts INTERRUPTED bit must be 0.\n");
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        // Critical section
        if (acquire_sharex_lock(&tdcs_p->migration_fields.scan_start_lock, TDX_LOCK_EXCLUSIVE) != LOCK_RET_SUCCESS)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MEM_SCAN_START);
            TDX_ERROR("Failed to acquire exclusive lock TDCS scan start lock - error = %llx\n", return_val);
            goto EXIT;
        }
        scan_start_exclusive_locked_flag = true;
        
        // Try to atomically check (using LOCK_CMPXCHG) that TDCS.MEM_SCAN_STATE is MEM_SCAN_READY and set it to MEM_SCAN_IN_PROGRESS.
        uint8_t mem_scan_state = _lock_cmpxchg_8bit(MEM_SCAN_READY, MEM_SCAN_IN_PROGRESS, (uint8_t*)&tdcs_p->migration_fields.mem_scan_state);

        switch (mem_scan_state)
        {
        case MEM_SCAN_READY: // success, state was changed
        {
            // Save the specified OPERATION and QUALIFIER in TDCS.MEM_SCAN_OPERATION and TDCS.MEM_SCAN_QUALIFIER respectively.
            tdcs_p->migration_fields.mem_scan_operation = scan_controls.operation;
            tdcs_p->migration_fields.mem_scan_qualifier = scan_controls.qualifier;
            break;
        }
        // failure for all other cases, state wasn't changed
        case MEM_SCAN_IN_PROGRESS:
        {
            // Check that the specified OPERATION and QUALIFIER are the same as used in the current scan (TDCS.MEM_SCAN_OPERATION and TDCS.MEM_SCAN_QUALIFIER).
            if ((tdcs_p->migration_fields.mem_scan_operation != scan_controls.operation) ||
                (tdcs_p->migration_fields.mem_scan_qualifier != scan_controls.qualifier))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
				TDX_ERROR("Invalid operation and qualifier\n");
            }

            break;
        }
        case MEM_SCAN_FAILED:
        {
            // If the value is MEM_SCAN_FAILED, return TDX_MEM_SCAN_FAILED_OTHER_THREAD.
            return_val = TDX_MEM_SCAN_FAILED_OTHER_THREAD;
            break;
        }
        case MEM_SCAN_SUCCESS:
        {
            // If the value is MEM_SCAN_SUCCESS, return TDX_MEM_SCAN_ALREADY_SUCCESSFUL.
            return_val = TDX_MEM_SCAN_ALREADY_SUCCESSFUL;
            break;
        }
        default:
        {
            fatal_error(FATAL_ERROR_ID_347, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
        }

        if (TDX_SUCCESS != return_val)
        {
            goto EXIT;
        }

        // Atomically increment MEM_SCAN_RANGES[RANGE_ID].THREAD_COUNT.
        (void)_lock_xadd_16b((uint16_t*)&ranges_p[scan_controls.range_id], 1);
        release_sharex_lock(&tdcs_p->migration_fields.scan_start_lock, TDX_LOCK_EXCLUSIVE);
        scan_start_exclusive_locked_flag = false;
    }

    // map the SEPT tree root
    pa_t sept_root_pa = { .raw = tdcs_p->executions_ctl_fields.eptp.raw & IA32E_PAGING_STRUCT_ADDR_MASK };
    sept_roots[0] = map_pa_with_hkid((void*)(sept_root_pa.full_pa), tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    for (uint16_t vm_id = 1; (vm_id <= tdcs_p->management_fields.num_l2_vms) && (vm_id < MAX_VMS); vm_id++)
    {
        ia32e_eptp_t l2_sept_root = get_l2_septp_with_hkid(tdr_p, tdcs_p, vm_id);
        sept_roots[vm_id] = map_pa((void*)(l2_sept_root.raw & IA32E_PAGING_STRUCT_ADDR_MASK), TDX_RANGE_RW);
    }

    // Process sub ranges
    while (TDX_SUCCESS == return_val)
    {
        // ####################################################################################
        // ############################### Sub-Range Allocation ###############################
        // ####################################################################################

        // If TDCS.MEM_SCAN_STATE is MEM_SCAN_FAILED, abort with a TDX_MEM_SCAN_FAILED_OTHER_THREAD status
        if (MEM_SCAN_FAILED == tdcs_p->migration_fields.mem_scan_state)
        {
            (void)_lock_xadd_16b((uint16_t*)&ranges_p[scan_controls.range_id], (uint16_t)-1);
            return_val = TDX_MEM_SCAN_FAILED_OTHER_THREAD;
            goto EXIT;
        }

        // Atomically calculate context.START_GPA and set the new sub-range start for the next invocation of TDH.MEM.SCAN.COMP
        if (!skip_increment_range)
        {
            context_entry_p->start_gpa =
                (_lock_xadd_64b(&ranges_p[scan_controls.range_id].next_sub_range,
                                BIT(ranges_p[scan_controls.range_id].sub_range_size_exp)) >> 12);
        }

        // Check if done with the current range
        if (context_entry_p->start_gpa >= (uint64_t)((uint64_t)(ranges_p[scan_controls.range_id + 1].range_start) << 9))
        {
            // Critical section, no other thread should increment the thread count. Other threads can decrement thread count
            if (acquire_sharex_lock(&tdcs_p->migration_fields.scan_start_lock, TDX_LOCK_SHARED) != LOCK_RET_SUCCESS)
            {
                return_val = api_error_with_operand_id(TDX_INTERRUPTED_BUSY, OPERAND_ID_MEM_SCAN_START);
                uint64_t tmp_gpa = (uint64_t)(ranges_p[scan_controls.range_id + 1].range_start << 21);
                prepare_context_for_interrupt(context_entry_p, scan_controls.range_id, tmp_gpa, tmp_gpa);
                TDX_ERROR("Failed to acquire shared lock TDCS scan start lock - error = %llx\n", return_val);
                goto EXIT;
            }
            scan_start_shared_locked_flag = true;
            // Check if this is the last thread working on this range.  Atomically decrement MEM_SCAN_RANGES[RANGE_ID].THREAD_COUNT.
            if (_lock_xadd_16b((uint16_t*)&ranges_p[scan_controls.range_id], (uint16_t)-1) > 1)
            {
                // If the old value was higher than 1, there are still other threads working on the current range. Abort with a TDX_SUCCESS status.
                TDX_LOG("Aborting mem scan - there are still other threads working on the current range. range_id = %d\n", scan_controls.range_id);
                return_val = TDX_SUCCESS;
                goto EXIT;
            }

            // If the old value was 1, the current range has been fully scanned.  Check if all ranges have been scanned.
            // Atomically increment (LOCK XADD) TDCS. NUM_MEM_SCAN_RANGES_COMPLETE
            if (_lock_xadd_8b(&tdcs_p->migration_fields.num_mem_scan_ranges_completed, 1) < tdcs_p->migration_fields.num_mem_scan_ranges - 2)
            {
                // If not all ranges have been scanned, abort with TDX_MEM_RANGE_SCAN_SUCCESS status
                TDX_LOG("Aborting mem scan - the current range has been fully scanned. range_id = %d\n", scan_controls.range_id);
                return_val = TDX_MEM_RANGE_SCAN_SUCCESS;
                goto EXIT;
            }

            // Else, all ranges have been scanned
            // Only one thread per TD can get to this point
            // Set TDCS.MEM_SCAN_STATE to MEM_SCAN_SUCCESS.
            tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_SUCCESS;

            // Abort with a TDX_MEM_SCAN_SUCCESS status.
            TDX_LOG("Aborting mem scan - all ranges have been scanned.\n");
            return_val = TDX_MEM_SCAN_SUCCESS;
            goto EXIT;
        }

        // Calculate context.RANGE_END = context.RANGE_START + RANGE_SIZE
        pa_t end_gpa;

        if (!skip_increment_range)
        {
            end_gpa.raw = MIN((context_entry_p->start_gpa << 12) + BIT(ranges_p[scan_controls.range_id].sub_range_size_exp),
                              (uint64_t)(ranges_p[scan_controls.range_id + 1].range_start) << 21);
        }
        else
        {
            end_gpa.raw = context_entry_p->end_gpa;
            skip_increment_range = false;
        }

        // If context.RANGE_END is higher than TDCS.ACTUAL_MAX_GPA, set it to TDCS.ACTUAL_MAX_GPA.
        if (end_gpa.raw > max_range_end)
        {
            end_gpa.raw = max_range_end;
        }

        context_entry_p->end_gpa = end_gpa.raw;

        // Set CURRENT_GPA = context.SUB_RANGE_START
        pa_t current_gpa = { .raw = (context_entry_p->start_gpa << 12) };

        // ####################################################################################
        // ######################## Depth-First Scan of the SEPT Trees ########################
        // ####################################################################################
        // Scan the L1 and any L2 SEPT trees in a depth-first mode (i.e., by incrementing GPA),
        // while CURRENT_GPA < context.SUB_RANGE_END and the GPA lists are not full.
        // The scanning is done in parallel on the L1 and L2 SEPT trees.Note that the L2 SEPT trees are subsets of the L1 SEPT tree,
        // i.e., any GPA mapped by L2 is in L1, but there may be GPAs mapped by L1 that are not in L2.

        return_val = find_first_non_free_gpa(tdr_p, tdcs_p, &current_gpa, tdcs_p->executions_ctl_fields.eptp.fields.ept_pwl, sept_roots[0], end_gpa, scan_controls, context_entry_p, &start_tsc);
        if (TDX_SUCCESS != return_val)
        {
            if(UNINITIALIZE_ERROR == return_val)
            {
                // Did not find a non-free entry, proceed to next sub-range
                return_val = TDX_SUCCESS;
                continue;
            }
            else
            {
                TDX_ERROR("Pending interrupt identified\n");
                goto EXIT;
            }
        }

        tdx_sanity_check((current_gpa.raw < end_gpa.raw), FATAL_ERROR_ID_342, 0);

        // ####################################################################################
        // ############# Scan the L1 and any L2 SEPT trees in a depth-first mode ##############
        // ####################################################################################

        return_val = scan_sept_trees(tdr_p,
                                     tdcs_p,
                                     sept_roots,
                                     &current_gpa,
                                     end_gpa,
                                     tdcs_p->executions_ctl_fields.eptp.fields.ept_pwl,
                                     scan_controls,
                                     &written_entries_count,
                                     &lists_tracker,
                                     context_entry_p,
                                     &start_tsc);

        if (TDX_SUCCESS != return_val)
        {
            goto EXIT;
        }
    }

EXIT:

    tdx_debug_assert(overall_next_entry + written_entries_count == lists_tracker.overall_next_entry);
    local_data_ptr->vmm_regs.r11 = lists_tracker.overall_next_entry;

    // Release all acquired locks
    if (scan_start_exclusive_locked_flag || scan_start_shared_locked_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.scan_start_lock, (scan_start_exclusive_locked_flag ? TDX_LOCK_EXCLUSIVE : TDX_LOCK_SHARED));
    }

    for (uint32_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if (sept_roots[vm_id])
        {
            free_la(sept_roots[vm_id]);
        }
    }

    if (sept_tree_locked_flag)
    {
        release_sharex_lock_hp_sh(&tdcs_p->executions_ctl_fields.secure_ept_lock);
    }

    if (lists_tracker.gpa_list_p != NULL)
    {
        free_la(lists_tracker.gpa_list_p);
    }

    if (lists_tracker.gpa_list_info_p != NULL)
    {
        free_la(lists_tracker.gpa_list_info_p);
    }

    if (contexts_locked_flag)
    {
        _lock_btr_64b((uint64_t*)context_entry_p, 0);
    }

    if (contexts_p != NULL)
    {
        free_la(contexts_p);
    }

    if (ranges_p != NULL)
    {
        free_la(ranges_p);
    }

    if (mem_scan_locked_flag)
    {
        release_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_SHARED);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(tdcs_p->management_fields.op_state_lock));
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_p);
    }

    return return_val;
}

