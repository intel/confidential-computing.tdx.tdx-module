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
 * @file tdh_mem_scan_range
 * @brief TDH_MEM_SCAN_RANGE API handler
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


api_error_type tdh_mem_scan_range(uint64_t list_of_lists_info, uint64_t tdr, uint64_t controls, uint64_t range_start, uint64_t range_size, uint64_t overall_next_entry)
{
    // TDH.MEM.SCAN.COMP is supported if any of its operations are enumerated as available.
    if (!(is_non_blocking_export_configured()
        || is_scan_export_restore_supported()
        ))
    {
        TDX_ERROR("TDH.MEM.SCAN.RANGE is supported if any of its operations are enumerated as available. non_blocking_export = %d, scan_export_restore = %d\n",
            is_non_blocking_export_configured(), is_scan_export_restore_supported());
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
    api_error_type            return_val = TDX_OPERAND_INVALID;

    pa_t                      current_gpa = { .raw = range_start };
    pa_t                      range_end_gpa = { .raw = range_start + range_size };

    bool_t                    scan_started = false;

    // TSC
    uint64_t start_tsc = ia32_rdtsc();

    // ####################################################################################
    // ################################## Initial Checks ##################################
    // ####################################################################################

    if (DSCAN == scan_controls.operation)
    {
        // FORMAT must be LIST_OF_LISTS (2), and FIRST_ENTRY must be 0.
        if (GPA_LIST_FORMAT_LIST_OF_LISTS != list_of_lists_info_hpa.format || list_of_lists_info_hpa.first_entry)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
            TDX_ERROR("Invalid LIST_OF_LISTS structure - format = %d, first_entry = 0x%llx\n", list_of_lists_info_hpa.format, list_of_lists_info_hpa.first_entry);
            goto EXIT;
        }

        // The next overall index of the GPA List entry to be written by TDH.MEM.SCAN.RANGE must be between 0 and (512 * [LIST_OF_LISTS_INFO.LAST_ENTRY + 1] - 1).
        if (overall_next_entry >= (512 * (list_of_lists_info_hpa.last_entry + 1)))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
            TDX_ERROR("Invalid overall_next_entry = %llx\n", overall_next_entry);
            goto EXIT;
        }
    }

	// 1. RESERVED0/1 - Reserved, must be 0. Note that context_id and_range_id are reserved in TDH.MEM.SCAN.RANGE.
    // 2. OPERATION - TDH.MEM.SCAN.RANGE supports only DSCAN and EXPORT_RESTORE. If EXPORT_RESTORE, RCX must be 0.
    // 3. QUALIFIER - Only EXPORT/REEXPORT qualifiers are supported by DCHECK.
    if (scan_controls.reserved0 || scan_controls.reserved1 || scan_controls.context_id || scan_controls.range_id ||
        ((DCHECK == scan_controls.operation) || ((EXPORT_RESTORE == scan_controls.operation) && (list_of_lists_info_hpa.raw))
        || (scan_controls.operation > MEM_SCAN_MAX_OP)) ||
        (scan_controls.qualifier > MEM_SCAN_QUALIFIER_MAX))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        TDX_ERROR("Illegal controls: 0x%llx\n", scan_controls.raw);
        goto EXIT;
    }

    // Check that RANGE_SIZE is valid. Must be a multiple of 4KB. Bits 63:52 must be 0.
    if ((0 == range_size) || (!is_addr_aligned_pwr_of_2(range_size, _4KB)) || (range_size & BITS(63,52)))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        TDX_ERROR("Illegal range size: 0x%llx.\n", range_size);
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
                                               TDH_MEM_SCAN_RANGE_LEAF,
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

    // Validate that the range_start is valid, private and aligned on 4KB.
    if (!check_gpa_validity((pa_t)range_start, tdcs_p->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_p->executions_ctl_fields.virt_maxpa))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        TDX_ERROR("Illegal range start: 0x%llx.\n", range_start);
        goto EXIT;
    }

    // If the requested operation is EXPORT_RESTORE, an export session must not be in progress.
    if (EXPORT_RESTORE == scan_controls.operation && op_state_is_export_in_progress(tdcs_p->management_fields.op_state))
    {
        TDX_ERROR("Incorrect OP state: %d\n", tdcs_p->management_fields.op_state);
        return_val = api_error_with_operand_id(TDX_OP_STATE_INCORRECT,(uint64_t)tdcs_p->management_fields.op_state);
        goto EXIT;
    }

    // ####################################################################################
    // ################################ Range Calculations ################################
    // ####################################################################################

    range_end_gpa.raw = MIN(range_start + range_size, calc_max_range_end(tdcs_p));

    // If the requested OPERATION does not return a page list (e.g., EXPORT_RESTORE), LIST_OF_LIST_INFO is ignored.
    if (DSCAN == scan_controls.operation)
    {
        // map the lists and initialize the lists tracker
        return_val = initialize_lists(list_of_lists_info_hpa, &lists_tracker);
        if (TDX_SUCCESS != return_val)
        {
            goto EXIT;
        }
    }

    // lock the SEPT tree
    if (TDX_SUCCESS != acquire_sharex_lock_hp(&tdcs_p->executions_ctl_fields.secure_ept_lock, TDX_LOCK_SHARED, false))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        TDX_ERROR("Failed to acquire SEPT tree lock");
        goto EXIT;
    }
    sept_tree_locked_flag = true;

    // map the SEPT tree root
    pa_t sept_root_pa = { .raw = tdcs_p->executions_ctl_fields.eptp.raw & IA32E_PAGING_STRUCT_ADDR_MASK };
    sept_roots[0] = map_pa_with_hkid((void*)(sept_root_pa.full_pa), tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    for (uint16_t vm_id = 1; (vm_id <= tdcs_p->management_fields.num_l2_vms) && (vm_id < MAX_VMS); vm_id++)
    {
        ia32e_eptp_t l2_sept_root = get_l2_septp_with_hkid(tdr_p, tdcs_p, vm_id);
        sept_roots[vm_id] = map_pa((void*)(l2_sept_root.raw & IA32E_PAGING_STRUCT_ADDR_MASK), TDX_RANGE_RW);
    }

    // ####################################################################################
    // ######################## Depth-First Scan of the SEPT Trees ########################
    // ####################################################################################
    // Scan the L1 and any L2 SEPT trees in a depth-first mode (i.e., by incrementing GPA), while CURRENT_GPA < RANGE_END
    // and the GPA lists are not full. The scanning is done in parallel on the L1 and L2 SEPT trees.

    return_val = find_first_non_free_gpa(tdr_p, tdcs_p, &current_gpa, tdcs_p->executions_ctl_fields.eptp.fields.ept_pwl, sept_roots[0], range_end_gpa, scan_controls, NULL, &start_tsc);
    if (TDX_SUCCESS != return_val)
    {
        if(UNINITIALIZE_ERROR == return_val)
        {
            // On successful end of range scan, NEXT_START  (R9) is set to RANGE_START + RANGE_SIZE.
            current_gpa.raw = range_end_gpa.raw;
            scan_started = true;
            TDX_WARN("No non-free GPAs found in the range.\n");
            return_val = TDX_SUCCESS;
        }
        else if (TDX_GPA_RANGE_BLOCKED == return_val)
        {
            TDX_WARN("Blocked GPA range identified.\n");
            scan_started = true;
        }

        // else, pending interrupt was identified during the scan

        goto EXIT;
    }

    tdx_sanity_check((current_gpa.raw < range_end_gpa.raw), FATAL_ERROR_ID_224, 0);

    return_val = scan_sept_trees(tdr_p,
                                 tdcs_p,
                                 sept_roots,
                                 &current_gpa,
                                 range_end_gpa,
                                 tdcs_p->executions_ctl_fields.eptp.fields.ept_pwl,
                                 scan_controls,
                                 &written_entries_count,
                                 &lists_tracker,
                                 NULL,
                                 &start_tsc);

    scan_started = true;

    if (current_gpa.raw > range_end_gpa.raw)
	{
	    // on successful scans where current_gpa surpasses range's end, update it to range_end_gpa
		current_gpa.raw = range_end_gpa.raw;
	}

EXIT:

    if (!scan_started)
    {
        // If scan has not started yet, R9 and R10 are unmodified
        local_data_ptr->vmm_regs.r9 = range_start;
        local_data_ptr->vmm_regs.r10 = range_size;
    }
    else
    {
        // The first GPA for next scan, aligned on 4KB.
        local_data_ptr->vmm_regs.r9 = current_gpa.raw;

        // The remaining size of the GPA range to scan, in multiples of 4KB
        local_data_ptr->vmm_regs.r10 = range_end_gpa.raw - current_gpa.raw;
    }
    // If the requested OPERATION does not return a page list (e.g., EXPORT_RESTORE), LIST_OF_LIST_INFO is ignored.
    if (DSCAN == scan_controls.operation)
    {
        tdx_debug_assert(overall_next_entry + written_entries_count == lists_tracker.overall_next_entry);
        local_data_ptr->vmm_regs.r11 = lists_tracker.overall_next_entry;
    }

    // Release all acquired locks

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
