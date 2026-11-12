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
 * @file tdh_mem_scan_config
 * @brief TDH_MEM_SCAN_CONFIG API handler
 */


#include "tdx_vmm_api_handlers.h"
#include "helpers/migration.h"
#include "helpers/mem_scan.h"
#include "helpers/helpers.h"

api_error_type tdh_mem_scan_config(uint64_t range_list_info, uint64_t tdr, uint64_t cx0_hpa, uint64_t cx1_hpa, uint64_t cx2_hpa, uint64_t cx3_hpa)
{
    // TDH.MEM.SCAN.CONFIG is supported if TDH.MEM.SCAN is supported.
    if (!(is_non_blocking_export_configured()
        || is_scan_export_restore_supported()
        ))
    {
        TDX_ERROR("TDH.MEM.SCAN.CONFIG is supported if Non-Blocking Export is configured. non_blocking_export = %d, scan_export_restore = %d\n",
                  is_non_blocking_export_configured(), is_scan_export_restore_supported());
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    range_list_info_t range_list_info_pa = { .raw = range_list_info };
    pa_t tdr_hpa = { .raw = tdr };
    pa_t cx_hpa_pa[MAX_MEM_SCAN_CONFIG_PAGES] = { (pa_t)cx0_hpa, (pa_t)cx1_hpa, (pa_t)cx2_hpa, (pa_t)cx3_hpa };
    uint64_t const HPA_NOT_IN_USE_MASK = BIT(63);
    tdx_module_local_t *local_data = get_local_data();
    uint64_t *cx_hpa_output_operand[MAX_MEM_SCAN_CONFIG_PAGES] = { &local_data->vmm_regs.r8, &local_data->vmm_regs.r9, &local_data->vmm_regs.r10, &local_data->vmm_regs.r11 };

    // TDR, contexts and TDCS
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t tdr_locked_flag = false;
    tdr_t* tdr_p = NULL;
    tdcs_t* tdcs_p = NULL;
    bool_t op_state_locked_flag = false;

    // range list and control structures
    range_list_entry_t* range_list_entry_p = NULL;

    uint32_t cx_hpa_operand_id[MAX_MEM_SCAN_CONFIG_PAGES] = { OPERAND_ID_R8, OPERAND_ID_R9, OPERAND_ID_R10, OPERAND_ID_R11 };
    pamt_walk_result_t cx_hpa_pamt_walk_result[MAX_MEM_SCAN_CONFIG_PAGES];
    bool_t cx_hpa_locked_flag[MAX_MEM_SCAN_CONFIG_PAGES] = { false };
    pa_t* cx_hpa_p[MAX_MEM_SCAN_CONFIG_PAGES] = { NULL };
    mem_scan_ranges_t ranges_arr[MAX_MEM_SCAN_RANGES + 1];
    //mem_scan_context_entry_t ctx_arr[NUM_MEM_SCAN_CONTEXTS];
    bool_t mem_scan_locked_flag = false;
    bool_t is_reconfiguration = false;
    api_error_type return_val = TDX_OPERAND_INVALID;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_hpa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
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
                                               TDH_MEM_SCAN_CONFIG_LEAF,
                                               &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;
    is_reconfiguration = (bool_t)(MEM_SCAN_INIT != tdcs_p->migration_fields.mem_scan_state);

    // The number of GPA ranges is at least 1 and not higher than MAX_MEM_SCAN_RANGES.
    if (range_list_info_pa.num_ranges < 1 || range_list_info_pa.num_ranges > MAX_MEM_SCAN_RANGES)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Illegal number of ranges: %d\n", range_list_info_pa.num_ranges);
        goto EXIT;
    }

    if (acquire_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_EXCLUSIVE, false) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MEM_SCAN_STATE);
        TDX_ERROR("Failed to lock TDCS mem scan lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mem_scan_locked_flag = true;

    // Allocate the control structure pages.
    return_val = shared_hpa_check((pa_t)(range_list_info_pa.range_list << 12), _4KB);
    if (TDX_SUCCESS != return_val || range_list_info_pa.reserved0 || range_list_info_pa.reserved1)
    {
        if (TDX_SUCCESS == return_val)
        {
            return_val = TDX_OPERAND_INVALID;
        }
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", (pa_t)(range_list_info_pa.range_list << 12));
        goto EXIT;
    }

    for (uint8_t i = 0; i < MEM_SCAN_CONFIG_PAGES; i++)
    {
        // If this is not the initial configuration, the provided HPA can be NULL or a valid HPA
        if (is_reconfiguration)
        {
            if (RANGES_PAGE_INDEX == i)
            {
                // For re-configuration, the ranges control page must must be the one already in use
                cx_hpa_p[i] = map_pa((void*)(tdcs_p->migration_fields.mem_scan_control_page_hpas[RANGES_PAGE_INDEX]), TDX_RANGE_RW);
                cx_hpa_locked_flag[i] = true;
            }

            // Nothing to check if the hpa is NULL
            if (NULL_PA == cx_hpa_pa[i].raw)
            {
                continue;
            }

            // Check that the provided page HPAs are valid 4KB-aligned shared HPAs
            return_val = shared_hpa_check_with_pwr_2_alignment(cx_hpa_pa[i], TDX_PAGE_SIZE_IN_BYTES);
            if (TDX_SUCCESS != return_val)
            {
                return_val = api_error_with_operand_id(return_val, cx_hpa_operand_id[i]);
                TDX_ERROR("Invalid control page #%d, HPA = 0x%llx\n", i, cx_hpa_pa[i].raw);
                goto EXIT;
            }
        }
        else
        {
            // Check, lock and map the new cx pages
            return_val = check_lock_and_map_explicit_private_4k_hpa(cx_hpa_pa[i],
                                                                    cx_hpa_operand_id[i],
                                                                    tdr_p,
                                                                    TDX_RANGE_RW,
                                                                    TDX_LOCK_EXCLUSIVE,
                                                                    PT_NDA,
                                                                    &cx_hpa_pamt_walk_result[i],
                                                                    &cx_hpa_locked_flag[i],
                                                                    (void**)&cx_hpa_p[i]);
        }

        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Illegal cx number %d, HPA: 0x%llx\n", i, cx_hpa_pa[i].raw);
            goto EXIT;
        }
    }

    range_list_entry_p = (range_list_entry_t*)map_pa((void*)(range_list_info_pa.range_list << 12), TDX_RANGE_RO);
    range_list_entry_t range_list_entry = *range_list_entry_p;
    uint64_t prev_range_start = 0;

    // For each GPA range in the provided list:
    for (uint8_t i = 0; i < range_list_info_pa.num_ranges; i++)
    {
        // 1.1  SUB_RANGE_SIZE_EXP must be at least 21 (SUB_RANGE_SIZE of 2MB).
        // 1.2  SUB_RANGE_SIZE_EXP must not surpass 51
        // 2.1 RANGE_START of entry 0 must be 0.
        // 2.2 Check that the provided GPA range list is sorted correctly
        // 3.  reserved fields must be 0.
        // 4.  Must be a valid private GPA, lower than the maximum valid private GPA allowed for the TD.
        // 5.  range_start must be aligned on 2^exp
        range_list_entry = range_list_entry_p[i];
        uint64_t range_start = (uint32_t)range_list_entry.range_start;
        if ((range_list_entry.sub_range_size_exp < 21 || range_list_entry.sub_range_size_exp > 51) ||
            (((0 == i) && range_start) || (i && (range_start <= prev_range_start))) ||
            range_list_entry.reserved0 || range_list_entry.reserved1 || range_list_entry.reserved2 ||
            !check_gpa_validity((pa_t)(range_start << 21), tdcs_p->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_p->executions_ctl_fields.virt_maxpa) ||
            (!is_addr_aligned_pwr_of_2((range_start << 21), BIT(range_list_entry.sub_range_size_exp))))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_RANGE_LIST_ENTRY);
            TDX_ERROR("Failed on range list entry  number %d validation: 0x%llx\n", i, range_list_entry.raw);
            goto EXIT;
        }

        prev_range_start = range_start;

        // Build the internal GPA range list entry (see the definition of MEM_SCAN_RANGES).
        // Note that an additional entry is added at the end of the configured ranges, with its start address set to the top of the TD's private GPA space.
        mem_scan_ranges_t mem_scan_ranges_entry = { 0 };
        mem_scan_ranges_entry.range_start = range_start;
        mem_scan_ranges_entry.next_sub_range = range_start << 21;
        mem_scan_ranges_entry.sub_range_size_exp = range_list_entry.sub_range_size_exp;

        ranges_arr[i] = mem_scan_ranges_entry;
    }

    // Do scan reset in case this it not the first time configuration is done
    // @note - if TDCS.MEM_SCAN_STATE is MEM_SCAN_INIT (first time configuration is done), mem_scan_reset will do nothing and return TDX_SUCCESS
    // @note - in case of re-configuration, we pass 'true' to indicate there is no reason to take the mem_scan_lock again inside mem_scan_reset
    return_val = mem_scan_reset(tdcs_p, is_reconfiguration);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Scan reset failed\n");
        goto EXIT;
    }

    if (!is_reconfiguration)
    {
        for (uint8_t i = 0; i < MEM_SCAN_CONFIG_PAGES; i++)
        {
            // Initialize the contexts page contents to 0 using direct write (MOVDIR64B).
            zero_area_cacheline((void*)cx_hpa_p[i], TDX_PAGE_SIZE_IN_BYTES);

            // Initialize the applicable forward link entry in TDCS (TDCS.MEM_SCAN_CONTROL_HPAS).
            pa_t hpa_with_hkid = assign_hkid_to_hpa(tdr_p, (pa_t)cx_hpa_pa[i].raw);
            tdcs_p->migration_fields.mem_scan_control_page_hpas[i] = hpa_with_hkid.raw;
        }
    }

    uint64_t range_end = calc_max_range_end(tdcs_p);

    mem_scan_ranges_t last_mem_scan_ranges_entry = { 0 };
    last_mem_scan_ranges_entry.range_start = (range_end >> 21);
    last_mem_scan_ranges_entry.next_sub_range = range_end;
    ranges_arr[range_list_info_pa.num_ranges] = last_mem_scan_ranges_entry;

    uint64_t size = (range_list_info_pa.num_ranges + 1) * sizeof(mem_scan_ranges_t);
    // check that the size does not exceeds a page size
    tdx_sanity_check((size <= _4KB), FATAL_ERROR_ID_349, 0);
    tdx_memcpy((void*)cx_hpa_p[RANGES_PAGE_INDEX], size, ranges_arr, size);

    tdcs_p->migration_fields.num_mem_scan_ranges = (uint8_t)(range_list_info_pa.num_ranges + 1);

    if (!is_reconfiguration)
    {
        // all checks passed successfully, commit the configuration
        // Atomically increment TDR.CHLDCNT
        (void)_lock_xadd_64b(&tdr_p->management_fields.chldcnt, MEM_SCAN_CONFIG_PAGES);

        for (uint8_t i = 0; i < MEM_SCAN_CONFIG_PAGES; i++)
        {
            // Initialize the context page metadata in PAMT (Set PT to PT_TDCX, OWNER to the TDR HPA)
            cx_hpa_pamt_walk_result[i].pamt_entry_p->pt = PT_TDCX;
            set_pamt_entry_owner(cx_hpa_pamt_walk_result[i].pamt_entry_p, tdr_hpa);
            // Atomically increment the non-leaf PAMT entry's page counter
            pamt_inc_nl_page_count(cx_hpa_pamt_walk_result[i].pamt_walk_path_nl[PT_2MB]);
        }
    }

    tdcs_p->migration_fields.num_mem_scan_ranges_completed = 0;
    tdcs_p->migration_fields.mem_scan_state = MEM_SCAN_READY;

EXIT:
    // Release all acquired locks
    for (uint8_t i = 0; i < MAX_MEM_SCAN_CONFIG_PAGES; i++)
    {
        if (cx_hpa_locked_flag[i])
        {
            if (!is_reconfiguration)
            {
                // un-walking the PAMT entry is required only on initial configurations
                pamt_unwalk(&cx_hpa_pamt_walk_result[i]);
            }
            free_la(cx_hpa_p[i]);
        }
    }

    if (range_list_entry_p)
    {
        free_la(range_list_entry_p);
    }

    if (mem_scan_locked_flag)
    {
        release_sharex_lock_hp(&tdcs_p->migration_fields.mem_scan_lock, TDX_LOCK_EXCLUSIVE);
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

    if(is_reconfiguration && (return_val == TDX_SUCCESS))
    {
        for (uint8_t i = 0; i < MEM_SCAN_CONFIG_PAGES; i++)
        {
            // Update output operands to indicate that the HPA provided was not used (since cx pages were already allocated in the first configuration)
            *cx_hpa_output_operand[i] |= HPA_NOT_IN_USE_MASK;
        }
    }

    return return_val;
}
