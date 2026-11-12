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
/*
 * mem_scan.h
 *
 *  Created on: 3 Mar 2025
 *      Author: mvainer
 */

#ifndef SRC_COMMON_HELPERS_MEM_SCAN_H_
#define SRC_COMMON_HELPERS_MEM_SCAN_H_


#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "accessors/data_accessors.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers.h"

#define MAX_MEM_SCAN_CONFIG_PAGES         4
#define ENTRIES_NUM_IN_PAGE_TABLE       512
#define BITS_NUM_IN_LIST_ENTRY            9


 /**
  * brief Check whether a dirty-bit based export is supported
  */
_STATIC_INLINE_ bool_t is_non_blocking_export_configured(void)
{
    return get_global_data()->non_blocking_export_configured;
}

/**
 * brief Check whether a scan export restore is supported
 */
_STATIC_INLINE_ bool_t is_scan_export_restore_supported(void)
{
    return get_global_data()->scan_export_restore;
}

_STATIC_INLINE_ void init_non_blocking_export_variables_in_tdcs(tdcs_t* tdcs_p)
{
    for (uint8_t vm_id = 0; vm_id < MEM_SCAN_CONFIG_PAGES; vm_id++)
    {
        tdcs_p->migration_fields.mem_scan_control_page_hpas[vm_id] = NULL_PA;
    }
    uint32_t init_mask = FIELD_SUPPORT_AT_INIT_INITIALIZATION_VALUE;
    if(is_non_blocking_export_configured())
    {
        init_mask |= BIT(FIELD_SUPPORT_AT_INIT_NBE_OK);
    }
    else
    {
        tdcs_p->executions_ctl2_fields.field_support_at_init &= ~BIT(FIELD_SUPPORT_AT_INIT_NBE_OK);
    }
    tdcs_p->executions_ctl2_fields.field_support_at_init |= init_mask;
}

_STATIC_INLINE_ api_error_type check_td_for_export_mode(tdr_t *tdr_p, tdcs_t* tdcs_p)
{
    // If all the following conditions are true, the SEPT of this TD can’t be used.  Mark the TD as FATAL and its memory as non-accessible.
    if (is_non_blocking_export_configured())
    {
        if(!(tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_NBE_OK)) &&
           (tdcs_p->migration_fields.num_migs) &&
           (get_global_data()->write_blocking_export_used == WRITE_BLOCKING_EXPORT_POSSIBLY_USED))
        {
            tdr_p->management_fields.fatal = true;
            return api_error_fatal(TDX_INCOMPATIBLE_EXPORT_MODE_TD_NON_ACCESSIBLE);
        }

        tdcs_p->executions_ctl2_fields.field_support_at_init |= BIT(FIELD_SUPPORT_AT_INIT_NBE_OK);
    }

    return TDX_SUCCESS;
}


typedef enum
{
    NOT_EXPORTED = 0,
    EXPORTED_MODIFIED = 1,
    EXPORTED_BLOCKED = 2,
    EXPORTED_REMOVED = 3,
} gpa_list_entry_state_e;

typedef enum mem_scan_operations_e
{
    DSCAN = 0,
    DCHECK = 1,
    EXPORT_RESTORE = 2,
    MEM_SCAN_MAX_OP = 2
} mem_scan_operations_t;

typedef enum mem_scan_qualifier_e
{
    MEM_SCAN_QUALIFIER_EXPORT = 0,
    MEM_SCAN_QUALIFIER_REEXPORT = 1,
    MEM_SCAN_QUALIFIER_MAX = 1,
} mem_scan_qualifier_t;

typedef enum cx_pages_indices_e
{
    RANGES_PAGE_INDEX = 0,
    CONTEXTS_PAGE_INDEX = 1
}cx_pages_indices_t;

typedef union range_list_info_s
{
    struct
    {
        uint64_t num_ranges :  9; // Bits  8: 0
        uint64_t reserved0  :  3; // Bits 11: 9
        uint64_t range_list : 40; // Bits 51:12
        uint64_t reserved1  : 12; // Bits 63:52
    };
    uint64_t raw;
} range_list_info_t;
tdx_static_assert(sizeof(range_list_info_t) == 8, range_list_info_t);

typedef union range_list_entry_s
{
    struct
    {
        uint64_t reserved0          : 21; // Bits 20: 0
        uint64_t range_start        : 30; // Bits 50:21
        uint64_t reserved1          :  1; // Bit     51
        uint64_t sub_range_size_exp :  6; // Bits 57:52
        uint64_t reserved2          :  6; // Bits 63:58
    };
    uint64_t raw;
} range_list_entry_t;
tdx_static_assert(sizeof(range_list_entry_t) == 8, range_list_entry_t);

typedef enum
{
    MEM_SCAN_INIT        = 0, // Initial state.
    MEM_SCAN_READY       = 1, // Initial state.  Set by TDH.MEM.SCAN.CONFIG, TDH.EXPORT.PAUSE and TDH.MEM.SCAN.RESET.
    MEM_SCAN_IN_PROGRESS = 2, // Indicates that a scan has started.
    MEM_SCAN_SUCCESS     = 3, // Indicates successful scan of the whole GPA space.
    MEM_SCAN_FAILED      = 4  // Indicates a failed scan.
} mem_scan_state_e;

typedef struct mem_scan_ranges_s
{
    struct
    {
        uint64_t thread_count       : 16; // Bits 15: 0
        uint64_t reserved0          :  5; // Bits 20:16
        uint64_t range_start        : 31; // Bits 51:21
        uint64_t sub_range_size_exp :  6; // Bits 57:52
        uint64_t reserved1          :  6; // Bits 63:58
    };
    uint64_t next_sub_range;
} mem_scan_ranges_t;
tdx_static_assert(sizeof(mem_scan_ranges_t) == 16, mem_scan_ranges_t);

typedef struct mem_scan_context_entry_s
{
    struct
    {
        uint64_t lock        :  1; // Bit      0
        uint64_t interrupted :  1; // Bit      1
        uint64_t reserved0   : 10; // Bits 11: 2
        uint64_t start_gpa   : 40; // Bits 51:12
        uint64_t reserved1   :  4; // Bits 55:52
        uint64_t range_id    :  8; // Bits 63:56
    };
    uint64_t end_gpa;
} mem_scan_context_entry_t;
tdx_static_assert(sizeof(mem_scan_context_entry_t) == 16, mem_scan_context_entry_t);


typedef union scan_controls_s
{
    struct
    {
        uint64_t operation  :  8; // Bits  7: 0
        uint64_t qualifier  :  8; // Bits 15: 8
        uint64_t reserved0  : 16; // Bits 31:16
        uint64_t context_id : 16; // Bits 47:32
        uint64_t range_id   :  8; // Bits 55:48
        uint64_t reserved1  :  7; // Bits 62:56
        uint64_t resume     :  1; // Bit     63
    };
    uint64_t raw;
} scan_controls_t;
tdx_static_assert(sizeof(scan_controls_t) == 8, scan_controls_t);

typedef struct lists_tracker_s
{
    uint64_t overall_next_entry;
    uint64_t overall_last_entry;
    uint64_t next_gpa_list_info_entry;
    uint64_t next_gpa_list_entry;
    gpa_list_info_t* gpa_list_info_p;
    gpa_list_entry_t* gpa_list_p;
    bool_t is_gpa_list_updated;
}lists_tracker_t;

/** @brief Check and map the GPA list info.
 *
 * @param list_of_lists_info - the LIST_OF_LISTS info structure
 * @param gpa_list_info_p - pointer to the mapped GPA list info
 *
 * @return TDX_SUCCESS - success
 * @return TDX_OPERAND_INVALID - invalid LIST_OF_LISTS structure
 */
_STATIC_INLINE_ api_error_type check_and_map_gpa_list_info(gpa_list_info_t list_of_lists_info, gpa_list_info_t** gpa_list_info_p)
{
    pa_t list_of_lists_info_pa = {.raw = 0};
    list_of_lists_info_pa.page_4k_num = list_of_lists_info.hpa;

    if (list_of_lists_info.reserved_0 ||
        (GPA_LIST_FORMAT_LIST_OF_LISTS != list_of_lists_info.format) ||
        (list_of_lists_info.first_entry > list_of_lists_info.last_entry) ||
        (TDX_SUCCESS != shared_hpa_check(list_of_lists_info_pa, _4KB)))
    {
        return TDX_OPERAND_INVALID;
    }

    // Map the page list
    *gpa_list_info_p = (gpa_list_info_t*)map_pa(list_of_lists_info_pa.raw_void, TDX_RANGE_RW);

    return TDX_SUCCESS;
}

/** @brief Calculate the maximum range end.
 *
 * @param tdcs_p - pointer to the TDCS structure
 *
 * @return uint64_t - maximum range end address
*/
_STATIC_INLINE_ uint64_t calc_max_range_end(tdcs_t* tdcs_p)
{
    uint64_t gpaw = (tdcs_p->executions_ctl_fields.gpaw ? 52 : 48);
    return (uint64_t)(gpaw <= tdcs_p->executions_ctl_fields.virt_maxpa ? BIT(gpaw - 1) : BIT(tdcs_p->executions_ctl_fields.virt_maxpa));
}

api_error_type initialize_lists(gpa_list_info_t list_of_lists_info_hpa, lists_tracker_t* lists_tracker);

/**
 * @brief Prepare the context for an interrupt during a memory scan.
 *
 * @param contexts_entry - pointer to the mem scan context entry
 * @param range_id - ID of the range being scanned
 * @param curr_gpa - current GPA
 * @param end_gpa - end GPA of the range
 */
void prepare_context_for_interrupt(mem_scan_context_entry_t* contexts_entry, uint64_t range_id, uint64_t curr_gpa, uint64_t end_gpa);

/**
 * @brief Check for pending interrupt during mem scan and prepare the context if required. Update the tsc counter while doing so.
 *
 * @param tdcs_p - pointer to the TDCS structure
 * @param start_tsc - pointer to the tsc counter
 * @param gpa - current gpa
 * @param range_end_pa - end gpa of the range
 * @param contexts_entry - pointer to the mem scan context entry
 * @param scan_controls - scan controls
 *
 * @return TDX_SUCCESS - Non-free entry was found
 * @return UNINITIALIZE_ERROR - No non-free entry found in the scanned range
 * @return TDX_INTERRUPTED_RESUMABLE - Pending interrupt detected
 * @return TDX_INTERRUPTED_BUSY - The SEPT lock is already taken exclusively (for DCHECK only)
 */
api_error_type check_for_pending_interrupt(tdcs_t* tdcs_p,
                                           uint64_t* start_tsc,
                                           pa_t gpa,
                                           pa_t range_end_pa,
                                           mem_scan_context_entry_t* contexts_entry,
                                           scan_controls_t scan_controls);

/**
 * @brief Scan the L1 SEPT tree to find the first non-free GPA. The function iterates over the highest EPT level entries and invokes the recursive function to scan lower levels.
 *
 * @param tdr_p - pointer to the TDR structure
 * @param tdcs_p - pointer to the TDCS structure
 * @param gpa - pointer to the current GPA
 * @param current_lvl - current EPT level
 * @param root - pointer to the root of the current tree
 * @param end_gpa - end GPA of the range
 * @param scan_controls - scan controls
 * @param contexts_entry - pointer to the mem scan context entry
 * @param start_tsc - pointer to the tsc counter
 *
 * @return TDX_SUCCESS - Non-free entry was found
 * @return UNINITIALIZE_ERROR - No non-free entry found in the scanned range
 * @return TDX_INTERRUPTED_RESUMABLE - Pending interrupt detected
 * @return TDX_INTERRUPTED_BUSY - The SEPT lock is already taken exclusively (for DCHECK only)
 */
api_error_type find_first_non_free_gpa(tdr_t* tdr_p,
                                       tdcs_t* tdcs_p,
                                       pa_t* gpa,
                                       ept_level_t current_lvl,
                                       ia32e_paging_table_t* root,
                                       pa_t end_gpa,
                                       scan_controls_t scan_controls,
                                       mem_scan_context_entry_t* contexts_entry,
                                       uint64_t* start_tsc);

/**
 * @brief Scan the L1 SEPT tree to find the first non-free GPA. The function recursively scans all levels of the provided tree root.
 *
 * @param tdr_p - pointer to the TDR structure
 * @param tdcs_p - pointer to the TDCS structure
 * @param gpa - pointer to the current GPA
 * @param current_lvl - current EPT level
 * @param root - pointer to the root of the current tree
 * @param end_gpa - end GPA of the range
 * @param scan_controls - scan controls
 * @param contexts_entry - pointer to the mem scan context entry
 * @param start_tsc - pointer to the tsc counter
 *
 * @return TDX_SUCCESS - Non-free entry was found
 * @return UNINITIALIZE_ERROR - No non-free entry found in the scanned range
 * @return TDX_INTERRUPTED_RESUMABLE - Pending interrupt detected
 * @return TDX_INTERRUPTED_BUSY - The SEPT lock is already taken exclusively (for DCHECK only)
 */
api_error_type recursive_find_first_non_free_gpa(tdr_t* tdr_p,
                                                 tdcs_t* tdcs_p,
                                                 pa_t* gpa,
                                                 ept_level_t current_lvl,
                                                 ia32e_paging_table_t* root,
                                                 pa_t end_gpa,
                                                 scan_controls_t scan_controls,
                                                 mem_scan_context_entry_t* contexts_entry,
                                                 uint64_t* start_tsc);

/**
 * @brief Scan the SEPT trees and process the entries according to their state. The function iterates over the highest EPT level entries and invokes the recursive function to scan lower levels.
 *
 * @param tdr_p - pointer to the TDR structure
 * @param tdcs_p - pointer to the TDCS structure
 * @param sept_roots - array of pointers to the roots of the SEPT trees for all VMs
 * @param gpa - pointer to the current GPA
 * @param end_gpa - end GPA of the range
 * @param current_lvl - current EPT level
 * @param scan_controls - scan controls
 * @param written_entries_count - pointer to the count of written entries
 * @param lists_tracker - pointer to the lists tracker
 * @param contexts_entry - pointer to the mem scan context entry
 * @param start_tsc - pointer to the tsc counter
 *
 * @return TDX_SUCCESS - Scan completed successfully
 * @return TDX_INTERRUPTED_RESUMABLE - Pending interrupt detected
 * @return TDX_INTERRUPTED_BUSY - The SEPT lock is already taken exclusively (for DCHECK only)
 * @return TDX_INTERRUPTED_LIST_FULL - The output buffer (list of lists) is full
 */
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
                               uint64_t* start_tsc);

/**
 * @brief Scan the SEPT trees and process the entries according to their state. The function recursively scans all levels of the provided trees roots.
 *
 * @param tdr_p - pointer to the TDR structure
 * @param tdcs_p - pointer to the TDCS structure
 * @param sept_roots - array of pointers to the roots of the SEPT trees for all VMs
 * @param gpa - pointer to the current GPA
 * @param end_gpa - end GPA of the range
 * @param current_lvl - current EPT level
 * @param scan_controls - scan controls
 * @param written_entries_count - pointer to the count of written entries
 * @param lists_tracker - pointer to the lists tracker
 * @param contexts_entry - pointer to the mem scan context entry
 * @param start_tsc - pointer to the tsc counter
 *
 * @return TDX_SUCCESS - Scan completed successfully
 * @return TDX_INTERRUPTED_RESUMABLE - Pending interrupt detected
 * @return TDX_INTERRUPTED_BUSY - The SEPT lock is already taken exclusively (for DCHECK only)
 * @return TDX_INTERRUPTED_LIST_FULL - The output buffer (list of lists) is full
 */
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
                                         uint64_t* start_tsc);

/**
 * @brief Reset the mem scan state, scan control pages and related variables in the TDCS structure.
 *
 * @param tdcs_p - pointer to the TDCS structure
 * @param is_reconfiguration - Indicates whether the reset is due to a reconfiguration request.
 *
 * @return TDX_SUCCESS - Reset completed successfully
 * @return TDX_OPERAND_BUSY - lock is already taken
 */
api_error_type mem_scan_reset(tdcs_t* tdcs_p, bool_t is_reconfiguration);


#endif // SRC_COMMON_HELPERS_MEM_SCAN_H_