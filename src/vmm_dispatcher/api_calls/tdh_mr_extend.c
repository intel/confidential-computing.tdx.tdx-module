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
 * @file tdh_mr_extend
 * @brief TDHMREXTEND API handler
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
#include "crypto/sha384.h"


api_error_type tdh_mr_extend(uint64_t target_page_gpa, uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA related variables
    pa_t                  page_gpa;                  // Target page GPA
    pa_t                  page_hpa;                  // Target page HPA (after SEPT walk)
    void                * page_ptr = NULL;           // Pointer to target page HPA (linear address)

    // SEPT related variables
    ia32e_sept_t        * page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           page_level_entry = LVL_PT; // SEPT entry level of the page

    sha384_128B_block_t   sha_gpa_update_block = {.block_qword_buffer = {0}};
    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    page_gpa.raw = target_page_gpa;
    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_EXCLUSIVE,
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
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_MR_EXTEND_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the page GPA is 256 Byte aligned
    if (!is_addr_aligned_pwr_of_2(page_gpa.raw, 256))
    {
        TDX_ERROR("Page GPA is not aligned to 256 Bytes\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // SEPT tree is implicitly locked in exclusive mode, since TDR is exclusively locked

    // Check GPA, don't lock SEPT and walk to find entry
    return_val = check_and_walk_private_gpa_to_leaf(tdcs_ptr,
                                                    OPERAND_ID_RCX,
                                                    page_gpa,
                                                    tdr_ptr->key_management_fields.hkid,
                                                    &page_sept_entry_ptr,
                                                    &page_level_entry,
                                                    &page_sept_entry_copy);

    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_PRESENT, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
            TDX_ERROR("Failed on SEPT walk - error = %lld\n", return_val);
        }

        TDX_ERROR("Failed on GPA check or any other error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify the EPT entry state is MAPPED
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MR_EXTEND_LEAF, page_sept_entry_copy))
    {
        return_val = TDX_EPT_ENTRY_NOT_PRESENT;
        TDX_ERROR("EPT entry is not present %llx\n", return_val);
        goto EXIT;
    }

    if(get_global_data()->update_compatibility && (tdcs_ptr->measurement_fields.mrtd_context_version != CRYPTO_LIB_COMPAT_VERSION))
    {
        return_val = TDX_INCOMPATIBLE_MRTD_CONTEXT;
        goto EXIT;
    }

    // Calculate HPA from SEPT page entry and GPA offset
    page_hpa.raw = leaf_ept_entry_to_hpa(page_sept_entry_copy, page_gpa.raw, page_level_entry);

    // Map the page to measure
    page_ptr = map_pa_with_hkid(page_hpa.raw_void, tdr_ptr->key_management_fields.hkid, TDX_RANGE_RO);

    /**
     *  Update the TD measurements with the page's measurement using SHA384.
     *  SHA384 works on 128 Byte block sizes, therefore we process 3 blocks (= 384 Byte).
     */
    sha_gpa_update_block.api_name.bytes[0] = 'M';
    sha_gpa_update_block.api_name.bytes[1] = 'R';
    sha_gpa_update_block.api_name.bytes[2] = '.';
    sha_gpa_update_block.api_name.bytes[3] = 'E';
    sha_gpa_update_block.api_name.bytes[4] = 'X';
    sha_gpa_update_block.api_name.bytes[5] = 'T';
    sha_gpa_update_block.api_name.bytes[6] = 'E';
    sha_gpa_update_block.api_name.bytes[7] = 'N';
    sha_gpa_update_block.api_name.bytes[8] = 'D';
    sha_gpa_update_block.gpa = page_gpa.raw;

    if ((sha_error_code = sha384_update_128B(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                               &sha_gpa_update_block,
                                               1)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        fatal_error(FATAL_ERROR_ID_111, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
    if ((sha_error_code = sha384_update_128B(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                               (sha384_128B_block_t*)page_ptr,
                                               2)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        fatal_error(FATAL_ERROR_ID_112, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }
    if (page_sept_entry_ptr != NULL)
    {
        free_la(page_sept_entry_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (page_ptr != NULL)
    {
        free_la(page_ptr);
    }
    return return_val;
}
