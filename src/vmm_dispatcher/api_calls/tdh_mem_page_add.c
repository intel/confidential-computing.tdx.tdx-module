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
 * @file tdh_mem_page_add
 * @brief TDHMEMPAGEADD API handler
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


api_error_type tdh_mem_page_add(page_info_api_input_t gpa_page_info,
                           uint64_t target_tdr_pa,
                           uint64_t target_page_pa,
                           uint64_t source_page_pa)
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
    ia32e_sept_t        * page_sept_entry_ptr = NULL;   // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;         // Cached SEPT entry of the page
    ept_level_t           page_level_entry = gpa_mappings.level; // SEPT entry level of the page

    // New TD private page variables
    pa_t                  td_page_pa;                // Physical address of the new TD page
    void                * td_page_ptr;               // Pointer to the new TD page
    pamt_walk_result_t    td_page_pamt_walk_result;
    bool_t                td_page_locked_flag = false;   // Indicate TD page is locked

    // Source page variables
    pa_t                  source_pa;                 // Physical address of the source page
    void                * source_page_ptr = NULL;    // Pointer to the source page

    sha384_128B_block_t   sha_update_block = {.block_qword_buffer = {0}};
    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    td_page_pa.raw = target_page_pa;
    source_pa.raw = source_page_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
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
                                               false, TDH_MEM_PAGE_ADD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // SEPT tree is implicitly locked in exclusive mode, since TDR is exclusively locked
    // Check GPA
    if (!check_gpa_validity(page_gpa, tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_ptr->executions_ctl_fields.virt_maxpa))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Failed on GPA check - error = 0x%llx\n", return_val);
        goto EXIT;
    }

    // SEPT and walk to find entry
    return_val = walk_private_gpa(tdcs_ptr, page_gpa, tdr_ptr->key_management_fields.hkid,
                                  &page_sept_entry_ptr, &page_level_entry, &page_sept_entry_copy, true);

    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX);
        // Update output register operands
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("Failed on SEPT walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // SEPT tree is implicitly locked in exclusive mode, since TDR is exclusively locked
    page_sept_entry_copy = *page_sept_entry_ptr;

    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_ADD_LEAF, page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("TDH_MEM_PAGE_ADD is not allowed in current SEPT entry state - 0x%llx\n", page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Verify the source physical address is aligned, canonical and shared
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(source_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", source_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R9);
        goto EXIT;
    }

    // Check, lock and map the new TD page
    return_val = check_lock_and_map_explicit_private_4k_hpa(td_page_pa,
                                                            OPERAND_ID_R8,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &td_page_pamt_walk_result,
                                                            &td_page_locked_flag,
                                                            (void**)&td_page_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new TD page - error = %llx\n", return_val);
        goto EXIT;
    }

    if(get_global_data()->update_compatibility && (tdcs_ptr->measurement_fields.mrtd_context_version != CRYPTO_LIB_COMPAT_VERSION))
    {
        return_val = TDX_INCOMPATIBLE_MRTD_CONTEXT;
        goto EXIT;
    }

    // Map the source page
    source_page_ptr = map_pa((void*)source_pa.raw, TDX_RANGE_RO);

    // Copy the source image to the target TD page, using the TD’s ephemeral
    // private HKID and direct writes (MOVDIR64B)
    cache_aligned_copy_direct((uint64_t)source_page_ptr, (uint64_t)td_page_ptr, TDX_PAGE_SIZE_IN_BYTES);

    // Update the parent EPT entry with the new TD page HPA and SEPT_PRESENT state
    sept_set_leaf_unlocked_entry_given_hpa_and_hkid(
        page_sept_entry_ptr,
        SEPT_PERMISSIONS_RWX,
        td_page_pa,
        tdr_ptr->key_management_fields.hkid,
        SEPT_STATE_MAPPED_MASK,
        false,
        false);

    /**
     *  Update the TD measurements with the API string and page GPA
     */
    sha_update_block.api_name.bytes[0] = 'M';
    sha_update_block.api_name.bytes[1] = 'E';
    sha_update_block.api_name.bytes[2] = 'M';
    sha_update_block.api_name.bytes[3] = '.';
    sha_update_block.api_name.bytes[4] = 'P';
    sha_update_block.api_name.bytes[5] = 'A';
    sha_update_block.api_name.bytes[6] = 'G';
    sha_update_block.api_name.bytes[7] = 'E';
    sha_update_block.api_name.bytes[8] = '.';
    sha_update_block.api_name.bytes[9] = 'A';
    sha_update_block.api_name.bytes[10] = 'D';
    sha_update_block.api_name.bytes[11] = 'D';
    sha_update_block.gpa = page_gpa.raw;

    if ((sha_error_code = sha384_update_128B(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                               &sha_update_block,
                                               1)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        fatal_error(FATAL_ERROR_ID_110, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    // Increment TDCS.MEM_COUNT
    tdcs_ptr->executions_ctl2_fields.mem_count++;

    // Increment TDR child count
    tdr_ptr->management_fields.chldcnt++;

    // Update the new Secure EPT page’s PAMT entry
    td_page_pamt_walk_result.pamt_entry_p->pt = PT_REG;
    set_pamt_entry_owner(td_page_pamt_walk_result.pamt_entry_p, tdr_pa);
    td_page_pamt_walk_result.pamt_entry_p->bepoch.raw = 0;  // Setting BEPOCH to 0 is required to avoid confusion during page export

    pamt_inc_nl_page_count(td_page_pamt_walk_result.pamt_walk_path_nl[PT_2MB]);

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (td_page_locked_flag)
    {
        pamt_unwalk(&td_page_pamt_walk_result);
        free_la(td_page_ptr);
    }
    if (page_sept_entry_ptr != NULL)
    {
        free_la(page_sept_entry_ptr);
    }
    if (source_page_ptr != NULL)
    {
        free_la(source_page_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }
    return return_val;
}
