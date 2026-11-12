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
 * @file tdh_export_state_vp.c
 * @brief TDH_EXPORT_STATE_VP API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include OP_STATE_LOOKUP_HEADER
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "metadata_handlers/metadata_generic.h"
#include "helpers/ipi_helpers.h"


api_error_type tdh_export_state_vp(uint64_t target_tdvpr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa)
{
    // Local data for return values
    tdx_module_local_t  *local_data_ptr = get_local_data();

    // tdvps
    tdvps_t              *tdvps_p = NULL;      // Pinter to the tdvps structure
    pa_t                  tdvpr_pa;            // Physical address of the tdvpr page
    pamt_walk_result_t    tdvpr_pamt_walk_result;
    bool_t                tdvpr_locked_flag = false;

    // TDR and TDCS
    tdr_t                *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t                  tdr_pa;               // Physical address of the owner TDR page
    pamt_entry_t         *tdr_pamt_p = NULL;    // Pinter to owner tdr pamt entry
    tdcs_t               *tdcs_p = NULL;        // Pointer to the TDCS structure

    bool_t                op_state_locked_flag = false;

    // MBMD
    mbmd_t               *mbmd_p = NULL;
    hpa_and_size_t        mbmd_hpa_and_size;

    // Page List
    page_list_info_t      page_list_info;
    uint32_t              page_list_i;
    pa_t                  page_list_pa;
    pa_t                 *page_list_p = NULL;

    // Single Metadata List Page
    volatile pa_t                  enc_md_list_pa;
    md_list_header_t     *enc_md_list_hdr_p = NULL;

    md_field_id_t         field_id = {.raw = 0};
    md_field_id_t         next_field_id;

    api_error_type        return_val = TDX_OPERAND_INVALID;

    md_list_t             md_list;

    // Migration Stream
    migs_index_and_cmd_t  migs_i_and_cmd;
    uint16_t              migs_i = 0;
    migsc_t              *migsc_p = NULL;
    pa_t                  migsc_pa;
    bool_t                migsc_locked_flag = false;

    // Input register operands
    tdvpr_pa.raw = target_tdvpr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    page_list_info.raw = page_or_list_pa;
    migs_i_and_cmd.raw = migs_i_and_cmd_pa;

    // By default, 0 pages are exported
    local_data_ptr->vmm_regs.rdx = 0ULL;

    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa, OPERAND_ID_RCX, TDX_LOCK_EXCLUSIVE, PT_TDVPR,
                                                        &tdvpr_pamt_walk_result, &tdvpr_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    tdr_pa.raw = 0;
    tdr_pa.page_4k_num = tdvpr_pamt_walk_result.pamt_entry_p->owner;
    bool_t is_tdr_locked = false;
    return_val = lock_and_map_implicit_tdr(tdr_pa, OPERAND_ID_TDR, TDX_RANGE_RO, TDX_LOCK_SHARED, &tdr_pamt_p, &is_tdr_locked, &tdr_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_EXPORT_STATE_VP_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Get the TD's ephemeral HKID
    uint16_t curr_hkid = tdr_p->key_management_fields.hkid;
    // Map the multi-page TDVPS structure
    tdvps_p = map_tdvps(tdvpr_pa, curr_hkid, tdcs_p->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (!tdvps_p)
    {
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check the VCPU state, associate with the current LP and set working VMCS
    bool_t new_association;
    return_val = check_and_associate_vcpu(tdvps_p, tdcs_p, &new_association, false);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Associate VCPU failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check that this VCPU has not been exported in the current export session
    if (tdvps_p->management.export_count == tdcs_p->migration_fields.export_count)
    {
        TDX_ERROR("VCPU already exported\n");
        return_val = TDX_VCPU_ALREADY_EXPORTED;
        goto EXIT;
    }

    // Process the migration stream

    // Check that the migration stream index is correct
    if (((uint32_t)migs_i_and_cmd.migs_index >= tdcs_p->migration_fields.num_migs - 1) ||
        (migs_i_and_cmd.reserved_31_16 != 0) ||
        (migs_i_and_cmd.reserved_62_32 != 0))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    migs_i = migs_i_and_cmd.migs_index;

    lfence();

    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[migs_i])))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[migs_i].migsc_hpa;

    migsc_p = (migsc_t *)map_pa_with_hkid(migsc_pa.raw_void,
            tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        // This is a new invocation, not a resumption

        // Check and map the page list
        if ((page_list_info.last_entry < (MIN_VP_STATE_EXPORT_PAGES - 1)) ||
            (page_list_info.reserved_1 != 0) ||
            (page_list_info.reserved_2 != 0))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
            goto EXIT;
        }

        if (tdcs_p->f_migsc_links[migs_i].initialized)
        {
            // If the MIGSC is initialized and MIGSC[n].INTERRUPTED.VALID is TRUE, terminate with a TDX_INVALID_RESUMPTION error
            // @note - this will not catch a case where the host VMM tries to export the same VCPU on a different Migration Stream than before
            if (migsc_p->interrupted_state.valid)
            {
                return_val = TDX_INVALID_RESUMPTION;
                goto EXIT;
            }
        }
        else
        {
            // Initialize the MIGSC if needed
            migsc_init(migsc_p, &tdcs_p->migration_fields.mig_enc_working_key);
            tdcs_p->f_migsc_links[migs_i].initialized = true;
        }

        // Increment the IV counter so we don't reuse a previous IV even if aborted
        migsc_p->iv_counter = migsc_p->iv_counter + 1;

        // Build the MBMD in the MIGSC
        migsc_p->mbmd.header.mig_version = tdcs_p->migration_fields.mig_working_version; // Current MBMD version
        migsc_p->mbmd.header.size = sizeof(mbmd_t);
        migsc_p->mbmd.header.migs_index = 0;   // Real value is written later, after MAC calculation
        migsc_p->mbmd.header.mb_type = MB_TYPE_MUTABLE_VCPU_STATE;
        migsc_p->mbmd.header.reserved_1 = 0;
        migsc_p->mbmd.header.mb_counter = migsc_p->next_mb_counter;
        migsc_p->mbmd.header.mig_epoch = tdcs_p->migration_fields.mig_epoch;
        migsc_p->mbmd.header.iv_counter = 0;   // Real value is written later, after MAC calculation
        migsc_p->mbmd.vp_state.vp_index = (uint16_t)tdvps_p->management.vcpu_index;
        migsc_p->mbmd.vp_state.reserved = 0;

        // Accumulate a MAC over the MAC’ed fields of the MBMD
        reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_i);
        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&migsc_p->mbmd.vp_state,
                MBMD_SIZE_NO_MAC(migsc_p->mbmd.vp_state)) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_141, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        // Update the MBMD with values not included in the MAC calculation
        migsc_p->mbmd.header.migs_index = migs_i;
        migsc_p->mbmd.header.iv_counter = migsc_p->iv_counter;

        page_list_i = 0;

        // Set the initial field ID.
        field_id.raw = MD_FIELD_ID_NA;
        field_id.context_code = MD_CTX_VP;

    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        // migsc must already be initialized
        if (!tdcs_p->f_migsc_links[migs_i].initialized)
        {
            return_val = TDX_MIGRATION_STREAM_STATE_INCORRECT;
            goto EXIT;
        }

        // Check the interrupted flag, then clear it
        if (!migsc_p->interrupted_state.valid)
        {
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        migsc_p->interrupted_state.valid = false;
        decrement_mig_interrupted_counters(&tdcs_p->migration_fields.mig_interrupted_count, migsc_p,
                                           (bool_t)tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT));

        // Check that the same function is resumed with the same parameters
        if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
            (migsc_p->interrupted_state.page_list_info.raw != page_list_info.raw) ||
            (migsc_p->interrupted_state.tdvpr_pa.raw != tdvpr_pa.raw))
        {
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        return_val = check_migsc_aes_gcm_context_compatibility_on_export_resume(migsc_p, migs_i);
        if (TDX_SUCCESS != return_val)
        {
            goto EXIT;
        }

        // Restore the saved state
        page_list_i = migsc_p->interrupted_state.num_processed;

        // Restore the td field ID from MIGSC, we use the right one later
        field_id.raw = migsc_p->interrupted_state.field_id.raw;
    }

    page_list_pa.raw = 0;
    page_list_pa.page_4k_num = page_list_info.hpa;

    // Verify the page list physical address is canonical and shared (it is aligned to 4KB by definition)
    if ((return_val = shared_hpa_check(page_list_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", page_list_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R9);
        goto EXIT;
    }

    // Map the page list
    page_list_p = (pa_t *)map_pa(page_list_pa.raw_void, TDX_RANGE_RO);

    /*
     * Set the field ID context for the dump operation below.
     * sys_field_is doesn't need a set context.
     */
    md_context_ptrs_t md_ctx;
    md_ctx.tdcs_ptr = tdcs_p;
    md_ctx.tdr_ptr = tdr_p;
    md_ctx.tdvps_ptr = tdvps_p;

    do
    {
        /*--------------------------------------
           Export the next metadata list page
        --------------------------------------*/

        // Copy the page list entry into an internal variable
        enc_md_list_pa.raw = page_list_p[page_list_i].raw;

        // Verify the metadata page physical address is canonical, shared, and aligned to 4KB
        if ((return_val = shared_hpa_check_with_pwr_2_alignment(enc_md_list_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
        {
            TDX_ERROR("Failed on source shared HPA 0x%llx check\n", enc_md_list_pa.raw);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_MIG_BUFF_LIST_ENTRY);
            goto EXIT;
        }

        // Map the metadata list
        if (enc_md_list_hdr_p)
        {
            free_la(enc_md_list_hdr_p);
        }
        enc_md_list_hdr_p = (md_list_header_t *)map_pa((void*)enc_md_list_pa.raw, TDX_RANGE_RW);

        md_access_qualifier_t access_qual = {.raw = 0};
        uint32_t buff_size = sizeof(md_list_t);

        // Dump the metadata list into a temporary buffer
        return_val = md_dump_list(MD_CTX_VP, field_id, md_ctx,
                                  &md_list.hdr, buff_size, MD_EXPORT_MUTABLE,
                                  access_qual, &next_field_id);

        // Restore SEAM VMCS after it was possible switched to VM VMCS by metadata accesses
        set_seam_vmcs_as_active();

        /*
         * The following code assumes dump_list never fails.
         * It just indicates if the metadata fit in the list or not.
         */
        tdx_debug_assert((return_val == TDX_METADATA_LIST_OVERFLOW) || (return_val == TDX_SUCCESS));

        // Zero-out the remaining pages in the temporary buffer
        tdx_debug_assert(md_list.hdr.list_buff_size <= _4KB);
        if (md_list.hdr.list_buff_size < _4KB)
        {
            basic_memset_to_zero(&md_list.raw[md_list.hdr.list_buff_size], _4KB - md_list.hdr.list_buff_size);
        }

        if (aes_gcm_encrypt(&migsc_p->aes_gcm_context, (uint8_t*)&md_list, (uint8_t*)enc_md_list_hdr_p , _4KB  ) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_142, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        page_list_i++;

        if (return_val == TDX_SUCCESS)
        {
            //  All metadata has been exported
            tdx_debug_assert(is_null_field_id(next_field_id));

            // Check and map the MBMD buffer in shared memory, and write out the MBMD
            if (mbmd_hpa_and_size.size < sizeof(mbmd_t))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                goto EXIT;
            }

            mbmd_hpa_and_size.size = 0;
            pa_t mbmd_hpa_and_size_pa = {.raw = mbmd_hpa_and_size.raw};
            // Verify the MBMD physical address is canonical, shared, and aligned
            if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
            {
                TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size_pa.raw);
                return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
                goto EXIT;
            }

            /*---------------------------------------------------------------
             ALL_CHECKS_PASSED:  The function is guaranteed to succeed
            ---------------------------------------------------------------*/
            // Save the current export count to avoid this VCPU from being exported again in this session
            tdvps_p->management.export_count = tdcs_p->migration_fields.export_count;

            // Map the MBMD
            mbmd_p = (mbmd_t *)map_pa((void*)mbmd_hpa_and_size.raw, TDX_RANGE_RW);

            // Write the MBMD's MAC field
            if (aes_gcm_finalize(&migsc_p->aes_gcm_context, migsc_p->mbmd.vp_state.mac) != AES_GCM_NO_ERROR)
            {
                fatal_error(FATAL_ERROR_ID_143, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
            }

            // Write out the MBMD
            copy_mbmd(mbmd_p, &migsc_p->mbmd);

            // Update the migration bundle counter and mark as non-interrupted
            (void)_lock_xadd_64b(&tdcs_p->migration_fields.total_mb_count, 1);
            migsc_p->next_mb_counter++;
            migsc_p->interrupted_state.valid = false;
        }
        else // There is more metadata to be exported
        {
            // Do a sanity check on the page list size
            if ((uint64_t)page_list_i > page_list_info.last_entry)
            {
                 return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
                 goto EXIT;
            }

            // Check for a pending interrupt
            if (is_interrupt_pending_host_side())
            {
                TDX_ERROR("Pending interrupt identified\n");
                return_val = TDX_INTERRUPTED_RESUMABLE;

                // There is a pending interrupt.  Save the state for the next invocation.
                migsc_p->interrupted_state.valid = true;
                migsc_p->interrupted_state.func.raw = local_data_ptr->vmm_regs.rax;
                migsc_p->interrupted_state.page_list_info.raw = page_list_info.raw;

                migsc_p->interrupted_state.field_id.raw = next_field_id.raw;

                migsc_p->interrupted_state.tdvpr_pa = tdvpr_pa;

                migsc_p->interrupted_state.num_processed = page_list_i;

                migsc_p->interrupted_state.aes_gcm_context_version = CRYPTO_LIB_COMPAT_VERSION;
                if (tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT))
                {
                    (void)_lock_xadd_16b(&get_global_data()->mig_interrupted_count, 1);
                    (void)_lock_xadd_16b(&tdcs_p->migration_fields.mig_interrupted_count, 1);
                }
            }
            else
            {
                // Move to the next field ID
                field_id.raw = next_field_id.raw;
            }
        }
    } while (return_val == TDX_METADATA_LIST_OVERFLOW);

    local_data_ptr->vmm_regs.rdx = page_list_i;

    if (return_val != TDX_INTERRUPTED_RESUMABLE)
    {
        return_val = TDX_SUCCESS;
    }

EXIT:

    set_seam_vmcs_as_active();

    // Release all acquired locks
    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[migs_i]);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_SHARED);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (page_list_p != NULL)
    {
        free_la(page_list_p);
    }

    if (enc_md_list_hdr_p != NULL)
    {
        free_la(enc_md_list_hdr_p);
    }

    if (tdr_pamt_p != NULL)
    {
        pamt_implicit_release_lock(tdr_pamt_p, TDX_LOCK_SHARED);
    }

    if (tdvpr_locked_flag)
    {
        pamt_unwalk(&tdvpr_pamt_walk_result);
    }

    if (migsc_p)
    {
        free_la(migsc_p);
    }

    if (tdvps_p)
    {
        free_la(tdvps_p);
    }

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (tdr_p)
    {
        free_la(tdr_p);
    }

    return return_val;
}
