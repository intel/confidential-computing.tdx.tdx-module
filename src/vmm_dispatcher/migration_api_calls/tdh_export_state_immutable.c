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
 * @file tdh_export_state_immutable
 * @brief TDHEXPORTSTATEIMMUTABLE API handler
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
#include "helpers/mem_scan.h"
#include "metadata_handlers/metadata_generic.h"

static api_error_type handle_command_by_type(migs_index_and_cmd_t migs_i_and_cmd, page_list_info_t page_list_info,
                                             migsc_t* migsc_p, tdcs_t* tdcs_p, migs_iv_t* iv,
                                             uint32_t* page_list_i, md_field_id_t* field_id, bool_t* sys_exported)
{
    api_error_type return_val = TDX_OPERAND_INVALID;

    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        // if RESUME is 0 and OP_STATE is START_EXPORT, terminate with a TDX_INVALID_RESUMPTION error (we don't have an initialized MIGSC yet)
        if (tdcs_p->management_fields.op_state == OP_STATE_START_EXPORT)
        {
            return TDX_INVALID_RESUMPTION;
        }

        // Check and map the page list
        if ((page_list_info.last_entry < (MIN_TD_IMMUTABLE_STATE_EXPORT_PAGES - 1)) ||
            (page_list_info.reserved_1 != 0) ||
            (page_list_info.reserved_2 != 0))
        {
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        }

        pa_t page_list_pa = { .raw = 0 };
        page_list_pa.page_4k_num = page_list_info.hpa;

        // Verify the page list physical address is canonical and shared (it's aligned to 4KB by definition).
        if ((return_val = shared_hpa_check(page_list_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
        {
            TDX_ERROR("Failed on source shared HPA 0x%llx check\n", page_list_pa.raw);
            return api_error_with_operand_id(return_val, OPERAND_ID_R9);
        }


        /*
         * Check that a valid migration key has been set by the Migration TD.  If this
         * is not the first migration session, then the migration key must have been
         * set after the previous migration session has started.
         * Concurrency protected by locking the OP_STATE.
         */
        if (!tdcs_p->migration_fields.mig_dec_key_set)
        {
            TDX_ERROR("migration decryption key not set");
            return TDX_MIGRATION_DECRYPTION_KEY_NOT_SET;
        }

        // Initialize the migration context
        tdcs_p->migration_fields.mig_enc_working_key = tdcs_p->migration_fields.mig_enc_key;
        /* Generate a new 256-bit encryption key for the next migration session
           Use a temporary variable to avoid overwriting TDCS.MIG_ENC_KEY in case
           there's an error, so TDH.EXPORT.STATE.IMMUTABLE can be called again. */
        key256_t tmp_end_key;
        if (!generate_256bit_random(&tmp_end_key))
        {
            return TDX_RND_NO_ENTROPY;
        }
        tdcs_p->migration_fields.mig_enc_key = tmp_end_key;

        basic_memset_to_zero(&tmp_end_key, sizeof(tmp_end_key));


        tdcs_p->migration_fields.mig_dec_working_key = tdcs_p->migration_fields.mig_dec_key;
        tdcs_p->migration_fields.mig_dec_key_set = false;
        tdcs_p->migration_fields.mig_working_version = tdcs_p->migration_fields.mig_version;
        tdcs_p->migration_fields.mig_epoch = 0;
        tdcs_p->migration_fields.total_mb_count = 0;
        tdcs_p->migration_fields.dirty_count = 0;

        // Mark all migration streams (both forward and backward) as uninitialized
        uint16_t migs_i = 0;
        for (migs_i = 0; migs_i < tdcs_p->migration_fields.num_migs; migs_i++)
        {
            tdcs_p->migsc_links[migs_i].initialized = 0;
        }

        migsc_init(migsc_p, &tdcs_p->migration_fields.mig_enc_working_key);
        tdcs_p->f_migsc_links[0].initialized = true;

        // Mark this flow as non-interrupted
        migsc_p->interrupted_state.valid = false;

        // Increment the IV counter so we don't reuse a previous IV even if aborted
        migsc_p->iv_counter = migsc_p->iv_counter + 1;

        // Prepare the IV
        iv->iv_counter = migsc_p->iv_counter;
        iv->migs_index = 0;
        iv->reserved = 0;

        // Build the MBMD in the MIGSC
        migsc_p->mbmd.header.mig_version = tdcs_p->migration_fields.mig_working_version; // Current MBMD version
        migsc_p->mbmd.header.size = sizeof(mbmd_t);
        migsc_p->mbmd.header.migs_index = 0;
        migsc_p->mbmd.header.mb_type = MB_TYPE_IMMUTABLE_TD_STATE;
        migsc_p->mbmd.header.reserved_1 = 0;
        migsc_p->mbmd.header.mb_counter = migsc_p->next_mb_counter;
        migsc_p->mbmd.header.mig_epoch = tdcs_p->migration_fields.mig_epoch;
        migsc_p->mbmd.header.iv_counter = 0; // Real value will be written later
        migsc_p->mbmd.immutable_td_state.num_f_migs = tdcs_p->migration_fields.num_migs - 1;   // Allow for 1 backwards mig. stream
        migsc_p->mbmd.immutable_td_state.num_sys_md_pages = NUM_SYS_STATE_EXPORT_PAGES;
        migsc_p->mbmd.immutable_td_state.reserved_0 = 0;
        migsc_p->mbmd.immutable_td_state.reserved_1 = 0;

        // Accumulate a MAC over the MAC’ed fields of the MBMD
        if (aes_gcm_reset(&migsc_p->aes_gcm_context, iv) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_134, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }
        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&migsc_p->mbmd.immutable_td_state,
                                MBMD_SIZE_NO_MAC(migsc_p->mbmd.immutable_td_state)) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_135, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        // Update the MBMD with values not included in the MAC calculation
        migsc_p->mbmd.header.iv_counter = migsc_p->iv_counter;

        *page_list_i = 0;

        /*
         * Increment the export counter.  Note that this counter counts all export sessions, including
         * aborted ones.
         */
        if (tdcs_p->migration_fields.export_count >= MAX_EXPORT_COUNT)
        {
            return TDX_MAX_EXPORTS_EXCEEDED;
        }
        tdcs_p->migration_fields.export_count++;

        // We first export the SYS metadata.  Set the initial field ID.
        field_id->raw = MD_FIELD_ID_NA;
        field_id->context_code = MD_CTX_SYS;
        *sys_exported = false;
        migsc_p->interrupted_state.sys_migrated = false;

        tdcs_p->executions_ctl2_fields.field_support_at_init |= BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT);
    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        /*---------------------------------------------------------------
           This is a resumption of a previously-interrupted invocation
        ---------------------------------------------------------------*/
        tdx_module_local_t* local_data_ptr = get_local_data();

        if (!tdcs_p->f_migsc_links[migs_i_and_cmd.migs_index].initialized)
        {
            return TDX_MIGRATION_STREAM_STATE_INCORRECT;
        }

        // Check the interrupted flag, then clear it
        if (!migsc_p->interrupted_state.valid)
        {
            return TDX_INVALID_RESUMPTION;
        }

        migsc_p->interrupted_state.valid = false;

        decrement_mig_interrupted_counters(&tdcs_p->migration_fields.mig_interrupted_count, migsc_p,
                                           (bool_t)tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT));

        // Check that the same function is resumed with the same parameters
        if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
            (migsc_p->interrupted_state.page_list_info.raw != page_list_info.raw))
        {
            return TDX_INVALID_RESUMPTION;
        }

        return_val = check_migsc_aes_gcm_context_compatibility_on_export_resume(migsc_p, 0);
        if (TDX_SUCCESS != return_val)
        {
            return return_val;
        }

        // Restore the saved state
        *page_list_i = migsc_p->interrupted_state.num_processed;

        /*
         * Restore both field IDs from MIGSC, we use the right one later
         * Implementation Note:
         */
        field_id->raw = migsc_p->interrupted_state.field_id.raw;
        *sys_exported = migsc_p->interrupted_state.sys_migrated;
    }

    return TDX_SUCCESS;
}

static api_error_type handle_continues_export(api_error_type* return_val, bool_t* sys_exported, md_field_id_t* next_field_id,
                                              hpa_and_size_t* mbmd_hpa_and_size, migsc_t* migsc_p, mbmd_t** mbmd_p,
                                              tdcs_t* tdcs_p, bool_t* continue_loop, uint32_t page_list_i,
                                              page_list_info_t page_list_info, md_field_id_t* field_id)
{
    if ((*return_val == TDX_SUCCESS) && *sys_exported)
    {
        //  All metadata has been exported
        tdx_debug_assert(is_null_field_id(*next_field_id));

        /*---------------------------------------------------------------
         ALL_CHECKS_PASSED:  The function is guaranteed to succeed
        ---------------------------------------------------------------*/
        // Map the MBMD
        if (*mbmd_p)
        {
            free_la(*mbmd_p);
        }
        *mbmd_p = (mbmd_t*)map_pa((void*)mbmd_hpa_and_size->raw, TDX_RANGE_RW);

        // Write the MBMD's MAC field
        if (aes_gcm_finalize(&migsc_p->aes_gcm_context, migsc_p->mbmd.immutable_td_state.mac) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_136, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        // Write out the MBMD
        copy_mbmd(*mbmd_p, &migsc_p->mbmd);

        // Update the migration bundle counter and mark as non-interrupted
        tdcs_p->migration_fields.total_mb_count = 1;
        migsc_p->next_mb_counter = 1;
        migsc_p->interrupted_state.valid = false;

        // Start the in-order export phase
        tdcs_p->management_fields.op_state = OP_STATE_LIVE_EXPORT;

        if (is_non_blocking_export_configured())
        {
            // Record the TD epoch at the start of the export session
            tdcs_p->migration_fields.bw_epoch.raw = tdcs_p->epoch_tracking.epoch_and_refcount.td_epoch;
        }
        else
        {
            get_global_data()->write_blocking_export_used = WRITE_BLOCKING_EXPORT_USED;
        }

        *continue_loop = false;
    }
    else // There is more metadata to be exported
    {
        // Do a sanity check on the page list size
        if (((uint64_t)page_list_i) > page_list_info.last_entry)
        {
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        }

        if (*return_val == TDX_SUCCESS)
        {
            // We should only get here on end of SYS export. Start TD export.
            tdx_debug_assert(page_list_i == NUM_SYS_STATE_EXPORT_PAGES);
            tdx_debug_assert(!*sys_exported);
            *sys_exported = true;
            next_field_id->raw = MD_FIELD_ID_NA;
            next_field_id->context_code = MD_CTX_TD;
        }

        // Check for a pending interrupt
        if (is_interrupt_pending_host_side())
        {
            TDX_ERROR("Pending interrupt identified\n");

            // There is a pending interrupt.  Save the state for the next invocation.
            migsc_p->interrupted_state.valid = true;
            tdx_module_local_t* local_data_ptr = get_local_data();
            migsc_p->interrupted_state.func.raw = local_data_ptr->vmm_regs.rax;
            migsc_p->interrupted_state.page_list_info.raw = page_list_info.raw;
            migsc_p->interrupted_state.sys_migrated = *sys_exported;

            // Set the interrupted field ID depending on the stage we are in
            migsc_p->interrupted_state.field_id.raw = next_field_id->raw;

            migsc_p->interrupted_state.num_processed = page_list_i;

            migsc_p->interrupted_state.aes_gcm_context_version = CRYPTO_LIB_COMPAT_VERSION;
            if (tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT))
            {
                (void)_lock_xadd_16b(&get_global_data()->mig_interrupted_count, 1);
                (void)_lock_xadd_16b(&tdcs_p->migration_fields.mig_interrupted_count, 1);
            }

            tdcs_p->management_fields.op_state = OP_STATE_START_EXPORT;

            *continue_loop = false;
            return TDX_INTERRUPTED_RESUMABLE;
        }

        else
        {
            // Move to the next field ID
            field_id->raw = next_field_id->raw;
        }
    }

    return TDX_SUCCESS;
}

api_error_type tdh_export_state_immutable(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                                          uint64_t page_list_info_pa, uint64_t  migs_i_and_cmd_pa)
{
    // Local data for return values
    tdx_module_local_t* local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t* tdr_p = NULL;              // Pointer to the owner TDR page
    pa_t                 tdr_pa;                    // Physical address of the owner TDR page
    pamt_walk_result_t   tdr_pamt_walk_result;
    tdcs_t* tdcs_p = NULL;             // Pointer to the TDCS structure
    bool_t               tdr_locked_flag = false;
    bool_t               op_state_locked_flag = false;
    bool_t               mig_locked_flag = false;

    // MBMD
    mbmd_t* mbmd_p = NULL;
    hpa_and_size_t       mbmd_hpa_and_size;

    // Page List
    page_list_info_t     page_list_info;
    uint32_t             page_list_i;
    pa_t                 page_list_pa;
    pa_t* page_list_p = NULL;

    // Single Metadata List Page
    volatile pa_t        enc_md_list_pa;
    md_list_header_t*    enc_md_list_hdr_p = NULL;   // Cyphertext
    bool_t               sys_exported;

    // field IDs for SYS and TD
    md_field_id_t       field_id;
    md_field_id_t       next_field_id;

    api_error_type      return_val = TDX_OPERAND_INVALID;

    md_list_t           md_list;

    // Migration Stream
    migs_index_and_cmd_t  migs_i_and_cmd;
    migsc_t* migsc_p = NULL;
    pa_t                  migsc_pa;
    bool_t                migsc_locked_flag = false;
    migs_iv_t             iv = { 0 };

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    page_list_info.raw = page_list_info_pa;
    migs_i_and_cmd.raw = migs_i_and_cmd_pa;

    // By default, 0 pages are exported
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
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
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_EXCLUSIVE, false,
                                               TDH_EXPORT_STATE_IMMUTABLE_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.MIG.STREAM.CREATE
    if (acquire_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIG);
        TDX_ERROR("Failed to lock TDCS mig lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mig_locked_flag = true;

    if (!tdcs_p->executions_ctl_fields.attributes.migratable)
    {
        return_val = TDX_TD_NOT_MIGRATABLE;
        goto EXIT;
    }

    if (tdcs_p->migration_fields.mig_count != 0)
    {
        return_val = TDX_PREVIOUS_EXPORT_CLEANUP_INCOMPLETE;
        goto EXIT;
    }

    if (tdcs_p->migration_fields.num_migs < MIN_MIGS)
    {
        return_val = TDX_MIN_MIGS_NOT_CREATED;
        goto EXIT;
    }

    return_val = check_td_for_export_mode(tdr_p, tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("TD state check for export mode failed - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = check_no_tdx_io_device_attached(tdr_p, tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Check and map the MBMD buffer in shared memory, and write out the MBMD
    if (mbmd_hpa_and_size.size < sizeof(mbmd_immutable_td_state_t))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    mbmd_hpa_and_size.size = 0;
    pa_t mbmd_hpa_and_size_pa = { .raw = mbmd_hpa_and_size.raw };
    // Verify the MBMD physical address is canonical, shared, and aligned
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    // Check that the migration stream index is correct
    if ((migs_i_and_cmd.migs_index != 0) ||
        (migs_i_and_cmd.reserved_31_16 != 0) ||
        (migs_i_and_cmd.reserved_62_32 != 0))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[0])))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[0].migsc_hpa;

    page_list_pa.raw = 0;
    page_list_pa.page_4k_num = page_list_info.hpa;

    migsc_p = (migsc_t*)map_pa_with_hkid(migsc_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    if (TDX_SUCCESS != (return_val = handle_command_by_type(migs_i_and_cmd, page_list_info, migsc_p, tdcs_p,
                                                            &iv, &page_list_i, &field_id, &sys_exported)))
    {
        goto EXIT;
    }

    // Map the page list
    page_list_p = (pa_t*)map_pa(page_list_pa.raw_void, TDX_RANGE_RW);

    /*
     * Set the field ID context for the dump operation below.
     * sys_field_is doesn't need a set context.
     */
    md_context_ptrs_t md_ctx;
    md_ctx.tdcs_ptr = tdcs_p;
    md_ctx.tdr_ptr = tdr_p;
    md_ctx.tdvps_ptr = NULL;

    bool_t continue_loop = true;
    while (continue_loop)
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
        enc_md_list_hdr_p = (md_list_header_t*)map_pa(enc_md_list_pa.raw_void, TDX_RANGE_RW);

        md_access_qualifier_t access_qual = { .raw = 0 };
        uint32_t buff_size = sizeof(md_list_t);
        // Dump the metadata list into a temporary buffer
        return_val = md_dump_list(sys_exported ? MD_CTX_TD : MD_CTX_SYS,
                                  field_id, md_ctx, &md_list.hdr, buff_size,
                                  MD_EXPORT_IMMUTABLE, access_qual, &next_field_id);

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

        if (aes_gcm_encrypt(&migsc_p->aes_gcm_context, (uint8_t*)&md_list, (uint8_t*)enc_md_list_hdr_p, _4KB) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_137, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        page_list_i++;

        return_val = handle_continues_export(&return_val, &sys_exported, &next_field_id, &mbmd_hpa_and_size, migsc_p,
                                             &mbmd_p, tdcs_p, &continue_loop, page_list_i, page_list_info, &field_id);
        if (TDX_SUCCESS != return_val)
        {
            // exit only on error
            goto EXIT;
        }
    } // while (continue_loop)

    local_data_ptr->vmm_regs.rdx = (uint64_t)page_list_i;

EXIT:
    // Release all acquired locks
    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[0]);
    }

    if (mig_locked_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_EXCLUSIVE);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_p);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (page_list_p != NULL)
    {
        free_la(page_list_p);
    }

    if (enc_md_list_hdr_p != NULL)
    {
        free_la(enc_md_list_hdr_p);
    }

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    return return_val;
}
