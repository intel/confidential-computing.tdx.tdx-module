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
 * @file tdh_export_abort
 * @brief TDHEXPORTABORT API handler
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

api_error_type tdh_export_abort(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t mig_stream_indx)
{

    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_walk_result_t tdr_pamt_walk_result;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_locked_flag = false;

    bool_t             op_state_locked_flag = false; // Indicate OP is locked

    // MBMD
    mbmd_t            *mbmd_p = NULL;
    hpa_and_size_t     mbmd_hpa_and_size;
    mbmd_t             mbmd;

    // Migration Stream
    uint64_t              migs_i;
    migsc_t              *migsc_p = NULL;
    pa_t                  migsc_pa;
    bool_t                mig_locked_flag = false;
    bool_t                migsc_locked_flag = false;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    migs_i = mig_stream_indx;

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
                                                TDH_EXPORT_ABORT_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.EXPORT.MEM
    if (acquire_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIG);
        TDX_ERROR("Failed to lock TDCS mig lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mig_locked_flag = true;

    // Check the stream index
    if (migs_i != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    if (tdcs_p->management_fields.op_state == OP_STATE_POST_EXPORT)
    {
        /*
         * The export session is in the post-copy phase but has not been committed,
         * process the Abort Token MBMD.
        */

        if (mbmd_hpa_and_size.size < sizeof(mbmd_t))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }

        mbmd_hpa_and_size.size = 0;

        // Verify the MBMD physical address is canonical, shared, and aligned to 128B
        pa_t mbmd_hpa_and_size_pa = { .raw = mbmd_hpa_and_size.raw };
        return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
            goto EXIT;
        }

        // Map the MBMD
        mbmd_p = (mbmd_t*)map_pa((void*)mbmd_hpa_and_size.raw, TDX_RANGE_RO);

        // Copy the MBMD to an internal buffer
        copy_mbmd(&mbmd, mbmd_p);

        // Check the MBMD
        if ((mbmd.header.mig_version != tdcs_p->migration_fields.mig_working_version) ||
            (mbmd.header.size != sizeof(mbmd_t) ||
                (mbmd.header.mb_type != MB_TYPE_ABORT_TOKEN) ||
                (mbmd.header.reserved_1 != 0) ||
                (mbmd.abort_token.reserved != 0) ||
                (mbmd.header.migs_index != 0)))
        {
            return_val = TDX_INVALID_MBMD;
            goto EXIT;
        }

        // Lock the MIGSC link
        if (!(migsc_lock(&tdcs_p->b_migsc_link)))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
            goto EXIT;
        }
        migsc_locked_flag = true;

        // Map the MIGSC
        migsc_pa.raw = 0;
        migsc_pa.page_4k_num = tdcs_p->b_migsc_link.migsc_hpa;

        migsc_p = (migsc_t*)map_pa_with_hkid(migsc_pa.raw_void,
            tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

        // preserve VMM's XCR0 and AVX states before crypto execution
        // it is required here in order to specify that AVX state preservation is needed, unlike in other migration SEAMCALLs
        prepare_state_for_avx_usage(true, false);

        // Initialize the MIGSC if needed
        if (!tdcs_p->b_migsc_link.initialized)
        {
            migsc_init(migsc_p, &tdcs_p->migration_fields.mig_dec_working_key);
            tdcs_p->b_migsc_link.initialized = true;
        }

        // Prevent later resumption of a previously interrupted function
        migsc_p->interrupted_state.valid = false;

        /* Calculate a MAC over the MACed fields of the MBMD and check that its value
         * is the same as the MAC fields value provided in the MBMD.
         */
        reset_to_next_iv(migsc_p, mbmd.header.iv_counter, mbmd.header.migs_index);

        mbmd.header.migs_index = 0;
        mbmd.header.iv_counter = 0;

        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&mbmd.abort_token, MBMD_SIZE_NO_MAC(mbmd.abort_token)) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_125, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        uint8_t   mac[MAC256_LEN];
        if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
        {
            fatal_error(FATAL_ERROR_ID_126, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        if (!tdx_memcmp_safe(mac, mbmd.abort_token.mac, sizeof(mac)))
        {
            return_val = TDX_INCORRECT_MBMD_MAC;
            goto EXIT;
        }
    }
    else // op_state != OP_STATE_POST_EXPORT
    {
        /*
         * The export session is in the pre-copy phase.  No Abort Token is expected.
         */
        if (mbmd_hpa_and_size.raw != 0)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }
    }

    if (is_non_blocking_export_configured())
    {
        return_val = mem_scan_reset(tdcs_p, false);
        if (TDX_SUCCESS != return_val)
        {
            TDX_ERROR("Failed to reset mem scan\n");
            goto EXIT;
        }
    }

    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    if ((bool_t)tdcs_p->executions_ctl2_fields.field_support_at_init & BIT(FIELD_SUPPORT_AT_INIT_MIG_INTERRUPTED_COUNT))
    {
        uint16_t old_val = _lock_xadd_16b(&get_global_data()->mig_interrupted_count, -(tdcs_p->migration_fields.mig_interrupted_count));
        tdx_sanity_check(old_val >= tdcs_p->migration_fields.mig_interrupted_count, FATAL_ERROR_ID_367, 0);
        tdcs_p->migration_fields.mig_interrupted_count = 0;
    }
    
    /* Terminate the export session
    */

    // Set all migration steams INITIALIZED and ENABLED flags to FALSE
    // Applies to forward and backward migration streams.
    for (uint16_t migs_indx = 0; migs_indx < tdcs_p->migration_fields.num_migs; migs_indx++)
    {
        tdcs_p->migsc_links[migs_indx].initialized = 0;
    }

    tdcs_p->management_fields.op_state = OP_STATE_RUNNABLE;

EXIT:
    // Release all acquired locks
    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->b_migsc_link);
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

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    return return_val;
}
