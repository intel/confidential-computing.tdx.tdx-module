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
 * @file tdh_mr_finalize
 * @brief TDHMRFINALIZE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "crypto/sha384.h"

api_error_type tdh_mr_finalize(uint64_t target_tdr_pa)
{
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
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
                                               false, TDH_MR_FINALIZE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // The TD must have at least one VCPU
    if (tdcs_ptr->management_fields.num_vcpus == 0)
    {
        TDX_ERROR("No VCPU's\n");
        return_val = TDX_NO_VCPUS;
        goto EXIT;
    }

    if(get_global_data()->update_compatibility && (tdcs_ptr->measurement_fields.mrtd_context_version != CRYPTO_LIB_COMPAT_VERSION))
    {
        return_val = TDX_INCOMPATIBLE_MRTD_CONTEXT;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The instruction is guaranteed to succeed

    /**
     *  Calculate finalized version of MRTD.
     *  SHA384 algorithm requires one last update that compresses the length (in bits)
     *  of the hashed message into the output SHA384 digest.
     */

    if (tdcs_ptr->measurement_fields.mrtd_context_version)
    {
        tdcs_ptr->measurement_fields.mrtd_context_version = 0;
        uint16_t old_val = _lock_xadd_16b(&get_global_data()->td_build_count, (uint16_t)-1);
        tdx_sanity_check(old_val > 0, FATAL_ERROR_ID_357, 0);
    }

    if ((sha_error_code = sha384_finalize(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                            tdcs_ptr->measurement_fields.mrtd.qwords)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        fatal_error(FATAL_ERROR_ID_113, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    calculate_servtd_hash(tdcs_ptr);


    tdcs_ptr->management_fields.op_state = OP_STATE_RUNNABLE;


EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}
