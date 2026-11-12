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
 * @file td_mng_rd_wr
 * @brief TDHMNGRD and TDHMNGWR API handlers
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include TDVPS_FIELDS_LOOKUP_HEADER

static api_error_type tdh_mng_rdwr(uint64_t target_tdr_pa, uint64_t requested_field_code, bool_t write,
                            uint64_t wr_data, uint64_t wr_mask, uint64_t version)
{
    tdx_module_local_t * local_data = get_local_data();

    // TDR related variables
    pa_t                  tdr_pa;
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    md_field_id_t         field_id = { .raw = requested_field_code };
    uint64_t              rd_value = 0;

    md_access_t           access_type = write ? MD_HOST_WR : MD_HOST_RD;
    md_context_ptrs_t     md_ctx;
    md_access_qualifier_t access_qual = { .raw = 0 };
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // Initialize output registers to default values
    if (!write && (version > 0))
    {
        local_data->vmm_regs.rdx = MD_FIELD_ID_NA;
    }
    local_data->vmm_regs.r8 = 0ULL;

    // TDH.MNG.RD supports version 1. Other version checks are done by the SEAMCALL dispatcher.
    if (version > 1)
    {
        TDX_ERROR("Unsupported version = %llx\n", version);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 write ? TDX_RANGE_RW : TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_walk_result,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED, false,
                                               write ? TDH_MNG_WR_LEAF : TDH_MNG_RD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    access_qual.host_qualifier.debug = tdcs_ptr->executions_ctl_fields.attributes.debug;

    field_id.context_code = MD_CTX_TD;

    md_ctx.tdr_ptr = tdr_ptr;
    md_ctx.tdcs_ptr = tdcs_ptr;
    md_ctx.tdvps_ptr = NULL;

    if (!write && (version > 0))
    {
        // For read, a null field ID means return the first field ID in context
        if (is_null_field_id(field_id))
        {
            local_data->vmm_regs.rdx =
                    (md_get_next_element_in_context(MD_CTX_TD, field_id, md_ctx, access_type, access_qual)).raw;

            return_val = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
            goto EXIT;
        }
    }

    return_val = md_check_as_single_element_id(field_id);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Request field id doesn't match single element (field_id = %llx) - error = %llx\n", field_id.raw, return_val);
        goto EXIT;
    }

    /**
     *  Read or Write the data
     */
    if (write)
    {
        return_val = md_write_element(MD_CTX_TD, field_id, access_type, access_qual,
                                      md_ctx, wr_data, wr_mask, &rd_value, true);
    }
    else
    {
        return_val = md_read_element(MD_CTX_TD, field_id, access_type, access_qual,
                                     md_ctx, &rd_value);

        if ((version > 0) && (return_val == TDX_SUCCESS))
        {
            local_data->vmm_regs.rdx =
                    (md_get_next_element_in_context(MD_CTX_TD, field_id, md_ctx, access_type, access_qual)).raw;
        }
    }

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to Read or Write data to a TDR/TDCS field (field_id = %llx) - error = %llx\n", field_id.raw, return_val);
        goto EXIT;
    }

    local_data->vmm_regs.r8 = rd_value;

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }

    return return_val;
}

api_error_type tdh_mng_rd(uint64_t target_tdr_pa, uint64_t requested_field_code, uint64_t version)
{
    return tdh_mng_rdwr(target_tdr_pa, requested_field_code, false, 0, 0, version);
}

api_error_type tdh_mng_wr(uint64_t target_tdr_pa, uint64_t requested_field_code,
                          uint64_t wr_data, uint64_t wr_mask)
{
    return tdh_mng_rdwr(target_tdr_pa, requested_field_code, true, wr_data, wr_mask, 0);
}
