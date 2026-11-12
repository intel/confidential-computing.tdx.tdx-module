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
 * @file tdh_vp_rd_wr
 * @brief TDHVPRD and TDHVPWR API handlers
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
#include "metadata_handlers/metadata_generic.h"

static api_error_type tdh_vp_rd_wr(uint64_t target_tdvpr_pa,
                            md_field_id_t field_code,
                            tdx_module_local_t * local_data_ptr,
                            bool_t write,
                            uint64_t wr_data,
                            uint64_t wr_request_mask,
                            uint64_t version)
{
    // TDVPS related variables
    pa_t                  tdvpr_pa = {.raw = target_tdvpr_pa};  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;                     // Pointer to the TDVPS structure ((Multi-page linear address)
    pamt_walk_result_t    tdvpr_pamt_walk_result;
    bool_t                tdvpr_locked_flag = false;            // Indicate TDVPR is locked

    // TDR related variables
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr = NULL;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    md_field_id_t         requested_field_id = field_code;

    uint16_t              curr_hkid;

    uint64_t              rd_data;

    md_access_t           access_type = write ? MD_HOST_WR : MD_HOST_RD;
    md_context_ptrs_t     md_ctx;
    md_access_qualifier_t access_qual = { .raw = 0 };
    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Initialize output registers to default values
    if (!write && (version > 0))
    {
        local_data_ptr->vmm_regs.rdx = MD_FIELD_ID_NA;
    }
    local_data_ptr->vmm_regs.r8 = 0ULL;

    // TDH.VP.RD supports version 1.  Other version checks are done by the SEAMCALL dispatcher.
    if ((!write) && (version > 1))
    {
        TDX_ERROR("Unsupported version = %llx\n", version);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_SHARED,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_walk_result,
                                                         &tdvpr_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock and map the TDR page
    return_val = lock_and_map_implicit_tdr(get_pamt_entry_owner(tdvpr_pamt_walk_result.pamt_entry_p),
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RO,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, write ? TDH_VP_WR_LEAF : TDH_VP_RD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get the TD's ephemeral HKID
    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the multi-page TDVPS structure
    tdvps_ptr = map_tdvps(tdvpr_pa, curr_hkid, tdcs_ptr->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    /**
     *  Associate the VCPU. On read, allow association even if the VCPU is disabled
     */
    bool_t associate_flag = false;
    if ((return_val = check_and_associate_vcpu(tdvps_ptr, tdcs_ptr, &associate_flag, !write)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to associate VCPU - error = %llx\n", return_val);
        goto EXIT;
    }

    md_ctx.tdr_ptr = tdr_ptr;
    md_ctx.tdcs_ptr = tdcs_ptr;
    md_ctx.tdvps_ptr = tdvps_ptr;

    access_qual.host_qualifier.debug = tdcs_ptr->executions_ctl_fields.attributes.debug;

    requested_field_id.context_code = MD_CTX_VP;

    if (!write && (version > 0))
    {
        // For read, a null field ID means return the first field ID in context
        if (is_null_field_id(requested_field_id))
        {
            local_data_ptr->vmm_regs.rdx =
                    (md_get_next_element_in_context(MD_CTX_VP, requested_field_id, md_ctx, access_type, access_qual)).raw;

            return_val = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
            goto EXIT;
        }
    }

    return_val = md_check_as_single_element_id(requested_field_id);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Request field id doesn't match single element = %llx\n", requested_field_id.raw);
        goto EXIT;
    }

    /**
     *  Read or Write the data
     */
    if (write)
    {
        return_val = md_write_element(MD_CTX_VP, requested_field_id, access_type, access_qual,
                                      md_ctx, wr_data, wr_request_mask, &rd_data, true);
    }
    else
    {
        return_val = md_read_element(MD_CTX_VP, requested_field_id, access_type, access_qual,
                                     md_ctx, &rd_data);

        if ((version > 0) && (return_val == TDX_SUCCESS))
        {
            local_data_ptr->vmm_regs.rdx =
                    (md_get_next_element_in_context(MD_CTX_VP, requested_field_id, md_ctx, access_type, access_qual)).raw;
        }
    }

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to Read or Write data to a TDVPS field (field_id = %llx) - error = %llx\n", requested_field_id.raw, return_val);
        goto EXIT;
    }

    // Write data to r8
    local_data_ptr->vmm_regs.r8 = rd_data;

EXIT:

    set_seam_vmcs_as_active();

    // Release all acquired locks and free keyhole mappings
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }

    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }

    if (tdvpr_locked_flag)
    {
        pamt_unwalk(&tdvpr_pamt_walk_result);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    return return_val;
}


api_error_type tdh_vp_wr(uint64_t tdvpr_pa,
                         md_field_id_t field_code,
                         uint64_t wr_data,
                         uint64_t wr_mask)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    return tdh_vp_rd_wr(tdvpr_pa, field_code, local_data_ptr, true, wr_data, wr_mask, 0);
}


api_error_type tdh_vp_rd(uint64_t tdvpr_pa, md_field_id_t field_code, uint64_t version)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    return tdh_vp_rd_wr(tdvpr_pa, field_code, local_data_ptr, false, 0, 0, version);
}



