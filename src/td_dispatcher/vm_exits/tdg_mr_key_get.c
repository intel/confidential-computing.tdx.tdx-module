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
 * @file tdg_mr_key_get.c
 * @brief TDGMRKEYGET API handler
 */


#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "data_structures/tdx_local_data.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "crypto/sha384.h"
#include "td_transitions/td_exit.h"

api_error_type tdg_mr_key_get(uint64_t td_key_request_gpa, uint64_t key_output_gpa, uint64_t requestor_info)
{
    // Local data and TD's structures
    tdx_module_local_t* local_data_ptr = get_local_data();
    tdr_t* tdr_p = local_data_ptr->vp_ctx.tdr;
    tdcs_t* tdcs_p = local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_p = local_data_ptr->vp_ctx.tdvps;

    tdx_sanity_check(tdr_p != NULL, FATAL_ERROR_ID_376, 0);
    tdx_sanity_check(tdcs_p != NULL, FATAL_ERROR_ID_377, 1);
    tdx_sanity_check(tdvps_p != NULL, FATAL_ERROR_ID_378, 2);

    // temp variables
    pa_t tdkeyrequest_gpa = { .raw = td_key_request_gpa };    // GPA of TDKEYREQUEST
    td_key_request_t* tdrequest_p = NULL;                     // Pointer to TDKEYREQUEST
    pa_t keyoutput_gpa = { .raw = key_output_gpa };           // GPA of keyoutput
    key256_t* keyoutput_p = NULL;                             // Pointer to key output
    requestor_info_t req_info = { .raw = requestor_info };    // Requestor info structure
    api_error_type return_val = TDX_OPERAND_INVALID;

    td_key_request_t keyrequest_prot;
    seam_key_request_t seamkeyrequest;
    tdgetkey_derivation_string_t derivation_str;
    bool_t rtmr_locked_flag = false;

    tdx_module_global_t* global_data = get_global_data();

    // For non-supported sealing SoC returns TDX_OPERAND_INVALID
    if (!global_data->sealing_supported)
    {
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    // Sealing key can't be migrated to other platform as it will not work there due to different CPUSVNs
    if (!tdcs_p->executions_ctl_fields.config_flags.sealing && !tdcs_p->executions_ctl_fields.td_ctls.enable_hw_keys)
    {
        return_val = TDX_MR_KEY_GET_NOT_SUPPORTED;
        goto EXIT;
    }

    // validate the requestor info input
    if (req_info.requestor > REQUESTOR_TYPE_MAX || req_info.reserved)
    {
        TDX_ERROR("Invalid requestor info 0x%llx\n", req_info.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Check TDKEYREQUEST GPA.
    if (!is_addr_aligned_pwr_of_2(tdkeyrequest_gpa.raw, TD_KEY_REQUEST_ALIGNMENT_IN_BYTES))
    {
        TDX_ERROR("TD_KEY_REQUEST is gpa (%llx), not aligned to %d\n", tdkeyrequest_gpa.raw, TD_KEY_REQUEST_ALIGNMENT_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Translation may implicitly mutate into a TD exit or throw a #VE on EPT violation/misconfiguration
    return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                   tdvps_p,
                                                   tdkeyrequest_gpa,
                                                   tdr_p->key_management_fields.hkid,
                                                   TDX_RANGE_RO,
                                                   PRIVATE_ONLY,
                                                   (void**)&tdrequest_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", tdkeyrequest_gpa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }


    // Copy keyrequest to local copy
    tdx_memcpy(&keyrequest_prot, sizeof(keyrequest_prot), tdrequest_p, sizeof(td_key_request_t));

    // Free keyhole mapping
    free_la(tdrequest_p);
    tdrequest_p = NULL;

    // Check output key GPA.
    if (!is_addr_aligned_pwr_of_2(keyoutput_gpa.raw, MR_KEY_ALIGNMENT_IN_BYTES))
    {
        TDX_ERROR("OUTPUT KEY is gpa (%llx), not aligned to %d\n", tdkeyrequest_gpa.raw, MR_KEY_ALIGNMENT_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Translation may implicitly mutate into a TD exit or throw a #VE on EPT violation/misconfiguration
    return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                   tdvps_p,
                                                   keyoutput_gpa,
                                                   tdr_p->key_management_fields.hkid,
                                                   TDX_RANGE_RW,
                                                   PRIVATE_ONLY,
                                                   (void**)&keyoutput_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", keyoutput_gpa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Assemble derivation string while verifying requested SVNs
    // Future note: Verifying CPUSVN & TEE_TCB_SVN only applies to non-migratable keys.
    // Populate SVNs for request. These will be verified by SEAMOPS(SEAMGETKEY) later.

    basic_memset_to_zero(&seamkeyrequest, sizeof(seamkeyrequest));

    tdx_memcpy(&seamkeyrequest.cpusvn, sizeof(seamkeyrequest.cpusvn), keyrequest_prot.cpusvn, sizeof(seamkeyrequest.cpusvn));
    seamkeyrequest.tee_tcb_svn = keyrequest_prot.tee_tcb_svn;

    // Verify TD Values
    if (0 != keyrequest_prot.keyname)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_KEYNAME);
        goto EXIT;
    }

    // Verify reserved fields
    if (!tdx_memcmp_to_zero(keyrequest_prot.reserved_0, sizeof(keyrequest_prot.reserved_0)) ||
        !tdx_memcmp_to_zero(keyrequest_prot.reserved_1, sizeof(keyrequest_prot.reserved_1)) ||
        keyrequest_prot.tdkeypolicy.reserved_0 ||
        keyrequest_prot.tdkeypolicy.reserved_1 ||
        keyrequest_prot.tdkeypolicy.reserved_2 ||
        !tdx_memcmp_to_zero(keyrequest_prot.tee_tcb_svn.reserved, sizeof(keyrequest_prot.tee_tcb_svn.reserved)) ||
        (keyrequest_prot.attributes_mask.reserved_p || keyrequest_prot.attributes_mask.reserved_n ||
         keyrequest_prot.attributes_mask.reserved_tud || keyrequest_prot.attributes_mask.reserved_tup2 ||
         keyrequest_prot.attributes_mask.reserved_other) ||
        ((ia32_xcr0_t)keyrequest_prot.xfam_mask).reserved_1)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify that the request key sizes as provided in KEYSIZE_BITMAP have at least one supported key size
    // by the TDX module and by the platform.
    if ((keyrequest_prot.keysize_bitmap & global_data->sealing_supported_sizes_bitmap) == 0)
    {
        TDX_ERROR("No valid supported key size requested: keysize_bitmap = 0x%llx\n", keyrequest_prot.keysize_bitmap);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_KEYSIZE_BITMAP);
        goto EXIT;
    }

    basic_memset_to_zero(&derivation_str, sizeof(derivation_str));

    derivation_str.keyname = keyrequest_prot.keyname;
    derivation_str.sw_keyname = keyrequest_prot.sw_keyname;

    derivation_str.masked_attributes.raw = (tdcs_p->executions_ctl_fields.attributes.raw & keyrequest_prot.attributes_mask.raw);
    derivation_str.attributes_mask = keyrequest_prot.attributes_mask.raw;

    derivation_str.masked_xfam = (tdcs_p->executions_ctl_fields.xfam & keyrequest_prot.xfam_mask);
    derivation_str.xfam_mask = keyrequest_prot.xfam_mask;

    // Include Policy Selectable items
    if (keyrequest_prot.tdkeypolicy.mrtd)
    {
        tdx_memcpy(&derivation_str.mrtd, sizeof(measurement_t), &tdcs_p->measurement_fields.mrtd, sizeof(measurement_t));
    }

    if (keyrequest_prot.tdkeypolicy.mrowner)
    {
        tdx_memcpy(&derivation_str.mrowner, sizeof(measurement_t), &tdcs_p->measurement_fields.mrowner, sizeof(measurement_t));
    }

    // Acquire shared access to TDCS.RTMR
    return_val = acquire_sharex_lock_hp_sh(&tdcs_p->measurement_fields.rtmr_lock, true);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("Couldn't acquire RTMR lock\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RTMR);
        goto EXIT;
    }

    rtmr_locked_flag = true;

    for (uint8_t i = 0; i < NUM_RTMRS; i++)
    {
        if (keyrequest_prot.tdkeypolicy.rtmr & BIT(i))
        {
            tdx_memcpy(&derivation_str.rtmr[i], sizeof(measurement_t), &tdcs_p->measurement_fields.rtmr[i], sizeof(measurement_t));
        }
    }

    // For Migratable TDs, update the key derivation string build: Populate the SERVTDHASH field using the Service TD HASH of the TD.
    if (tdcs_p->executions_ctl_fields.attributes.migratable)
    {
        tdx_memcpy((void*)derivation_str.servtd_hash.bytes, sizeof(measurement_t), (void*)tdcs_p->service_td_fields.servtd_hash.bytes, sizeof(measurement_t));
	}

    derivation_str.requestor = req_info.requestor;
    derivation_str.keypolicy = keyrequest_prot.tdkeypolicy;
    
    // For all TDs, update the key derivation string build: Populate the SALT field with the corresponding values supplied by the VMM in the TDKEYREQUEST structure.
    tdx_memcpy((void*)derivation_str.salt, SIZE_OF_SALT_IN_BYTES, (void*)keyrequest_prot.salt, SIZE_OF_SALT_IN_BYTES);

    // Derive Key
    // Compute key label as SHA of derivation string
    uint384_t hash = { 0 };
    if (sha384_generate_hash((uint8_t*)(&derivation_str), sizeof(derivation_str), (uint64_t*)(&hash), true) != 0)
    {
        fatal_error(FATAL_ERROR_ID_379, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    seamkeyrequest.key_info = hash;
    seamkeyrequest.key_name_space = 1;
    seamkeyrequest.seamdb_index = tdr_p->td_preserving_fields.seamdb_index;
    seamkeyrequest.seamdb_nonce[0] = tdr_p->td_preserving_fields.seamdb_nonce.qwords[0];
    seamkeyrequest.seamdb_nonce[1] = tdr_p->td_preserving_fields.seamdb_nonce.qwords[1];
    seamkeyrequest.seamdb_nonce[2] = tdr_p->td_preserving_fields.seamdb_nonce.qwords[2];
    seamkeyrequest.seamdb_nonce[3] = tdr_p->td_preserving_fields.seamdb_nonce.qwords[3];

    // Derive key using SEAMOPS. Note this call can throw  TDCALL_STATUS
    if (SEAMOPS_SUCCESS != ia32_seamops_seam_get_key(&seamkeyrequest, keyoutput_p))
    {
        return_val = TDX_SVN_INVALID;
        goto EXIT;
    }

    tdvps_p->guest_state.gpr_state.r9 = (uint64_t)(128 << seamkeyrequest.key_size); // key size in bits

EXIT:
    if (rtmr_locked_flag)
    {
        release_sharex_lock_hp_sh(&tdcs_p->measurement_fields.rtmr_lock);
    }

    if (keyoutput_p)
    {
        free_la(keyoutput_p);
    }

    return return_val;
}
