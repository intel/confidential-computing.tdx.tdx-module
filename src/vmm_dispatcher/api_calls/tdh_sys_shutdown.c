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
 * @file tdh_sys_shutdown
 * @brief TDH_SYS_SHUTDOWN API handler
 */

#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER

#include "data_structures/tdx_global_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "helpers/preserving.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"

api_error_type tdh_sys_shutdown(uint64_t handoff)
{
    // Global data
    tdx_module_global_t* global_data = get_global_data();
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    bool_t global_locked_flag = false;
    api_error_type ret_val = TDX_OPERAND_INVALID;

    handoff_input_param_t handoff_input = { .raw = handoff };

    // Verify that request HV is supported and reserved field is 0
    if ((handoff_input.handoff_version < global_data->min_update_hv) ||
        (handoff_input.handoff_version > global_data->module_hv) ||
        (global_data->no_downgrade && (handoff_input.handoff_version != global_data->module_hv)) ||
        (handoff_input.reserved))
    {
        ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Acquire an exclusive lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_ex(&global_data->global_lock) != LOCK_RET_SUCCESS)
    {
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_locked_flag = true;

    // This is checked by the VMM dispatcher
    tdx_sanity_check(global_data->global_state.sys_state == SYS_READY, FATAL_ERROR_ID_301, 0);

    // Mark the TDX-SEAM module as being shut down
    global_data->global_state.sys_state = SYS_SHUTDOWN;

    // Serialize global system state setup
    mfence();

    // Verify that no other LP is "busy"
    uint32_t num_busy = 0;

    for (uint64_t lp_num = 0; lp_num < get_num_addressable_lps(sysinfo_table); lp_num++)
    {
        if (get_other_lp_local_data(sysinfo_table, lp_num)->lp_is_busy)
        {
            num_busy++;
        }
    }

    tdx_sanity_check(num_busy > 0, FATAL_ERROR_ID_302, 1);

    if (num_busy > 1) // another LP is in SEAM mode
    {
        global_data->global_state.sys_state = SYS_READY;
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }

    // if AVOID_COMPAT_SENSITIVE is set and either TD_BUILD_COUNT or MIG_INTERRUPTED_COUNT aren't zero
    if(handoff_input.avoid_compat_sensitive && (global_data->td_build_count || global_data->mig_interrupted_count))
    {
        global_data->global_state.sys_state = SYS_READY;
        ret_val = TDX_UPDATE_COMPATIBILITY_SENSITIVE;

        if (global_data->td_build_count)
        {
            // If PL.TD_BUILD_COUNT is not 0, revert PL.SYS_STATE and return a TDX_UPDATE_COMPATIBILITY_SENSITIVE error,
            // with bits 15:0 set to 0 and bits 31:16 set to PL.TD_BUILD_COUNT.
            ret_val |= ((uint64_t)global_data->td_build_count << 16);
        }
        else
        {
            // If PL.MIG_INTERRUPTED_COUNT is not 0, revert PL.SYS_STATE and return a TDX_UPDATE_COMPATIBILITY_SENSITIVE error,
            // with bits 15:0 set to 1 and bits 31:16 set to PL. MIG_INTERRUPTED_COUNT.
            ret_val |= (((uint64_t)global_data->mig_interrupted_count << 16) | 1);
        }

        goto EXIT;
    }

    prepare_handoff_data(handoff_input.handoff_version);

    ret_val = TDX_SUCCESS;

EXIT:
    // Release all locks
    if (global_locked_flag)
    {
        release_sharex_lock_ex(&global_data->global_lock);
    }

    return ret_val;
}
