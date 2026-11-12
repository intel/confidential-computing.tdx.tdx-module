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
 * @file tdh_sys_disable.c
 * @brief TDHSYSDISABLE API handler
 */
#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "data_structures/tdx_global_data.h"
#include "helpers/helpers.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "accessors/data_accessors.h"
#include "data_structures/preserving_defs.h"
#include "tdx_vmm_api_handlers.h"

static void reset_interruption_point(tdx_module_global_t *global_data)
{
    global_data->sys_disable_intr_state.intr_point = SYS_DISABLE_START;
    global_data->sys_disable_intr_state.tdmr_index = 0;
    global_data->sys_disable_intr_state.offset_from_base = 0;
    global_data->sys_disable_intr_state.page_size = PT_4KB;
    global_data->sys_disable_intr_state.offset_in_page = 0;
    global_data->sys_disable_intr_state.lp_num = 0;
}

static bool_t convert_private_page_to_shared(uint64_t page_pa, page_size_t page_size, uint64_t* offset_in_page)
{
    uint64_t offset = *offset_in_page;
    uint64_t limit = _4KB << (9 * page_size);

    for (; offset < limit; offset += _4KB)
    {
        // Convert page to shared by mapping it with HKID 0, and clearing it with MOVDIR64B
        void* page_la = map_pa_with_hkid((void*)(page_pa + offset), 0, TDX_RANGE_RW);
        zero_area_cacheline(page_la, _4KB);
        free_la(page_la);

        if (((offset + _4KB) < limit) && is_interrupt_pending_host_side())
        {
            *offset_in_page = offset + _4KB;
            return true;
        }
    }

    *offset_in_page = 0;
    return false;
}

static pamt_entry_t* pamt_quick_walk(tdmr_entry_t* tdmr_entry, page_size_t* page_size, uint64_t offset,
                                              uint64_t* dyn_node_page)
{
    // Quick PAMT walk that finds the lowest PAMT entry pointing to a page (or 4KB entry),
    // starting from *page_size

    pamt_entry_t* pamt_4kb_p = (pamt_entry_t*)tdmr_entry->pamt_4k_base;
    pamt_entry_t* pamt_2mb_p = (pamt_entry_t*)tdmr_entry->pamt_2m_base;
    pamt_entry_t* pamt_1gb_p = (pamt_entry_t*)tdmr_entry->pamt_1g_base;

    pa_t pa = { .raw = offset };

    pa_t pamt_4kb_pp;

    pamt_entry_t* pamt_entry_p = NULL;

    if (*page_size == PT_4KB)
    {
        goto PAMT_4K_SIZE;
    }

    if (*page_size == PT_2MB)
    {
        goto PAMT_2MB_SIZE;
    }

    pamt_entry_p = map_pa_with_global_hkid(&pamt_1gb_p[pa.page_1g_num], TDX_RANGE_RO);
    if (pamt_entry_p->pt == PT_REG)
    {
        *page_size = PT_1GB;
        return pamt_entry_p;
    }

    free_la(pamt_entry_p);

PAMT_2MB_SIZE:

    pamt_entry_p = map_pa_with_global_hkid(&pamt_2mb_p[pa.page_2m_num], TDX_RANGE_RO);

    if (pamt_entry_p->pt == PT_REG)
    {
        *page_size = PT_2MB;
        return pamt_entry_p;
    }

    free_la(pamt_entry_p);

PAMT_4K_SIZE:

    if (get_global_data()->dynamic_pamt_enabled)
    {
        pamt_non_leaf_entry_t* pamt_2mb_node = map_pa_with_global_hkid(&pamt_2mb_p[pa.page_2m_num], TDX_RANGE_RO);

        if (pamt_2mb_node->pt != PT_PAMT)
        {
            // No 2MB entry - return NULL
            free_la(pamt_2mb_node);
            *page_size = PT_2MB;
            return NULL;
        }

        pa_t node_page = (pa.pamt_4k_in_2mb.idx < 256) ? get_pamt_node_page0(pamt_2mb_node) :
                                                         get_pamt_node_page1(pamt_2mb_node);

        *dyn_node_page = node_page.raw;

        free_la(pamt_2mb_node);

        pamt_4kb_pp.raw_void = &(((pamt_entry_t*)node_page.raw_void)[pa.pamt_4k_in_2mb.idx % 256]);
    }
    else
    {
        pamt_4kb_pp.raw_void = &pamt_4kb_p[pa.page_4k_num];
    }

    pamt_entry_p = map_pa_with_global_hkid(pamt_4kb_pp.raw_void, TDX_RANGE_RO);

    *page_size = PT_4KB;

    return pamt_entry_p;
}

static void save_interrupt_point(sys_disable_interruption_point intr_point, uint32_t tdmr_index,
                                 page_size_t page_size, uint64_t offset, uint64_t offset_in_page,
                                 tdx_module_global_t *global_data)
{
    // Interrupt detected
    global_data->sys_disable_intr_state.intr_point = intr_point;
    global_data->sys_disable_intr_state.tdmr_index = tdmr_index;
    global_data->sys_disable_intr_state.page_size = page_size;
    global_data->sys_disable_intr_state.offset_from_base = offset;
    global_data->sys_disable_intr_state.offset_in_page = offset_in_page;
}

static bool_t memory_reset(tdx_module_global_t* global_data)
{
    // Restore interruption point data
    uint32_t tdmr_index = global_data->sys_disable_intr_state.tdmr_index;
    page_size_t page_size = global_data->sys_disable_intr_state.page_size;
    uint64_t offset = global_data->sys_disable_intr_state.offset_from_base;
    uint64_t offset_in_page = global_data->sys_disable_intr_state.offset_in_page;

    // Loop over all TDMR's
    for (; tdmr_index < global_data->num_of_tdmr_entries; tdmr_index++)
    {
        tdmr_entry_t* tdmr_entry = &global_data->tdmr_table[tdmr_index];
        bool_t non_first_iteration = false;

        uint64_t size_to_reset = (tdmr_entry->last_initialized & ~(_1GB - 1)) - tdmr_entry->base;

        for (; offset < size_to_reset; offset += (_4KB << (page_size * 9)))
        {
            // Sometimes we may loop over many PAMT entries that don't point to actual pages,
            // so we need to check for interrupt here also, and not only when we convert page
            if (non_first_iteration && is_interrupt_pending_host_side())
            {
                // Interrupt detected
                save_interrupt_point(SYS_DISABLE_MEMORY_RESET, tdmr_index, page_size, offset,
                                     offset_in_page, global_data);
                return true;
            }

            non_first_iteration = true;

            page_size = PT_4KB;
            pamt_entry_t* pamt_entry_p = NULL;
            uint64_t dyn_node_page = NULL_PA;

            // If we are at a start of 1GB/2MB range, check if we actually have a large page there.
            // pamt_quick_walk will reach and return the lowest page if it's a PT_REG
            IF_RARE ((offset % _1GB) == 0)
            {
                page_size = PT_1GB;
            }
            else IF_RARE ((offset % _2MB) == 0)
            {
                page_size = PT_2MB;
            }

            pamt_entry_p = pamt_quick_walk(tdmr_entry, &page_size, offset, &dyn_node_page);

            // In case of enabled dynamic PAMT we might receive NULL entry from the helper function
            // That means that the whole 2MB range doesn't exist, and we should skip it
            if (pamt_entry_p == NULL)
            {
                continue;
            }

            // If PAMT entry points to an actual page - convert it to shared
            if ((pamt_entry_p->pt != PT_NDA) && (pamt_entry_p->pt != PT_RSVD))
            {
                bool_t interrupt = convert_private_page_to_shared(tdmr_entry->base + offset, page_size, &offset_in_page);

                if (interrupt)
                {
                    // Interrupt detected
                    save_interrupt_point(SYS_DISABLE_MEMORY_RESET, tdmr_index, page_size, offset,
                                         offset_in_page, global_data);

                    free_la(pamt_entry_p);
                    return true;
                }
            }

            free_la(pamt_entry_p);

            // For Dynamic PAMT, once we finished clearing 1MB range of memory, clear also
            // the corresponding 4KB PAMT page that points to it
            if (global_data->dynamic_pamt_enabled)
            {
                // If we finished the last 4KB page in 1MB range
                if ((page_size == PT_4KB) && ((offset + _4KB) % _1MB == 0))
                {
                    uint64_t single_page_offset = 0;
                    convert_private_page_to_shared(dyn_node_page, page_size, &single_page_offset);
                }
            }
        }

        offset = 0;
    }

    reset_interruption_point(global_data);
    return false;
}

static bool_t pamt_reset(tdx_module_global_t* global_data)
{
    uint32_t tdmr_index = global_data->sys_disable_intr_state.tdmr_index;
    page_size_t pamt_size = global_data->sys_disable_intr_state.page_size;
    uint64_t offset = global_data->sys_disable_intr_state.offset_from_base;
    uint64_t offset_in_page = 0;

    // Loop over all TDMR's
    for (; tdmr_index < global_data->num_of_tdmr_entries; tdmr_index++)
    {
        tdmr_entry_t* tdmr_entry = &global_data->tdmr_table[tdmr_index];

        // Loop over all the 3 PAMT arrays
        for (; pamt_size <= PT_1GB; pamt_size++)
        {
            uint64_t pamt_array_pa;
            uint64_t pamt_array_size;

            if (pamt_size == PT_4KB)
            {
                pamt_array_pa = tdmr_entry->pamt_4k_base;
                // For Dynamic PAMT, once we finished clearing 1MB range of memory, clear also
                // the corresponding 4KB PAMT page that points to it
                if (global_data->dynamic_pamt_enabled)
                {
                    // Calculate required size for a bitmap, as 4K PAMT area serves as a bitmap instead
                    pamt_array_size = (tdmr_entry->size / _4KB) / 8;
                }
                else
                {
                    pamt_array_size = (tdmr_entry->size / _4KB) * sizeof(pamt_entry_t);
                }
            }
            else if (pamt_size == PT_2MB)
            {
                pamt_array_pa = tdmr_entry->pamt_2m_base;
                pamt_array_size = (tdmr_entry->size / _2MB) * sizeof(pamt_entry_t);
            }
            else
            {
                pamt_array_pa = tdmr_entry->pamt_1g_base;
                pamt_array_size = (tdmr_entry->size / _1GB) * sizeof(pamt_entry_t);
            }

            for (; offset < pamt_array_size; offset += _4KB)
            {
                convert_private_page_to_shared(pamt_array_pa + offset, PT_4KB, &offset_in_page);

                if (is_interrupt_pending_host_side())
                {
                    // Interrupt detected
                    offset += _4KB;
                    save_interrupt_point(SYS_DISABLE_PAMT_RESET, tdmr_index, pamt_size, offset, 0, global_data);

                    return true;
                }
            }

            offset = 0;
        }

        pamt_size = PT_4KB;
    }

    reset_interruption_point(global_data);
    return false;
}

static bool_t lp_state_reset(tdx_module_global_t* global_data, sysinfo_table_t* sysinfo_table)
{
    for (uint64_t lp_num = global_data->sys_disable_intr_state.lp_num;
         lp_num < get_num_addressable_lps(sysinfo_table); lp_num++)
    {
        // Skip current LP local data
        if (lp_num == get_local_data()->lp_info.x2apic_id)
        {
            continue;
        }

        tdx_module_local_t* other_lp_local_data = get_other_lp_local_data(sysinfo_table, lp_num);

        void* local_data_fast_ref_ptr = other_lp_local_data->local_data_fast_ref_ptr;
        void* global_data_fast_ref_ptr = other_lp_local_data->global_data_fast_ref_ptr;
        void* sysinfo_fast_ref_ptr = other_lp_local_data->sysinfo_fast_ref_ptr;
        uint32_t x2apic_id = other_lp_local_data->lp_info.x2apic_id;
        uint64_t stack_canary = other_lp_local_data->stack_canary;

        basic_memset_to_zero((void*)((uint64_t)other_lp_local_data + sizeof(gprs_state_t)),
                             sizeof(tdx_module_local_t) - sizeof(gprs_state_t));

        other_lp_local_data->local_data_fast_ref_ptr = local_data_fast_ref_ptr;
        other_lp_local_data->global_data_fast_ref_ptr = global_data_fast_ref_ptr;
        other_lp_local_data->sysinfo_fast_ref_ptr = sysinfo_fast_ref_ptr;
        other_lp_local_data->lp_info.x2apic_id = x2apic_id;
        other_lp_local_data->stack_canary = stack_canary;

        if (is_interrupt_pending_host_side())
        {
            // Interrupt detected
            global_data->sys_disable_intr_state.intr_point = SYS_DISABLE_LP_STATE_RESET;
            global_data->sys_disable_intr_state.lp_num = lp_num + 1;
            return true;
        }
    }

    reset_interruption_point(global_data);
    return false;
}

static bool_t keyhole_state_reset(tdx_module_global_t* global_data, sysinfo_table_t* sysinfo_table)
{
    uint64_t offset = global_data->sys_disable_intr_state.offset_from_base;

    for (; offset < sysinfo_table->keyhole_edit_rgn_size; offset += _4KB)
    {
        // Remove protection from keyhole entry pages
        ia32_set_ac();

        basic_memset_to_zero((void*)(sysinfo_table->keyhole_edit_rgn_base + offset), _4KB);

        ia32_clear_ac();

        if (is_interrupt_pending_host_side())
        {
            // Interrupt detected
            global_data->sys_disable_intr_state.intr_point = SYS_DISABLE_KEYHOLE_STATE_RESET;
            global_data->sys_disable_intr_state.offset_from_base = offset + _4KB;
            return true;
        }
    }

    reset_interruption_point(global_data);
    return false;
}

static bool_t handoff_data_reset(tdx_module_global_t* global_data, sysinfo_table_t* sysinfo_table)
{
    uint64_t offset = global_data->sys_disable_intr_state.offset_from_base;

    for (; offset < (sysinfo_table->num_handoff_pages + 1) * _4KB; offset += _4KB)
    {
        basic_memset_to_zero((void*)(sysinfo_table->data_rgn_base + offset), _4KB);

        if (is_interrupt_pending_host_side())
        {
            // Interrupt detected
            global_data->sys_disable_intr_state.intr_point = SYS_DISABLE_HANDOFF_RESET;
            global_data->sys_disable_intr_state.offset_from_base = offset + _4KB;
            return true;
        }
    }

    reset_interruption_point(global_data);
    return false;
}

static void global_data_reset(tdx_module_global_t* global_data)
{
    // Start zeroing the global data after the lock, state and sys_disable intr state fields
    // as we need them preserved until the end of the API
    uint64_t base = (uint64_t)(&global_data->sys_disable_intr_state) + sizeof(sys_disable_interruption_state_t);
    uint64_t size = sizeof(tdx_module_global_t) - (base - (uint64_t)global_data);

    basic_memset_to_zero((void*)base, size);
}

static void current_lp_state_reset(void)
{
    // Must be volatile to make sure it's stored in actual variable
    // since we clean/restore local data fast pointer at the end
    volatile tdx_module_local_t* local_data = get_local_data();

    // Zero out the current LP state but keep the stack canary value.
    // Keep also the VMM regs at the beginning so we can return normally to the VMM
    // Keep also the LAM and SPEC_CTRL MSR's that are required during vmm_post_dispatching
    // Keep also the stack canary

    uint64_t ia32_spec_ctrl = local_data->vmm_non_extended_state.ia32_spec_ctrl;
    uint64_t ia32_lam_enable = local_data->vmm_non_extended_state.ia32_lam_enable;

    void* local_data_fast_ref_ptr = local_data->local_data_fast_ref_ptr;
    void* global_data_fast_ref_ptr = local_data->global_data_fast_ref_ptr;
    void* sysinfo_fast_ref_ptr = local_data->sysinfo_fast_ref_ptr;
    uint32_t x2apic_id = local_data->lp_info.x2apic_id;
    uint64_t stack_canary = local_data->stack_canary;

    basic_memset_to_zero((void*)((uint64_t)local_data + sizeof(gprs_state_t)),
                         sizeof(tdx_module_local_t) - sizeof(gprs_state_t));

    local_data->vmm_non_extended_state.ia32_spec_ctrl = ia32_spec_ctrl;
    local_data->vmm_non_extended_state.ia32_lam_enable = ia32_lam_enable;

    local_data->local_data_fast_ref_ptr = local_data_fast_ref_ptr;
    local_data->global_data_fast_ref_ptr = global_data_fast_ref_ptr;
    local_data->sysinfo_fast_ref_ptr = sysinfo_fast_ref_ptr;
    local_data->lp_info.x2apic_id = x2apic_id;
    local_data->stack_canary = stack_canary;
}

api_error_type tdh_sys_disable(void)
{
    api_error_type return_val = TDX_SUCCESS;
    tdx_module_global_t* global_data = get_global_data();
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();
    bool_t global_lock_acquired = false;

    if (acquire_sharex_lock_ex(&global_data->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock\n");
        return_val = TDX_SYS_BUSY;
        goto EXIT;
    }

    global_lock_acquired = true;

    // If we are already in SYS_DISABLE state, jump to the relevant interruption point
    if (SYS_DISABLE == global_data->global_state.sys_state)
    {
        if (global_data->sys_disable_intr_state.working_lp != get_local_data()->lp_info.x2apic_id)
        {
            TDX_ERROR("API must be resumed from the same LP that started it\n");
            return_val = TDX_RESUME_LP_MISMATCH;
            goto EXIT;
        }

        switch (global_data->sys_disable_intr_state.intr_point)
        {
            case SYS_DISABLE_MEMORY_RESET:
                goto MEMORY_RESET;
            case SYS_DISABLE_PAMT_RESET:
                goto PAMT_RESET;
            case SYS_DISABLE_LP_STATE_RESET:
                goto LP_STATE_RESET;
            case SYS_DISABLE_KEYHOLE_STATE_RESET:
                goto KEYHOLE_STATE_RESET;
            case SYS_DISABLE_HANDOFF_RESET:
                goto HANDOFF_DATA_RESET;
            default:
                fatal_error(FATAL_ERROR_ID_386, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
                break;
        }
    }

    // Abort with TDX_SYS_NOT_READY error if global state is not SYS_READY.
    if (SYS_READY != global_data->global_state.sys_state)
    {
        return_val = TDX_SYS_NOT_READY;
        TDX_ERROR("TDX system state is not SYS_READY, current state = %d\n", global_data->global_state.sys_state);
        goto EXIT;
    }

    // Set the TDX module global state to SYS_DISABLE.
    global_data->global_state.sys_state = SYS_DISABLE;
    
    // Serialize global system state setup
    mfence();

    // Remember the LP that started running this API
    global_data->sys_disable_intr_state.working_lp = get_local_data()->lp_info.x2apic_id;

    // If any other LP is executing in SEAM mode, restore the global state to SYS_READY and return with TDX_SYS_BUSY error code. 
    uint32_t num_busy = 0;
    for (uint64_t lp_num = 0; lp_num < get_num_addressable_lps(sysinfo_table); lp_num++)
    {
        if (get_other_lp_local_data(sysinfo_table, lp_num)->lp_is_busy)
        {
            num_busy++;
        }
    }

    tdx_sanity_check(num_busy > 0, FATAL_ERROR_ID_385, 1);

    if (num_busy > 1)
    {
        global_data->global_state.sys_state = SYS_READY;
        return_val = TDX_SYS_BUSY;
        TDX_ERROR("Another LP is executing in SEAM mode, cannot proceed with TDH.SYS.DISABLE\n");
        goto EXIT;
    }

    reset_interruption_point(global_data);



MEMORY_RESET:
    // Memory Reset:  Convert all the TD and TDX Module’s private pages, as referenced
    // by the PAMT entries, to shared memory.
    if (memory_reset(global_data))
    {
        return_val = TDX_INTERRUPTED_RESUMABLE;
        goto EXIT;
    }

PAMT_RESET:
    // PAMT Reset:  Convert the PAMT arrays memory to shared memory.
    if (pamt_reset(global_data))
    {
        return_val = TDX_INTERRUPTED_RESUMABLE;
        goto EXIT;
    }
    

LP_STATE_RESET:

    // Reset TDX module memory and return the TDX module to initialize state.
    // Zero out all LP's state (set the LP state data to all 0s using REP STOSQ) but the current LP.
    if (lp_state_reset(global_data, sysinfo_table))
    {
        return_val = TDX_INTERRUPTED_RESUMABLE;
        goto EXIT;
    }

KEYHOLE_STATE_RESET:

    // Zero out all LP's keyhole state.
    if (keyhole_state_reset(global_data, sysinfo_table))
    {
        return_val = TDX_INTERRUPTED_RESUMABLE;
        goto EXIT;
    }

HANDOFF_DATA_RESET:

    // Zero out HANDOFF data area.
    if (handoff_data_reset(global_data, sysinfo_table))
    {
        return_val = TDX_INTERRUPTED_RESUMABLE;
        goto EXIT;
    }

    // Zero out global data, besides the lock state and the TDX module system state.
    global_data_reset(global_data);

    // Set the TDX module global state to its initial value, SYSINIT_PENDING.
    global_data->sys_disable_intr_state.intr_point = SYS_DISABLE_START;
    global_data->global_state.sys_state = SYSINIT_PENDING;

    // Zero out the current LP state
    current_lp_state_reset();

    // Return with TDX_SUCCESS.
    return_val = TDX_SUCCESS;

EXIT:

    if (global_lock_acquired)
    {
        release_sharex_lock_ex(&global_data->global_lock);
    }

    return return_val;
}
