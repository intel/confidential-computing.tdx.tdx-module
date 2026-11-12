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
 * @file data_accessors.h
 * @brief Global and local data accessors, and SYSINFO table acessors
 */

#ifndef SRC_COMMON_ACCESSORS_DATA_ACCESSORS_H_
#define SRC_COMMON_ACCESSORS_DATA_ACCESSORS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/loader_data.h"

//****************************************************************************************
// Optimized accessors to SEAM module data structures - always use those in the code
//****************************************************************************************
// Explanation on the syntax below:
// The "i" constraint creates a constant integer immediate input constraint with a symbolic name, "local_data".
// The square brackets are the syntax to reference the immediate.
// And the '%c' syntax is necessary to get the formatting correct for using the constant as a memory operand.
// More info:
// https://gcc.gnu.org/onlinedocs/gcc/Simple-Constraints.html#Simple-Constraints,
// https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#InputOperands
// https://gcc.gnu.org/onlinedocs/gccint/Output-Template.html#Output-Template.

_STATIC_INLINE_ tdx_module_local_t* get_local_data(void)
{
    uint64_t local_data_addr;

    _ASM_ ("movq %%gs:%c[local_data], %0\n\t"
             :"=r"(local_data_addr)
             :[local_data]"i"(offsetof(tdx_module_local_t, local_data_fast_ref_ptr)));

    return (tdx_module_local_t*)local_data_addr;
}


_STATIC_INLINE_ sysinfo_table_t* get_sysinfo_table(void)
{
    uint64_t sysinfo_table_addr;
    _ASM_ ("movq %%gs:%c[sysinfo], %0\n\t"
             :"=r"(sysinfo_table_addr)
             :[sysinfo]"i"(offsetof(tdx_module_local_t, sysinfo_fast_ref_ptr)));

    return (sysinfo_table_t*)sysinfo_table_addr;
}

_STATIC_INLINE_ tdx_module_global_t* get_global_data(void)
{
    uint64_t global_data_addr;
    _ASM_ ("movq %%gs:%c[global_data], %0\n\t"
             :"=r"(global_data_addr)
             :[global_data]"i"(offsetof(tdx_module_local_t, global_data_fast_ref_ptr)));

    return (tdx_module_global_t*)global_data_addr;
}

#define LOCAL_DATA_SIZE_PER_LP         (TDX_PAGE_SIZE_IN_BYTES * (get_sysinfo_table()->num_tls_pages + 1))

_STATIC_INLINE_ uint64_t get_current_thread_num(sysinfo_table_t* sysinfo_table, tdx_module_local_t* local_data)
{
    uint64_t current_local_data_addr = (uint64_t)local_data;
    uint64_t local_data_start_addr = sysinfo_table->data_rgn_base;

    local_data_start_addr += (sysinfo_table->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES;

    uint64_t local_data_size_per_lp = (TDX_PAGE_SIZE_IN_BYTES * (sysinfo_table->num_tls_pages + 1));

    return (current_local_data_addr - local_data_start_addr) / local_data_size_per_lp;
}

_STATIC_INLINE_ uint64_t get_num_addressable_lps(sysinfo_table_t* sysinfo_table)
{
    return ((sysinfo_table->stack_rgn_size / TDX_PAGE_SIZE_IN_BYTES) /
            (sysinfo_table->num_stack_pages + 1 + 1));
}

//************************************************************************************************
// Raw non-optimized accessors to SEAM module data structures - should not be used in general code
//************************************************************************************************

// In SEAM TDX module, GSBASE holds a pointer to the local data of current thread
// We are reading GSBASE by loading effective address of 0 with GS prefix
_STATIC_INLINE_ tdx_module_local_t* calculate_local_data(void)
{
    void* local_data_addr;
    _ASM_VOLATILE_ ("rdgsbase %0"
                    :"=r"(local_data_addr)
                    : :);

    return (tdx_module_local_t*)local_data_addr;
}

// In SEAM TDX module, FSBASE holds a pointer to the SYSINFO table
// We are reading FSBASE by loading effective address of 0 with FS prefix
_STATIC_INLINE_ sysinfo_table_t* calculate_sysinfo_table(void)
{
    void* sysinfo_table_addr;
    _ASM_VOLATILE_ ("rdfsbase %0"
                    :"=r"(sysinfo_table_addr)
                    : :);

    return (sysinfo_table_t*)sysinfo_table_addr;
}

_STATIC_INLINE_ tdx_module_global_t* calculate_global_data(sysinfo_table_t* sysinfo_table)
{
    // For each addressable LP, there are D pages of data stack and 1 page of shadow stack,
    // where D = NUM_STACK_PAGES + 1.
    // STACK_REGION_SIZE gives the size (in bytes) of all stack pages, i.e. STACK_REGION_SIZE = (D + 1) * N * 4K.
    // Therefore, N = (STACK_REGION_SIZE / 4K) / (D + 1) = (STACK_REGION_SIZE >> 12) / (NUM_STACK_PAGES + 1 + 1).

    uint64_t num_of_addressable_lp = get_num_addressable_lps(sysinfo_table);

    uint64_t local_data_size_per_lp = (TDX_PAGE_SIZE_IN_BYTES * (sysinfo_table->num_tls_pages + 1));

    uint64_t global_data_addr = sysinfo_table->data_rgn_base +
            num_of_addressable_lp * local_data_size_per_lp;

    global_data_addr += (sysinfo_table->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES;

    return (tdx_module_global_t*)global_data_addr;
}

// Must be done before accessing local/global data or sysinfo table through optimized data accessors
_STATIC_INLINE_ void init_data_fast_ref_ptrs(tdx_module_local_t* local_data_ptr_from_gsbase)
{
    tdx_module_local_t* local_data = local_data_ptr_from_gsbase;

    IF_RARE (!local_data->local_data_fast_ref_ptr)
    {
        local_data->local_data_fast_ref_ptr  = local_data;
        local_data->sysinfo_fast_ref_ptr     = calculate_sysinfo_table();
        local_data->global_data_fast_ref_ptr = calculate_global_data((sysinfo_table_t *) local_data->sysinfo_fast_ref_ptr);

        // Calc LPID from local_data_ptr
        local_data->lp_info.x2apic_id = (uint32_t)get_current_thread_num((sysinfo_table_t *) local_data->sysinfo_fast_ref_ptr, local_data);
    }
}

//****************************************************************************************
// All the other accessors to SEAM module data structures
//****************************************************************************************

_STATIC_INLINE_ tdx_module_local_t* get_other_lp_local_data(sysinfo_table_t* sysinfo_table, uint64_t lp_num)
{
    uint64_t local_data_start = sysinfo_table->data_rgn_base;

    local_data_start += (sysinfo_table->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES;

    uint64_t local_data_size_per_lp = (TDX_PAGE_SIZE_IN_BYTES * (sysinfo_table->num_tls_pages + 1));

    return (tdx_module_local_t*)(local_data_start + (local_data_size_per_lp * lp_num));
}

#endif /* SRC_COMMON_ACCESSORS_DATA_ACCESSORS_H_ */
