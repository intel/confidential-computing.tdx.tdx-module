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
 * @file keyhole_manager.c
 * @brief Keyhole manager implementation
 */

#include "keyhole_manager.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/loader_data.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"

_STATIC_INLINE_ uint64_t la_from_keyhole_idx(uint16_t keyhole_idx)
{
    // The keyhole mechanism allows LP with LPID = i to map at most M = 128 physical pages.
    // M keyhole access pages, starting at linear address Vi = Sysinfo.KeyholeRegionBase + i * M * 4K

    tdx_debug_assert(keyhole_idx < MAX_KEYHOLE_PER_LP);

    return get_sysinfo_table()->keyhole_rgn_base +
            (((uint64_t)get_local_data()->lp_info.x2apic_id * MAX_KEYHOLE_PER_LP + keyhole_idx) * (uint64_t)0x1000);
}

_STATIC_INLINE_ uint16_t keyhole_idx_from_la(uint64_t la)
{
    // The keyhole mechanism allows LP with LPID = i to map at most M = 128 physical pages.
    // M keyhole access pages, starting at linear address Vi = Sysinfo.KeyholeRegionBase + i * M * 4K

    tdx_debug_assert(la >= (get_sysinfo_table()->keyhole_rgn_base +
            (get_local_data()->lp_info.x2apic_id * MAX_KEYHOLE_PER_LP) * 0x1000));
    tdx_debug_assert(la < (get_sysinfo_table()->keyhole_rgn_base +
            ((get_local_data()->lp_info.x2apic_id + 1 ) * MAX_KEYHOLE_PER_LP) * 0x1000));

    uint16_t keyhole_idx = (uint16_t)(((la - get_sysinfo_table()->keyhole_rgn_base) / 0x1000) -
                                      (get_local_data()->lp_info.x2apic_id * MAX_KEYHOLE_PER_LP));

    tdx_debug_assert(keyhole_idx < MAX_KEYHOLE_PER_LP);

    return keyhole_idx;
}

static void fill_keyhole_pte(uint16_t keyhole_idx, uint64_t pa, bool_t is_writable, bool_t is_wb_memtype)
{
    uint64_t lp_keyhole_edit_base = get_sysinfo_table()->keyhole_edit_rgn_base +
            (uint64_t)(get_local_data()->lp_info.x2apic_id * MAX_KEYHOLE_PER_LP * sizeof(ia32e_pxe_t));

    ia32e_pxe_t* pte_p = (ia32e_pxe_t*)(lp_keyhole_edit_base + (uint64_t)((uint32_t)keyhole_idx * sizeof(ia32e_pxe_t)));
    ia32e_pxe_t new_pte;

    new_pte.raw = (uint64_t)0;

    new_pte.fields_4k.addr = (pa >> 12);
    new_pte.fields_4k.p    = 1;
    new_pte.fields_4k.a    = 1;
    new_pte.fields_4k.xd   = 1;
    new_pte.fields_4k.rw   = is_writable;
    new_pte.fields_4k.d    = is_writable;

    // If not WB memtype - UC required - which is mapped in index 7 of IA32_PAT_MSR
    if (is_wb_memtype == false)
    {
        new_pte.fields_4k.pat = 1;
        new_pte.fields_4k.pwt = 1;
        new_pte.fields_4k.pcd = 1;
    }
    // Else - default WB memtype required - mapped at index 0 of IA32_PAT_MSR (PAT=PWT=PCD=0)

    ia32_set_ac();

    pte_p->raw = new_pte.raw;

    ia32_clear_ac();

    return;
}

static uint16_t hash_pa(uint64_t bits)
{
    uint16_t res;

    res = (uint16_t)(bits & BIT_MASK_16BITS);
    res ^= (uint16_t)((bits >> 16) & BIT_MASK_16BITS);
    res ^= (uint16_t)((bits >> 32) & BIT_MASK_16BITS);
    res ^= (uint16_t)((bits >> 48) & BIT_MASK_16BITS);

    res %= (uint16_t)MAX_KEYHOLE_PER_LP;

    return res;
}

static uint16_t hash_table_find_entry(uint64_t pa, bool_t is_writable, bool_t is_wb_memtype, uint16_t* prev_idx)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint64_t pa_pg_start = PG_START(pa);

    uint16_t hash_idx = hash_pa(pa_pg_start);
    uint16_t keyhole_idx = keyhole_state->hash_table[hash_idx];
    uint16_t ret_idx = UNDEFINED_IDX;

    keyhole_entry_t* keyhole;

    while (keyhole_idx != UNDEFINED_IDX)
    {
        tdx_debug_assert(keyhole_idx < MAX_KEYHOLE_PER_LP);
        keyhole = &keyhole_state->keyhole_array[keyhole_idx];

        if ((keyhole->mapped_pa == pa_pg_start) && (keyhole->is_writable == is_writable) &&
            (keyhole->is_wb_memtype == is_wb_memtype))
        {
            ret_idx = keyhole_idx;
            break;
        }
        if (prev_idx != NULL)
        {
            *prev_idx = keyhole_idx;
        }
        keyhole_idx = keyhole->hash_list_next;
    }

    return ret_idx;
}

static void hash_table_remove_entry(uint64_t pa, bool_t is_writable, bool_t is_wb_memtype)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint64_t pa_pg_start = PG_START(pa);

    uint16_t hash_idx = hash_pa(pa_pg_start);
    uint16_t prev_idx = UNDEFINED_IDX;
    uint16_t keyhole_idx = hash_table_find_entry(pa, is_writable, is_wb_memtype, &prev_idx);

    keyhole_entry_t* keyhole;

    keyhole = &keyhole_state->keyhole_array[keyhole_idx];

    // Indicates first entry in the hash table
    if (prev_idx == UNDEFINED_IDX)
    {
        keyhole_state->hash_table[hash_idx] = keyhole->hash_list_next;
    }
    else
    {
        tdx_debug_assert(prev_idx < MAX_KEYHOLE_PER_LP);
        keyhole_state->keyhole_array[prev_idx].hash_list_next = keyhole->hash_list_next;
    }

    keyhole->hash_list_next = (uint16_t)UNDEFINED_IDX;
}

static void hash_table_insert_entry(uint64_t pa, uint16_t new_keyhole_idx)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint64_t pa_pg_start = PG_START(pa);

    uint16_t hash_idx = hash_pa(pa_pg_start);
    uint16_t keyhole_idx = keyhole_state->hash_table[hash_idx];

    keyhole_state->keyhole_array[new_keyhole_idx].hash_list_next = keyhole_idx;
    keyhole_state->hash_table[hash_idx] = new_keyhole_idx;
}

static void lru_cache_remove_entry(uint16_t keyhole_idx)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint16_t lru_prev = keyhole_state->keyhole_array[keyhole_idx].lru_prev;
    uint16_t lru_next = keyhole_state->keyhole_array[keyhole_idx].lru_next;

    if (keyhole_state->lru_head == keyhole_idx)
    {
        keyhole_state->lru_head = lru_prev;
    }

    if (keyhole_state->lru_tail == keyhole_idx)
    {
        keyhole_state->lru_tail = lru_next;
    }

    if (lru_prev != UNDEFINED_IDX)
    {
        tdx_debug_assert(lru_prev < MAX_KEYHOLE_PER_LP);
        keyhole_state->keyhole_array[lru_prev].lru_next = lru_next;
    }

    if (lru_next != UNDEFINED_IDX)
    {
        tdx_debug_assert(lru_next < MAX_KEYHOLE_PER_LP);
        keyhole_state->keyhole_array[lru_next].lru_prev = lru_prev;
    }
}

static void lru_cache_add_head_entry(uint16_t keyhole_idx)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint16_t lru_prev = keyhole_state->lru_head;

    if (lru_prev == UNDEFINED_IDX)
    {
        keyhole_state->lru_head = keyhole_idx;
    } else {
        tdx_debug_assert(lru_prev < MAX_KEYHOLE_PER_LP);
        keyhole_state->keyhole_array[lru_prev].lru_next = keyhole_idx;
    }

    keyhole_state->keyhole_array[keyhole_idx].lru_prev = lru_prev;
    keyhole_state->keyhole_array[keyhole_idx].lru_next = (uint16_t)UNDEFINED_IDX;

    keyhole_state->lru_head = keyhole_idx;
}

void init_keyhole_state(void)
{
    tdx_module_local_t* local_data = get_local_data();
    if (!local_data->keyhole_state_initialized)
    {
        keyhole_state_t* keyhole_state = &local_data->keyhole_state;
        // At init state - free keyhole entries will be linked in the LRU list
        // So that as long as there are any free entries left, they will be used before
        // cached entries will be reused.

        for (uint16_t i = 0; i < MAX_KEYHOLE_PER_LP; i++)
        {
            keyhole_state->keyhole_array[i].state = (uint8_t)KH_ENTRY_FREE;
            keyhole_state->keyhole_array[i].lru_prev = i - 1;
            keyhole_state->keyhole_array[i].lru_next = i + 1;
            keyhole_state->keyhole_array[i].hash_list_next = (uint16_t)UNDEFINED_IDX;
            keyhole_state->keyhole_array[i].mapped_pa = 0;
            keyhole_state->keyhole_array[i].is_writable = 0;
            keyhole_state->keyhole_array[i].ref_count = 0;

            keyhole_state->hash_table[i] = (uint16_t)UNDEFINED_IDX;
        }

        keyhole_state->keyhole_array[0].lru_prev = (uint16_t)UNDEFINED_IDX;
        keyhole_state->keyhole_array[MAX_CACHEABLE_KEYHOLES - 1].lru_next = (uint16_t)UNDEFINED_IDX;

        keyhole_state->lru_head = MAX_CACHEABLE_KEYHOLES - 1;
        keyhole_state->lru_tail = 0;

        keyhole_state->total_ref_count = 0;
        local_data->keyhole_state_initialized = true;
    }
}

void* map_pa_with_memtype(void* pa, mapping_type_t mapping_type, bool_t is_wb_memtype)
{
    tdx_debug_assert(get_local_data()->keyhole_state_initialized);
    tdx_debug_assert(get_local_data()->lp_info.x2apic_id == get_current_thread_num(get_sysinfo_table(), get_local_data()));

    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    bool_t is_writable = (mapping_type == TDX_RANGE_RW) ? true : false;

    // Search the requested PA first, if it's mapped or cached
    uint16_t keyhole_idx = hash_table_find_entry((uint64_t)pa, is_writable, is_wb_memtype, NULL);

    // Increment the total ref count and check for overflow
    keyhole_state->total_ref_count += 1;
    tdx_sanity_check(keyhole_state->total_ref_count != 0, FATAL_ERROR_ID_208, 0);

    // Requested PA is already mapped/cached
    if (keyhole_idx != UNDEFINED_IDX)
    {
        tdx_debug_assert(keyhole_idx < MAX_KEYHOLE_PER_LP);
        // If the relevant keyhole is marked for removal, remove it from the LRU cache list
        // and make it "mapped"
        if (keyhole_state->keyhole_array[keyhole_idx].state == KH_ENTRY_CAN_BE_REMOVED)
        {
            lru_cache_remove_entry(keyhole_idx);
            keyhole_state->keyhole_array[keyhole_idx].state = (uint8_t)KH_ENTRY_MAPPED;
        }
        keyhole_state->keyhole_array[keyhole_idx].ref_count += 1;

        // Check ref count overflow
        tdx_sanity_check(keyhole_state->keyhole_array[keyhole_idx].ref_count != 0, FATAL_ERROR_ID_209, 1);

        // Protection against speculative attacks on sensitive physical addresses
        lfence();

        // In any case, both MAPPED and CAN_BE_REMOVED - return the existing LA to the user
        return (void*)(la_from_keyhole_idx(keyhole_idx) | PG_OFFSET((uint64_t)pa));
    }

    // If it's not mapped, take the entry from LRU tail
    // If there are any free entries, they will be first from tail in the LRU list
    keyhole_idx = keyhole_state->lru_tail;

    // Check if there any available keyholes left, otherwise - kill the module
    tdx_sanity_check(keyhole_idx != UNDEFINED_IDX, FATAL_ERROR_ID_210, 2);

    keyhole_entry_t* target_keyhole = &keyhole_state->keyhole_array[keyhole_idx];

    uint64_t la = la_from_keyhole_idx(keyhole_idx) | PG_OFFSET((uint64_t)pa);

    // Remove the entry from the LRU list - valid for both FREE and CAN_BE_REMOVED
    lru_cache_remove_entry(keyhole_idx);

    // If a cached entry is being reused:
    bool_t flush = (target_keyhole->state == KH_ENTRY_CAN_BE_REMOVED);

    // Remove it from LRU list, remove it from the search hash table, and flush TLB
    if (flush)
    {
        hash_table_remove_entry(target_keyhole->mapped_pa, target_keyhole->is_writable,
                                target_keyhole->is_wb_memtype);
    }

    // Update the entry info, insert it to the search hash table, and fill the actual PTE
    target_keyhole->state = KH_ENTRY_MAPPED;
    target_keyhole->mapped_pa = PG_START((uint64_t)pa);
    target_keyhole->is_writable = is_writable;
    target_keyhole->is_wb_memtype = is_wb_memtype;
    target_keyhole->ref_count = 1;

    hash_table_insert_entry((uint64_t)pa, keyhole_idx);
    fill_keyhole_pte(keyhole_idx, (uint64_t)pa, is_writable, is_wb_memtype);

    // Flush the TLB for a reused entry - ***AFTER*** the PTE was updated
    // If INVLPG is done before the PTE is updated - the TLB entry may not be flushed properly
    ia32_invalidate_tlb_entries(la);

    // Protection against speculative attacks on sensitive physical addresses
    lfence();

    return (void*)la;
}

void* map_pa_non_wb(void* pa, mapping_type_t mapping_type)
{
    return map_pa_with_memtype(pa, mapping_type, false);
}

void* map_pa(void* pa, mapping_type_t mapping_type)
{
    return map_pa_with_memtype(pa, mapping_type, true);
}

void free_la(void* la)
{
    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    uint16_t keyhole_idx = keyhole_idx_from_la((uint64_t)la);

    tdx_sanity_check((keyhole_state->keyhole_array[keyhole_idx].state != KH_ENTRY_FREE) &&
                     (keyhole_state->keyhole_array[keyhole_idx].state != KH_ENTRY_CAN_BE_REMOVED),
                     FATAL_ERROR_ID_211, 3);

    if (keyhole_idx >= MAX_CACHEABLE_KEYHOLES)
    {
        return;
    }

    tdx_sanity_check((keyhole_state->total_ref_count > 0) &&
                     (keyhole_state->keyhole_array[keyhole_idx].ref_count > 0), FATAL_ERROR_ID_212, 4);

    keyhole_state->total_ref_count -= 1;
    keyhole_state->keyhole_array[keyhole_idx].ref_count -= 1;

    if (keyhole_state->keyhole_array[keyhole_idx].ref_count == 0)
    {
        keyhole_state->keyhole_array[keyhole_idx].state = (uint8_t)KH_ENTRY_CAN_BE_REMOVED;
        lru_cache_add_head_entry(keyhole_idx);
    }

    return;
}

void* map_continuous_pages(uint64_t* pa_array, uint16_t array_size, mapping_type_t mapping_type,
                           uint16_t starting_static_keyhole)
{
    tdx_debug_assert(get_local_data()->keyhole_state_initialized);
    tdx_debug_assert(get_local_data()->lp_info.x2apic_id == get_current_thread_num(get_sysinfo_table(), get_local_data()));

    keyhole_state_t* keyhole_state = &get_local_data()->keyhole_state;
    bool_t is_writable = (mapping_type == TDX_RANGE_RW) ? true : false;

    tdx_debug_assert(MAX_STATIC_KEYHOLES > starting_static_keyhole);
    tdx_debug_assert(array_size <= (MAX_STATIC_KEYHOLES - starting_static_keyhole));

    for (uint16_t i = 0; i < array_size; i++)
    {
        uint64_t pa = PG_START(pa_array[i]);
        uint16_t keyhole_idx = (uint16_t)MAX_CACHEABLE_KEYHOLES + starting_static_keyhole + i;

        keyhole_entry_t* target_keyhole = &keyhole_state->keyhole_array[keyhole_idx];

        // If the static keyhole already mapped - but for a different PA/different access rights
        // Flush the TLB for that entry and replace it
        bool_t flush = (target_keyhole->state == KH_ENTRY_MAPPED) &&
                        ((target_keyhole->mapped_pa != pa) || (target_keyhole->is_writable != is_writable));

        // Flush the TLB for a reused entry - ***AFTER*** the PTE was updated
        // If INVLPG is done before the PTE is updated - the TLB entry may not be flushed properly
        IF_RARE(flush || (target_keyhole->state != KH_ENTRY_MAPPED))
        {
            target_keyhole->state = (uint8_t)KH_ENTRY_MAPPED;
            target_keyhole->mapped_pa = pa;
            target_keyhole->is_writable = is_writable;
            target_keyhole->is_wb_memtype = true;

            fill_keyhole_pte(keyhole_idx, pa, is_writable, true);
        }
        IF_RARE (flush)
        {
            uint64_t la = la_from_keyhole_idx(keyhole_idx);
            ia32_invalidate_tlb_entries(la);
        }
    }

    // Protection against speculative attacks on sensitive physical addresses
    lfence();

    return (void*)(la_from_keyhole_idx(MAX_CACHEABLE_KEYHOLES + starting_static_keyhole));
}
