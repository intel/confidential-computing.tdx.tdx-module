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
 * @file pamt_manager.c
 * @brief PAMT manager implementation
 */

#include "pamt_manager.h"
#include "data_structures/tdx_global_data.h"
#include "keyhole_manager.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"

bool_t dynamic_pamt_4k_bitmap_set(pamt_block_t* pamt_block, uint64_t hpa)
{
    uint64_t bit_index = (hpa - pamt_block->tdmr_base) >> 12;
    uint64_t qword_index = bit_index / 64;
    uint64_t bit_in_qword = bit_index % 64;

    uint64_t qword_addr = (uint64_t)pamt_block->pamt_4kb_p + (qword_index * 8);

    void* qword_la = map_pa_with_global_hkid((void*)qword_addr, TDX_RANGE_RW);

    bool_t result = (_lock_bts_64b((volatile uint64_t*)qword_la, bit_in_qword) == 0);

    free_la(qword_la);

    return result;
}

uint8_t dynamic_pamt_4k_bitmap_get(pamt_block_t* pamt_block, uint64_t hpa)
{
    uint64_t bit_index = (hpa - pamt_block->tdmr_base) >> 12;
    uint64_t qword_index = bit_index / 64;
    uint64_t bit_in_qword = bit_index % 64;

    uint64_t qword_addr = (uint64_t)pamt_block->pamt_4kb_p + (qword_index * 8);

    void* qword_la = map_pa_with_global_hkid((void*)qword_addr, TDX_RANGE_RW);

    uint8_t result = (uint8_t)(((*(volatile uint64_t*)qword_la) & BIT(bit_in_qword)) >> bit_in_qword);

    free_la(qword_la);

    return result;
}

void dynamic_pamt_4k_bitmap_clear(pamt_block_t* pamt_block, uint64_t hpa)
{
    uint64_t bit_index = (hpa - pamt_block->tdmr_base) >> 12;
    uint64_t qword_index = bit_index / 64;
    uint64_t bit_in_qword = bit_index % 64;

    uint64_t qword_addr = (uint64_t)pamt_block->pamt_4kb_p + (qword_index * 8);

    void* qword_la = map_pa_with_global_hkid((void*)qword_addr, TDX_RANGE_RW);

    (void)_lock_btr_64b((volatile uint64_t*)qword_la, bit_in_qword);

    free_la(qword_la);
}

void pamt_inc_nl_page_count(pamt_non_leaf_entry_t* pamt_nl_entry)
{
    if (get_global_data()->dynamic_pamt_enabled && pamt_nl_entry && (pamt_nl_entry->pt == PT_PAMT))
    {
        uint64_t prev_count = _lock_xadd_16b((uint16_t*)&pamt_nl_entry->second_quadword, 1);
        prev_count &= PAMT_NL_PAGE_COUNT_MASK;
        tdx_sanity_check(prev_count != 512, FATAL_ERROR_ID_351, 0);
    }
}

bool_t pamt_dec_nl_page_count(pamt_non_leaf_entry_t* pamt_nl_entry)
{
    if (get_global_data()->dynamic_pamt_enabled && pamt_nl_entry && (pamt_nl_entry->pt == PT_PAMT))
    {
        uint64_t prev_count = _lock_xadd_16b((uint16_t*)&pamt_nl_entry->second_quadword, (uint16_t)-1);
        prev_count &= PAMT_NL_PAGE_COUNT_MASK;

        tdx_sanity_check(prev_count != 0, FATAL_ERROR_ID_170, 0);

        if (prev_count == 1)
        {
            return true;
        }
    }

    return false;
}


tdmr_entry_t* get_covering_tdmr_for_hpa(pa_t pa)
{
    tdmr_entry_t* covering_tdmr = NULL;
    tdx_module_global_t* global_data_ptr = get_global_data();

    pa = remove_hkid_from_pa(pa);
    uint64_t pa_addr = get_addr_from_pa(pa);

    // Assuming that TDMR table is sorted by base (ascending)
    for (uint32_t i = 0; i < global_data_ptr->num_of_tdmr_entries; i++)
    {
        if (global_data_ptr->tdmr_table[i].base <= pa_addr)
        {
            covering_tdmr = &global_data_ptr->tdmr_table[i];
        }
        else
        {
            break;
        }
    }

    if (covering_tdmr == NULL || pa_addr >= (covering_tdmr->base + covering_tdmr->size))
    {
        return NULL;
    }

    return covering_tdmr;
}

bool_t pamt_get_block(pa_t pa, pamt_block_t* pamt_block)
{
    uint64_t pa_addr = get_addr_from_pa(pa);

    tdmr_entry_t* covering_tdmr = get_covering_tdmr_for_hpa(pa);

    if (covering_tdmr == NULL)
    {
        TDX_ERROR("Couldn't find covering TDMR for PA = 0x%llx\n", pa_addr);
        return false;
    }

    pa_t offset_pa;

    offset_pa.raw = pa_addr - covering_tdmr->base;
    uint32_t pamt_block_num = (uint32_t)offset_pa.page_1g_num;

    tdx_sanity_check(pamt_block_num < covering_tdmr->num_of_pamt_blocks, FATAL_ERROR_ID_213, 0);

    if (pa_addr >= (covering_tdmr->last_initialized & ~(_1GB - 1)))
    {
        TDX_ERROR("PA = 0x%llx wasn't initialized yet for the covering TDMR (last init addr = 0x%llx)\n",
                pa_addr, covering_tdmr->last_initialized);
        return false;
    }

    pamt_block->pamt_1gb_p = (pamt_entry_t*) (covering_tdmr->pamt_1g_base
            + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t)));
    pamt_block->pamt_2mb_p = (pamt_entry_t*) (covering_tdmr->pamt_2m_base
            + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t) * PAMT_2MB_ENTRIES_IN_1GB));

    if (get_global_data()->dynamic_pamt_enabled)
    {
        pamt_block->pamt_4kb_p = (pamt_entry_t*)covering_tdmr->pamt_4k_base;
    }
    else
    {
        pamt_block->pamt_4kb_p = (pamt_entry_t*) (covering_tdmr->pamt_4k_base
                + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t) * PAMT_4KB_ENTRIES_IN_1GB));
    }

    pamt_block->tdmr_base = covering_tdmr->base;

    return true;
}

bool_t is_page_reserved(uint64_t page_offset, tdmr_entry_t *tdmr_entry, uint32_t* last_rsdv_idx)
{
    uint64_t rsvd_offset, rsvd_offset_end;
    uint32_t i;

    for (i = *last_rsdv_idx; i < tdmr_entry->num_of_rsvd_areas; i++)
    {
        rsvd_offset = tdmr_entry->rsvd_areas[i].offset;
        rsvd_offset_end = rsvd_offset + tdmr_entry->rsvd_areas[i].size;

        if ((page_offset >= rsvd_offset) && (page_offset < rsvd_offset_end))
        {
            *last_rsdv_idx = i;
            return true;
        }
    }

    *last_rsdv_idx = 0;
    return false;
}

_STATIC_INLINE_ void pamt_4kb_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry)
{
    pamt_entry_t* pamt_entry = NULL;
    uint64_t current_4k_page_idx = ((uint64_t)pamt_block->pamt_4kb_p - tdmr_entry->pamt_4k_base)
                                    / sizeof(pamt_entry_t);
    uint64_t page_offset;
    uint32_t last_rsvd_idx = 0;

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = (uint32_t)(num_4k_entries / pamt_entries_in_page);

    pamt_entry_t* pamt_entry_start = pamt_block->pamt_4kb_p;
    tdx_sanity_check(((uint64_t)pamt_entry_start % TDX_PAGE_SIZE_IN_BYTES) == 0, FATAL_ERROR_ID_214, 11);
    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        pamt_entry = map_pa_with_global_hkid(
                &pamt_entry_start[pamt_entries_in_page * i], TDX_RANGE_RW);
        // create a cache aligned, cache sized chunk and fill it with 'val'
        ALIGN(MOVDIR64_CHUNK_SIZE) pamt_entry_t chunk[PAMT_4K_ENTRIES_IN_CACHE];
        basic_memset((uint64_t)chunk, PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t), 0 , PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t));
        for (uint32_t j = 0; j < pamt_entries_in_page; j++, current_4k_page_idx++)
        {
            page_offset = current_4k_page_idx * TDX_PAGE_SIZE_IN_BYTES;
            if (is_page_reserved(page_offset, tdmr_entry, &last_rsvd_idx))
            {
                chunk[j%PAMT_4K_ENTRIES_IN_CACHE].pt = PT_RSVD;
            }
            else
            {
                chunk[j%PAMT_4K_ENTRIES_IN_CACHE].pt = PT_NDA;
            }
            if ((j+1)%PAMT_4K_ENTRIES_IN_CACHE == 0)
            {
                fill_cachelines_no_sfence((void*)&(pamt_entry[j-3]), (uint8_t*)chunk, 1);
            }
        }
        mfence();
        free_la(pamt_entry);
    }
}

_STATIC_INLINE_ void pamt_4kb_bitmap_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry)
{
    uint64_t start_pamt_4k_p = (uint64_t)pamt_block->pamt_4kb_p;

    // For dynamic PAMT the pamt_4kb_p pointer is just a virtual pointers and doesn't points
    // to any actual 4K PAMT array. We will just use it to calculate which 4K bitmap bits we need
    // to initialize for the current state of pamt_block and num_4k_entries
    uint64_t num_of_bits_to_set = num_4k_entries;
    tdx_debug_assert((num_of_bits_to_set % 8) == 0);

    uint64_t num_of_bytes_to_set = num_of_bits_to_set / 8;
    tdx_debug_assert((num_of_bytes_to_set % MOVDIR64_CHUNK_SIZE) == 0);

    uint64_t starting_bit = (start_pamt_4k_p - tdmr_entry->pamt_4k_base) / sizeof(pamt_entry_t);
    tdx_debug_assert((starting_bit % 8) == 0);

    uint64_t starting_byte = starting_bit / 8;
    tdx_debug_assert((starting_byte % MOVDIR64_CHUNK_SIZE) == 0);

    // Check that we can use only one mapping - the range fits in same page
    tdx_debug_assert((starting_byte / _4KB) == ((starting_byte + num_of_bytes_to_set - 1) / _4KB));
    uint8_t* starting_byte_la = map_pa_with_global_hkid((void*)(tdmr_entry->pamt_4k_base + starting_byte), TDX_RANGE_RW);

    // For dynamic PAMT we just need to zero the bitmap
    zero_area_cacheline(starting_byte_la, num_of_bytes_to_set);

    // Loop over the zeroed quadwords and set reserved page bits to 1
    uint64_t current_4k_page_idx = starting_bit;
    uint32_t last_rsvd_idx = 0;

    tdx_debug_assert((num_of_bytes_to_set % 8) == 0);
    for (uint64_t i = 0; i < num_of_bytes_to_set / sizeof(uint64_t); i++)
    {
        uint64_t qword_bitmap = 0;
        for (uint32_t j = 0; j < 64; j++, current_4k_page_idx++)
        {
            uint64_t page_offset = current_4k_page_idx * TDX_PAGE_SIZE_IN_BYTES;
            if (is_page_reserved(page_offset, tdmr_entry, &last_rsvd_idx))
            {
                qword_bitmap |= BIT(j);
            }
        }

        *(uint64_t*)(starting_byte_la + (i * sizeof(uint64_t))) = qword_bitmap;
    }

    free_la(starting_byte_la);
}

_STATIC_INLINE_ void pamt_nodes_init(uint64_t start_pamt_4k_p, uint64_t end_pamt_4k_p,
        pamt_entry_t* nodes_array, uint64_t entries_in_node, tdmr_entry_t *tdmr_entry)
{
    pamt_entry_t* pamt_entry;

    uint64_t entries_start = (start_pamt_4k_p - tdmr_entry->pamt_4k_base) / (entries_in_node * (uint64_t)sizeof(pamt_entry_t));
    uint64_t entries_end   = (end_pamt_4k_p - tdmr_entry->pamt_4k_base) / (entries_in_node * (uint64_t)sizeof(pamt_entry_t));

    uint32_t i = 0;
    while ((entries_end - (uint64_t)i) > entries_start)
    {
        void* entry_p = &nodes_array[i];
        pamt_entry = map_pa_with_global_hkid(entry_p, TDX_RANGE_RW);
        if (is_cacheline_aligned(entry_p))
        {
            zero_cacheline(pamt_entry);
        }

        pamt_entry->pt = PT_NDA;

        free_la(pamt_entry);
        i++;
    }
}

void pamt_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry)
{
    uint64_t start_pamt_4k_p = (uint64_t)pamt_block->pamt_4kb_p;
    uint64_t end_pamt_4k_p = start_pamt_4k_p + (num_4k_entries * (uint64_t)sizeof(pamt_entry_t));

    if (get_global_data()->dynamic_pamt_enabled)
    {
        pamt_4kb_bitmap_init(pamt_block, num_4k_entries, tdmr_entry);
    }
    else
    {
        pamt_4kb_init(pamt_block, num_4k_entries, tdmr_entry);
    }

    pamt_nodes_init(start_pamt_4k_p, end_pamt_4k_p, pamt_block->pamt_2mb_p, PAMT_4K_ENTRIES_IN_2MB, tdmr_entry);
    pamt_nodes_init(start_pamt_4k_p, end_pamt_4k_p, pamt_block->pamt_1gb_p, PAMT_4K_ENTRIES_IN_1GB, tdmr_entry);
}

api_error_code_e pamt_walk(pa_t pa, pamt_block_t pamt_block, lock_type_t leaf_lock_type,
                           page_size_t target_size, bool_t walk_to_target_size,
                           bool_t is_guest, pamt_walk_result_t* pamt_walk_result)
{
    pamt_entry_t* pamt_1gb = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
    pamt_entry_t* pamt_2mb = NULL;
    pamt_entry_t* pamt_4kb = NULL;

    pamt_entry_t* ret_entry_pp = (void*)NULL_PA;

    target_size = walk_to_target_size ? target_size : PT_4KB;

    api_error_code_e retval = UNINITIALIZE_ERROR;

    pamt_walk_result->pamt_walk_path[PT_4KB] = NULL;
    pamt_walk_result->pamt_walk_path[PT_2MB] = NULL;
    pamt_walk_result->pamt_walk_path[PT_1GB] = NULL;
    pamt_walk_result->pamt_entry_p = NULL;
    pamt_walk_result->leaf_lock_type = leaf_lock_type;
    pamt_walk_result->valid = false;

    // Exclusive mode is not supported in guest-side calls
    tdx_debug_assert(!(is_guest && (leaf_lock_type == TDX_LOCK_EXCLUSIVE)));

    // Acquire PAMT 1GB entry lock as shared
    if ((retval = acquire_sharex_lock_hp(&pamt_1gb->entry_lock, TDX_LOCK_SHARED, is_guest)) != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Return pamt_1g entry if it is currently a leaf entry
    if ((pamt_1gb->pt != PT_NDA) || (target_size == PT_1GB))
    {
        // Promote PAMT lock to exclusive if needed
        if ((leaf_lock_type == TDX_LOCK_EXCLUSIVE) &&
            ((retval = promote_sharex_lock_hp(&pamt_1gb->entry_lock)) != TDX_SUCCESS))
        {
            goto EXIT_FAILURE_RELEASE_ROOT;
        }

        pamt_walk_result->level_reached = PT_1GB;
        ret_entry_pp = pamt_block.pamt_1gb_p;

        goto EXIT;
    }

    pamt_2mb = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);

    // Acquire PAMT 2MB entry lock as shared
    if ((retval = acquire_sharex_lock_hp(&pamt_2mb->entry_lock, TDX_LOCK_SHARED, is_guest)) != TDX_SUCCESS)
    {
        goto EXIT_FAILURE_RELEASE_ROOT;
    }

    // Return pamt_2m entry if it is leaf
    if ((!get_global_data()->dynamic_pamt_enabled && (pamt_2mb->pt != PT_NDA)) ||
        (get_global_data()->dynamic_pamt_enabled && (pamt_2mb->pt != PT_PAMT)) ||
        (target_size == PT_2MB))
    {
        // Promote PAMT lock to exclusive if needed
        if ((leaf_lock_type == TDX_LOCK_EXCLUSIVE) &&
            ((retval = promote_sharex_lock_hp(&pamt_2mb->entry_lock)) != TDX_SUCCESS))
        {
            goto EXIT_FAILURE_RELEASE_ALL;
        }

        pamt_walk_result->level_reached = PT_2MB;
        ret_entry_pp = &pamt_block.pamt_2mb_p[pa.pamt_2m.idx];

        goto EXIT;
    }

    pa_t pamt_4kb_pp;

    if (get_global_data()->dynamic_pamt_enabled)
    {
        pamt_non_leaf_entry_t* pamt_2mb_node = (pamt_non_leaf_entry_t*)pamt_2mb;

        pa_t node_page = (pa.pamt_4k_in_2mb.idx < 256) ? get_pamt_node_page0(pamt_2mb_node) :
                                                         get_pamt_node_page1(pamt_2mb_node);

        pamt_4kb_pp.raw_void = &(((pamt_entry_t*)node_page.raw_void)[pa.pamt_4k_in_2mb.idx % 256]);
    }
    else
    {
        pamt_4kb_pp.raw_void = &pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
    }

    pamt_4kb = map_pa_with_global_hkid(pamt_4kb_pp.raw_void, TDX_RANGE_RW);

    // Acquire PAMT 4KB entry lock as shared/exclusive based on the lock flag
    if ((retval = acquire_sharex_lock_hp(&pamt_4kb->entry_lock, leaf_lock_type, is_guest)) != TDX_SUCCESS)
    {
        goto EXIT_FAILURE_RELEASE_ALL;
    }

    pamt_walk_result->level_reached = PT_4KB;
    ret_entry_pp = pamt_4kb_pp.raw_void;

    goto EXIT;

EXIT_FAILURE_RELEASE_ALL:
    // Release PAMT 2MB shared lock
    release_sharex_lock_hp_sh(&pamt_2mb->entry_lock);
EXIT_FAILURE_RELEASE_ROOT:
    // Release PAMT 1GB shared lock
    release_sharex_lock_hp_sh(&pamt_1gb->entry_lock);

EXIT:

    if (ret_entry_pp != (void*)NULL_PA)
    {
        pamt_walk_result->pamt_walk_path[PT_1GB] = pamt_1gb;
        pamt_walk_result->pamt_walk_path[PT_2MB] = pamt_2mb;
        pamt_walk_result->pamt_walk_path[PT_4KB] = pamt_4kb;

        pamt_walk_result->pamt_entry_p = map_pa_with_global_hkid(ret_entry_pp,
                (leaf_lock_type == TDX_LOCK_EXCLUSIVE) ? TDX_RANGE_RW : TDX_RANGE_RO);

        pamt_walk_result->valid = true;
    }
    else
    {
        free_la(pamt_1gb);
        if (pamt_2mb)
        {
            free_la(pamt_2mb);
        }
        if (pamt_4kb)
        {
            free_la(pamt_4kb);
        }
    }

    return retval;
}

void pamt_unwalk(pamt_walk_result_t* pamt_walk_result)
{
    tdx_debug_assert(pamt_walk_result->valid);

    lock_type_t lock_type = pamt_walk_result->leaf_lock_type;

    switch (pamt_walk_result->level_reached)
    {
        case PT_4KB:
            release_sharex_lock_hp(&pamt_walk_result->pamt_walk_path[PT_4KB]->entry_lock, lock_type);
            free_la(pamt_walk_result->pamt_walk_path[PT_4KB]);
            pamt_walk_result->pamt_walk_path[PT_4KB] = NULL;
            lock_type = TDX_LOCK_SHARED;

            // no break
        case PT_2MB:
            release_sharex_lock_hp(&pamt_walk_result->pamt_walk_path[PT_2MB]->entry_lock, lock_type);
            free_la(pamt_walk_result->pamt_walk_path[PT_2MB]);
            pamt_walk_result->pamt_walk_path[PT_2MB] = NULL;
            lock_type = TDX_LOCK_SHARED;

            // no break
        case PT_1GB:
            release_sharex_lock_hp(&pamt_walk_result->pamt_walk_path[PT_1GB]->entry_lock, lock_type);
            free_la(pamt_walk_result->pamt_walk_path[PT_1GB]);
            pamt_walk_result->pamt_walk_path[PT_1GB] = NULL;

            break;
        default:
            tdx_sanity_check(0, FATAL_ERROR_ID_215, 2);
    }

    free_la(pamt_walk_result->pamt_entry_p);

    pamt_walk_result->pamt_entry_p = NULL;
    pamt_walk_result->valid = false;

    return;
}

static pamt_entry_t* pamt_implicit_get_internal(pa_t pa, page_size_t leaf_size, pamt_non_leaf_entry_t** pamt_nl_entry)
{
    pamt_block_t pamt_block;

    if (!pamt_get_block(pa, &pamt_block))
    {
        // PAMT block not found or not initialized
        extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)leaf_size);
        fatal_error(FATAL_ERROR_ID_109, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
    }

    pamt_entry_t* pamt_entry_p = NULL;

    if (pamt_nl_entry != NULL)
    {
        *pamt_nl_entry = NULL;
    }

    switch (leaf_size)
    {
        case PT_1GB:
            pamt_entry_p = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
            break;
        case PT_2MB:
            pamt_entry_p = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
            break;
        case PT_4KB:
        {
            pa_t pamt_4kb_pp;

            if (get_global_data()->dynamic_pamt_enabled)
            {
                pamt_non_leaf_entry_t* pamt_2mb_node = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);

                if (pamt_2mb_node->pt != PT_PAMT)
                {
                    extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)leaf_size);
                    fatal_error(FATAL_ERROR_ID_336, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
                }

                pa_t node_page = (pa.pamt_4k_in_2mb.idx < 256) ? get_pamt_node_page0(pamt_2mb_node) :
                                                                 get_pamt_node_page1(pamt_2mb_node);

                pamt_4kb_pp.raw_void = &(((pamt_entry_t*)node_page.raw_void)[pa.pamt_4k_in_2mb.idx % 256]);

                if (pamt_nl_entry != NULL)
                {
                    *pamt_nl_entry = pamt_2mb_node;
                }
                else
                {
                    free_la(pamt_2mb_node);
                }
            }
            else
            {
                pamt_4kb_pp.raw_void = &pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
            }

            pamt_entry_p = map_pa_with_global_hkid(pamt_4kb_pp.raw_void, TDX_RANGE_RW);
            break;
        }
        default:
        {
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)leaf_size);
            fatal_error(FATAL_ERROR_ID_171, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
            break;
        }
    }

    tdx_sanity_check((pamt_entry_p->pt != PT_NDA) && (pamt_entry_p->pt != PT_RSVD), FATAL_ERROR_ID_339, 10);

    tdx_sanity_check((pamt_entry_p->pt != PT_PAMT), FATAL_ERROR_ID_340, 17);

    return pamt_entry_p;
}

pamt_entry_t* pamt_implicit_get(pa_t pa, page_size_t leaf_size)
{
    return pamt_implicit_get_internal(pa, leaf_size, NULL);
}

pamt_entry_t* pamt_implicit_get_with_nl_entry(pa_t pa, page_size_t leaf_size, pamt_non_leaf_entry_t** pamt_nl_entry)
{
    return pamt_implicit_get_internal(pa, leaf_size, pamt_nl_entry);
}

static api_error_code_e pamt_implicit_get_and_lock_internal(pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                                            pamt_entry_t** pamt_entry,
                                                            pamt_non_leaf_entry_t** pamt_nl_entry,
                                                            bool_t is_guest)
{
    api_error_code_e errc = UNINITIALIZE_ERROR;
    pamt_entry_t* tmp_pamt_entry = pamt_implicit_get_internal(pa, leaf_size, pamt_nl_entry);

    if ((errc = acquire_sharex_lock_hp(&tmp_pamt_entry->entry_lock, leaf_lock_type, is_guest)) != TDX_SUCCESS)
    {
        free_la(tmp_pamt_entry);
        *pamt_entry = NULL;

        if ((pamt_nl_entry != NULL) && (*pamt_nl_entry != NULL))
        {
            free_la(*pamt_nl_entry);
            *pamt_nl_entry = NULL;
        }

        return errc;
    }

    *pamt_entry = tmp_pamt_entry;
    return TDX_SUCCESS;
}

api_error_code_e pamt_implicit_get_and_lock(pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                            pamt_entry_t** pamt_entry, bool_t is_guest)
{
    return pamt_implicit_get_and_lock_internal(pa, leaf_size, leaf_lock_type,
                                               pamt_entry, NULL, is_guest);
}

api_error_code_e pamt_implicit_get_with_nl_entry_and_lock(
                                pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                pamt_entry_t** pamt_entry, pamt_non_leaf_entry_t** pamt_nl_entry, bool_t is_guest)
{
    return pamt_implicit_get_and_lock_internal(pa, leaf_size, leaf_lock_type,
                                               pamt_entry, pamt_nl_entry, is_guest);
}

void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type)
{
    release_sharex_lock_hp(&pamt_entry->entry_lock, leaf_lock_type);

    free_la(pamt_entry);
}

bool_t pamt_is_2mb_range_free(pa_t hpa, pamt_block_t* pamt_block)
{
    if (get_global_data()->dynamic_pamt_enabled)
    {

        uint64_t bitmap_qwords_in_2mb_range = _2MB / _4KB / 64;

        uint64_t bit_index = (hpa.raw - pamt_block->tdmr_base) >> 12;
        uint64_t qword_index = bit_index / 64;

        uint64_t qword_addr = (uint64_t)pamt_block->pamt_4kb_p + (qword_index * 8);

        // Check that we don't cross a 4K page
        tdx_debug_assert((qword_addr / _4KB) == ((qword_addr + (bitmap_qwords_in_2mb_range * 8) - 1) / _4KB));

        uint64_t* qword_la = map_pa_with_global_hkid((void*)qword_addr, TDX_RANGE_RO);

        for (uint64_t i = 0; i < bitmap_qwords_in_2mb_range; i++)
        {
            if (qword_la[i] != 0)
            {
                free_la(qword_la);
                return false;
            }
        }

        free_la(qword_la);
    }
    else
    {
        pamt_entry_t* pamt_entry_children_la;
        pamt_entry_t* pamt_entry_children_pa = &pamt_block->pamt_4kb_p[hpa.pamt_4k.idx];
        uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
        uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

        tdx_sanity_check(((uint64_t)pamt_entry_children_pa % TDX_PAGE_SIZE_IN_BYTES) == 0, FATAL_ERROR_ID_341, 3);

        for (uint32_t i = 0; i < pamt_pages; i++)
        {
            pamt_entry_children_la = map_pa_with_global_hkid(&pamt_entry_children_pa[pamt_entries_in_page * i], TDX_RANGE_RO);

            for (uint32_t j = 0; j < pamt_entries_in_page; j++)
            {
                // Check the leaf entry is not directly assigned
                if (pamt_entry_children_la[j].pt != PT_NDA)
                {
                    TDX_ERROR("Page %d in range is not NDA!\n", (i * pamt_entries_in_page) + j);
                    free_la(pamt_entry_children_la);
                    return false;
                }
            }
            free_la(pamt_entry_children_la);
        }
    }

    return true;
}

api_error_code_e pamt_promote(pa_t pa, page_size_t new_leaf_size, uint64_t removed_child_pages[DEFAULT_NUM_PAMT_PAGES])
{
    pamt_entry_t* promoted_pamt_entry = NULL;
    pamt_entry_t* pamt_entry_children_la = NULL;
    pamt_block_t pamt_block;
    api_error_code_e retval = UNINITIALIZE_ERROR;

    tdx_sanity_check((new_leaf_size == PT_2MB) || (new_leaf_size == PT_1GB), FATAL_ERROR_ID_216, 3);

    // Get PAMT block of the merge page address (should never fail)
    if (!pamt_get_block(pa, &pamt_block))
    {
        extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)new_leaf_size);
        fatal_error(FATAL_ERROR_ID_168, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
    }

    if (new_leaf_size == PT_2MB)
    {
        promoted_pamt_entry = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);

        if (get_global_data()->dynamic_pamt_enabled)
        {
            pamt_non_leaf_entry_t* promoted_pamt_node = (pamt_non_leaf_entry_t*)promoted_pamt_entry;

            removed_child_pages[0] = get_pamt_node_page0(promoted_pamt_node).raw;
            removed_child_pages[1] = get_pamt_node_page1(promoted_pamt_node).raw;
        }
        else
        {
            removed_child_pages[0] = (uint64_t)&pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
            removed_child_pages[1] = removed_child_pages[0] + _4KB;
        }
    }
    else // No other case except PT_1GB here, enforced by sanity check above
    {
        promoted_pamt_entry = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);

        removed_child_pages[0] = (uint64_t)&pamt_block.pamt_2mb_p[pa.pamt_2m.idx];
        removed_child_pages[1] = removed_child_pages[0] + _4KB;
    }

    if ((get_global_data()->dynamic_pamt_enabled) && (new_leaf_size == PT_2MB))
    {
        tdx_sanity_check(promoted_pamt_entry->pt == PT_PAMT, FATAL_ERROR_ID_217, 4);
    }
    else
    {
        tdx_sanity_check(promoted_pamt_entry->pt == PT_NDA, FATAL_ERROR_ID_223, 4);
    }

    // Acquire exclusive lock on the promoted entry
    if ((retval = acquire_sharex_lock_hp_ex(&promoted_pamt_entry->entry_lock, false)) != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

    tdx_sanity_check(pamt_pages == DEFAULT_NUM_PAMT_PAGES, FATAL_ERROR_ID_218, 5);

    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        // Map as RW since static PAMT case use it for writing
        pamt_entry_children_la = map_pa_with_global_hkid((void*)removed_child_pages[i], TDX_RANGE_RW);

        if (i == 0)
        {
            // Copy the first child leaf metadata to the merged new leaf entry
            // making its page type PT_REG and inheriting its owner
            promoted_pamt_entry->pt = pamt_entry_children_la[0].pt;
            promoted_pamt_entry->owner = pamt_entry_children_la[0].owner;
            if (get_global_data()->dynamic_pamt_enabled)
            {
                promoted_pamt_entry->bepoch.raw = 0;
            }
        }

        if ((!get_global_data()->dynamic_pamt_enabled) || (new_leaf_size == PT_1GB))
        {
            for (uint32_t j = 0; j < pamt_entries_in_page; j++)
            {
                tdx_sanity_check((promoted_pamt_entry->pt == pamt_entry_children_la[j].pt) &&
                           (promoted_pamt_entry->owner == pamt_entry_children_la[j].owner),
                           FATAL_ERROR_ID_219, 6);

                pamt_entry_children_la[j].pt = PT_NDA;
            }
        }

        free_la(pamt_entry_children_la);
    }

    if ((get_global_data()->dynamic_pamt_enabled) && (new_leaf_size == PT_2MB))
    {
        pamt_block_t entry0_block, entry1_block;

        if (!pamt_get_block((pa_t)removed_child_pages[0], &entry0_block) ||
            !pamt_get_block((pa_t)removed_child_pages[1], &entry1_block))
        {
            TDX_ERROR("Couldn't find covering TDMR for removed PAMT pages - not expected\n");
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)new_leaf_size);
            fatal_error(FATAL_ERROR_ID_337, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
        }

        dynamic_pamt_4k_bitmap_clear(&entry0_block, removed_child_pages[0]);
        dynamic_pamt_4k_bitmap_clear(&entry1_block, removed_child_pages[1]);
    }

    // Release previously acquired exclusive lock
    release_sharex_lock_hp_ex(&promoted_pamt_entry->entry_lock);

    retval = TDX_SUCCESS;

EXIT:
    free_la(promoted_pamt_entry);

    return retval;
}

api_error_code_e pamt_demote(pa_t pa, page_size_t leaf_size, uint64_t pamt_hpa0, uint64_t pamt_hpa1)
{
    pamt_entry_t* demoted_pamt_entry = NULL;
    uint64_t pamt_entry_children_pa[DEFAULT_NUM_PAMT_PAGES];
    pamt_entry_t* pamt_entry_children_la = NULL;
    pamt_block_t pamt_block;
    api_error_code_e retval = UNINITIALIZE_ERROR;


    pamt_block_t pamt0_block, pamt1_block;
    pamt_walk_result_t pamt0_walk_result = { .valid = false };
    pamt_walk_result_t pamt1_walk_result = { .valid = false };


    bool_t demoted_entry_locked = false;

    tdx_sanity_check((leaf_size == PT_2MB) || (leaf_size == PT_1GB), FATAL_ERROR_ID_220, 7);

    // Get PAMT block (should never fail)
    if (!pamt_get_block(pa, &pamt_block))
    {
        extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_page_hpa(pa.raw, (uint8_t)leaf_size);
        fatal_error(FATAL_ERROR_ID_169, FATAL_INFO_FORMAT_PAGE_HPA_INFO, &extended_fatal_info);
    }

    if (leaf_size == PT_2MB)
    {
        demoted_pamt_entry = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);

        if (get_global_data()->dynamic_pamt_enabled)
        {
            pamt_entry_children_pa[0] = pamt_hpa0;
            pamt_entry_children_pa[1] = pamt_hpa1;
        }
        else
        {
            pamt_entry_children_pa[0] = (uint64_t)&pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
            pamt_entry_children_pa[1] = pamt_entry_children_pa[0] + _4KB;
        }
    }
    else // No other case except PT_1GB here, enforced by sanity check above
    {
        demoted_pamt_entry = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);

        pamt_entry_children_pa[0] = (uint64_t)&pamt_block.pamt_2mb_p[pa.pamt_2m.idx];
        pamt_entry_children_pa[1] = pamt_entry_children_pa[0] + _4KB;
    }

    tdx_sanity_check(demoted_pamt_entry->pt == PT_REG, FATAL_ERROR_ID_221, 8);

    // Acquire exclusive lock on the demoted entry
    if ((retval = acquire_sharex_lock_hp_ex(&demoted_pamt_entry->entry_lock, false)) != TDX_SUCCESS)
    {
        retval = api_error_with_operand_id(retval, OPERAND_ID_RCX);
        goto EXIT;
    }

    demoted_entry_locked = true;

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

    tdx_sanity_check(pamt_pages == DEFAULT_NUM_PAMT_PAGES, FATAL_ERROR_ID_222, 9);

    if (get_global_data()->dynamic_pamt_enabled && (leaf_size == PT_2MB))
    {
        if ((get_hkid_from_pa((pa_t)pamt_hpa0) != 0) || !is_addr_aligned_pwr_of_2(pamt_hpa0, TDX_PAGE_SIZE_IN_BYTES) ||
            !is_pa_smaller_than_max_pa(pamt_hpa0))
        {
            TDX_ERROR("Error in Dynamic PAMT HPA0 0x%llx\n", pamt_hpa0);
            retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R12);
            goto EXIT;
        }

        if ((get_hkid_from_pa((pa_t)pamt_hpa1) != 0) || !is_addr_aligned_pwr_of_2(pamt_hpa1, TDX_PAGE_SIZE_IN_BYTES) ||
            !is_pa_smaller_than_max_pa(pamt_hpa1))
        {
            TDX_ERROR("Error in Dynamic PAMT HPA1 0x%llx\n", pamt_hpa1);
            retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R13);
            goto EXIT;
        }

        if (!pamt_get_block((pa_t)pamt_hpa0, &pamt0_block))
        {
            retval = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_R12);
            goto EXIT;
        }

        if (!pamt_get_block((pa_t)pamt_hpa1, &pamt1_block))
        {
            retval = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_R13);
            goto EXIT;
        }

        // PAMT-walk the two new pages and check their type
        retval = pamt_walk((pa_t)pamt_hpa0, pamt0_block, TDX_LOCK_SHARED, PT_4KB, true, false, &pamt0_walk_result);
        if (retval != TDX_SUCCESS)
        {
            retval = api_error_with_operand_id(retval, OPERAND_ID_R12);
            goto EXIT;
        }

        if (pamt0_walk_result.pamt_entry_p->pt != PT_NDA)
        {
            TDX_ERROR("New PAMT HPA0 - 0x%llx is not free!\n", pamt_hpa0);
            retval = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R12);
            goto EXIT;
        }

        retval = pamt_walk((pa_t)pamt_hpa1, pamt1_block, TDX_LOCK_SHARED, PT_4KB, true, false, &pamt1_walk_result);
        if (retval != TDX_SUCCESS)
        {
            retval = api_error_with_operand_id(retval, OPERAND_ID_R13);
            goto EXIT;
        }

        if (pamt1_walk_result.pamt_entry_p->pt != PT_NDA)
        {
            TDX_ERROR("New PAMT HPA1 - 0x%llx is not free!\n", pamt_hpa1);
            retval = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R13);
            goto EXIT;
        }

        // For each of the two new PAMT pages, atomically test & set its respective PAMT_PAGE_BITMAP bit.
        if (!dynamic_pamt_4k_bitmap_set(&pamt0_block, pamt_hpa0))
        {
            TDX_ERROR("New PAMT HPA0 - 0x%llx already used as PAMT page\n", pamt_hpa0);
            retval = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R12);
            goto EXIT;
        }

        if (!dynamic_pamt_4k_bitmap_set(&pamt1_block, pamt_hpa1))
        {
            dynamic_pamt_4k_bitmap_clear(&pamt0_block, pamt_hpa0);

            TDX_ERROR("New PAMT HPA1 - 0x%llx already used as PAMT page\n", pamt_hpa1);
            retval = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R13);
            goto EXIT;
        }

        // create a cache aligned, cache sized chunk and fill it with 'val'
        ALIGN(MOVDIR64_CHUNK_SIZE) pamt_entry_t chunk[PAMT_4K_ENTRIES_IN_CACHE];
        basic_memset((uint64_t)chunk, PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t), 0, PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t));

        for (uint32_t i = 0; i < PAMT_4K_ENTRIES_IN_CACHE; i++)
        {
            chunk[i].pt = demoted_pamt_entry->pt;
            chunk[i].owner = demoted_pamt_entry->owner;
            chunk[i].bepoch.raw = 0;
        }

        for (uint32_t i = 0; i < pamt_pages; i++)
        {
            pamt_entry_children_la = map_pa_with_global_hkid((void*)pamt_entry_children_pa[i], TDX_RANGE_RW);

            // Use MOVDIR64B for dynamic PAMT case, and regular copies for non-dynamic PAMT
            fill_cachelines(pamt_entry_children_la, (uint8_t*)chunk, TDX_PAGE_SIZE_IN_BYTES / MOVDIR64_CHUNK_SIZE);

            free_la(pamt_entry_children_la);
        }

        // Convert parent entry type from regular to PAMT
        demoted_pamt_entry->pt = PT_PAMT;
        ((pamt_non_leaf_entry_t*)demoted_pamt_entry)->page_hpa0 = ((pa_t)pamt_hpa0).page_4k_num;
        ((pamt_non_leaf_entry_t*)demoted_pamt_entry)->page_hpa1 = ((pa_t)pamt_hpa1).page_4k_num;
        ((pamt_non_leaf_entry_t*)demoted_pamt_entry)->page_count = 512;
    }
    else
    {
        for (uint32_t i = 0; i < pamt_pages; i++)
        {
            pamt_entry_children_la = map_pa_with_global_hkid((void*)pamt_entry_children_pa[i], TDX_RANGE_RW);

            // Use MOVDIR64B for dynamic PAMT case, and regular copies for non-dynamic PAMT
            for (uint32_t j = 0; j < pamt_entries_in_page; j++)
            {
                // Copy the leaf entry metadata to its 512 child entries
                pamt_entry_children_la[j].pt = demoted_pamt_entry->pt;
                pamt_entry_children_la[j].owner = demoted_pamt_entry->owner;
                pamt_entry_children_la[j].bepoch.raw = 0;
            }

            free_la(pamt_entry_children_la);
        }

        // Convert parent entry type from regular to NDA
        demoted_pamt_entry->pt = PT_NDA;
    }

    retval = TDX_SUCCESS;

EXIT:

    if (pamt1_walk_result.valid)
    {
        pamt_unwalk(&pamt1_walk_result);
    }

    if (pamt0_walk_result.valid)
    {
        pamt_unwalk(&pamt0_walk_result);
    }

    if (demoted_entry_locked)
    {
        // Release previously acquired exclusive lock
        release_sharex_lock_hp_ex(&demoted_pamt_entry->entry_lock);
    }

    free_la(demoted_pamt_entry);
    return retval;
}
