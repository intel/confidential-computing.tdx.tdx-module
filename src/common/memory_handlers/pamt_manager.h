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
 * @file pamt_manager.h
 * @brief PAMT manager headers
 */

#ifndef SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_
#define SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_

#include "tdx_basic_types.h"
#include "helpers/tdx_locks.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"

#include TDX_ERROR_CODES_DEFS_HEADER

// With dynamic PAMT, the number of non-HKID bits in HPA must be at most 48
#define MAX_DYNAMIC_PAMT_HKID_START_BIT         48

/**
 * @brief Enum for page type in PAMT
 */
typedef enum {
    PT_NDA   = 0,
    PT_RSVD  = 1,
    PT_REG   = 3,
    PT_TDR   = 4,
    PT_TDCX  = 5,
    PT_TDVPR = 6,
    //reserved = 7,
    PT_EPT   = 8
    // TDX-IO
    ,PT_DEVIFCS_R  = 9,
    PT_DEVIFCS_NR = 10,
    PT_IOMMU_MT   = 11,
    PT_MMIO_MT    = 12,
    PT_DEVIF_MT   = 13
    ,PT_PAMT  = 15
} page_type_t;


#define PAMT_ENTRY_SIZE_IN_BYTES        16

#define PAMT_4K_ENTRIES_IN_2MB    (_2MB / _4KB)
#define PAMT_4K_ENTRIES_IN_1GB    (_1GB / _4KB)
#define PAMT_4K_ENTRIES_IN_CACHE  (MOVDIR64_CHUNK_SIZE / sizeof(pamt_entry_t))

/**
 * @struct bepoch_t
 *
 * @brief BEPOCH is part of the PAMT entry.  It is used for either holding BEPOCH for TLB tracking
   or migration epoch for migration tracking.
 */
typedef union bepoch_u
{
    struct
    {
        uint64_t mig_epoch    : 32; // Bits 31:0  : Migration epoch
        uint64_t export_count : 31; // Bits 62:32 : Export counter
        uint64_t mig_flag     : 1;  // Bit 63     : If set, indicates that BEPOCH is used for migration epoch
    };

    uint64_t raw;
} bepoch_t;
tdx_static_assert(sizeof(bepoch_t) == 8, bepoch_t);

/**
 * @struct pamt_entry_t
 *
 * @brief PAMT entry structure
 */
typedef struct pamt_entry_s
{
    struct
    {
        sharex_hp_lock_t entry_lock; // 2 byte (16 bit)
        page_type_t pt : 8;
        //uint64_t reserved : 3; // WA for ticket https://hsdes.intel.com/appstore/article-one/#/13013681268
        uint64_t owner : 40; // don't access this field directly, use accessors below
    }; // primary

    union
    {
        bepoch_t bepoch;
    }; // additional
} pamt_entry_t;
tdx_static_assert(sizeof(pamt_entry_t) == PAMT_ENTRY_SIZE_IN_BYTES, pamt_entry_t);
tdx_static_assert((MOVDIR64_CHUNK_SIZE % sizeof(pamt_entry_t)) == 0, pamt_entry_t_2);

#define PAMT_NL_PAGE_COUNT_MASK         0x3FF

/**
 * @struct pamt_entry_t
 *
 * @brief PAMT entry structure
 */
typedef struct pamt_non_leaf_entry_s
{
    struct
    {
        sharex_hp_lock_t entry_lock; // 2-byte
        page_type_t      pt        :  5;
        uint64_t         reserved0 :  7;
        uint64_t         page_hpa0 : 36; // don't access this field directly, use accessors below
    }; // first quadword

    union
    {
        struct
        {
            uint64_t         page_count : 10;
            uint64_t         reserved1  : 18;
            uint64_t         page_hpa1  : 36; // don't access this field directly, use accessors below
        }; // second quadword

        uint64_t second_quadword;
    };

} pamt_non_leaf_entry_t;
tdx_static_assert(sizeof(pamt_non_leaf_entry_t) == PAMT_ENTRY_SIZE_IN_BYTES, pamt_non_leaf_entry_t);
tdx_static_assert((MOVDIR64_CHUNK_SIZE % sizeof(pamt_non_leaf_entry_t)) == 0, pamt_non_leaf_entry_t_2);

_STATIC_INLINE_ pa_t get_pamt_entry_owner(pamt_entry_t* pamt_entry)
{
    pa_t owner_pa;
    owner_pa.raw = ((uint64_t)pamt_entry->owner) << 12;
    return owner_pa;
}

_STATIC_INLINE_ void set_pamt_entry_owner(pamt_entry_t* pamt_entry, pa_t owner)
{
    pamt_entry->owner = owner.page_4k_num;
}

_STATIC_INLINE_ pa_t get_pamt_node_page0(pamt_non_leaf_entry_t* pamt_entry)
{
    pa_t pa;
    pa.raw = ((uint64_t)pamt_entry->page_hpa0) << 12;
    return pa;
}

_STATIC_INLINE_ pa_t get_pamt_node_page1(pamt_non_leaf_entry_t* pamt_entry)
{
    pa_t pa;
    pa.raw = ((uint64_t)pamt_entry->page_hpa1) << 12;
    return pa;
}

#define PAMT_CHILD_ENTRIES              ( 512 )

#define PAMT_2MB_ENTRIES_IN_1GB         ( PAMT_CHILD_ENTRIES )
#define PAMT_4KB_ENTRIES_IN_1GB         ( PAMT_CHILD_ENTRIES * PAMT_2MB_ENTRIES_IN_1GB )

#define DEFAULT_NUM_PAMT_PAGES          2

/**
 * @struct pamt_block_t
 *
 * @brief 1GB PAMT block virtual structure. Contains 3 physical pointers, 1 to PAMT_1GB entry
 *        from the TDMR.PAMT_1GB array, and to the corresponding (to that 1GB area) PAMT_2MB entries (512)
 *        and PAMT_4KB entries (512*512).
 *        In dynamic PAMT mode, the 4KB pointer points to a 4K page bitmap array
 */
typedef struct pamt_block_s
{
    uint64_t      tdmr_base;
    pamt_entry_t* pamt_1gb_p;
    pamt_entry_t* pamt_2mb_p;
    pamt_entry_t* pamt_4kb_p;
} pamt_block_t;

/**
 * @struct pamt_walk_result_t
 *
 * @brief Pointers stored by pamt_walk function for all levels reached.
 *        Pointers at index < level_reached are invalid and set to NULL.
 *        A union is made for convenience, since some entries can be non-leaf, and some can be leaf.
 *        Once created by pamt_walk, at the usage end must be passed to pamt_unwalk to free all the pointers.
 */
typedef struct pamt_walk_result_s
{
    bool_t valid;
    page_size_t level_reached;

    union
    {
        pamt_entry_t*          pamt_walk_path[PT_1GB + 1];
        pamt_non_leaf_entry_t* pamt_walk_path_nl[PT_1GB + 1];
    };

    lock_type_t leaf_lock_type;
    pamt_entry_t* pamt_entry_p; // Actual PAMT entry that should be used in most cases
} pamt_walk_result_t;

/**
 * @brief Set, get or clear a bit in dynamic PAMT 4K bitmap, corresponding to the PAMT
 *
 * @param pamt_block - PAMT block related to the PAMT page
 * @param hpa - Physical address of the PAMT page
 *
 * @return If bit setting was successful
 */
bool_t dynamic_pamt_4k_bitmap_set(pamt_block_t* pamt_block, uint64_t hpa);
uint8_t dynamic_pamt_4k_bitmap_get(pamt_block_t* pamt_block, uint64_t hpa);
void dynamic_pamt_4k_bitmap_clear(pamt_block_t* pamt_block, uint64_t hpa);

#define PAMT_REMOVAL_HINT_BIT_NUM       62
#define PAMT_REMOVAL_HINT               BIT(PAMT_REMOVAL_HINT_BIT_NUM)

/**
 * @brief If the provided non-leaf PAMT entry pointer (should happen only if the TDX module is configured for
 *         Dynamic PAMT and the non-leaf entry is a PAMT_2M entry), atomically increment the non-leaf entry's page count.
 *         Else, do nothing.
 *
 * @param pamt_nl_entry
 */
void pamt_inc_nl_page_count(pamt_non_leaf_entry_t* pamt_nl_entry);

/**
 * @brief If the provided non-leaf PAMT entry pointer in non-NULL (should happen only if the TDX module is configured for
 *        Dynamic PAMT and the non-leaf entry is a PAMT_2M entry):
 *        - Atomically decrement the non-leaf entry's page count.
 *        - If the number of entries is decremented to 0, return true.  Else, return false.
 *        Else, do nothing and return false.
 *
 * @param pamt_nl_entry
 */
bool_t pamt_dec_nl_page_count(pamt_non_leaf_entry_t* pamt_nl_entry);

_STATIC_INLINE_ uint64_t pamt_dec_nl_page_count_and_get_hint(pamt_non_leaf_entry_t* pamt_nl_entry)
{
    return VAL_OR_ZERO(PAMT_REMOVAL_HINT, pamt_dec_nl_page_count(pamt_nl_entry));
}

/**
 * @brief Tells if the page belongs to reserved area.
 *        When used for sequential pages remembers the last_rsvd_idx for faster search
 *
 * @param page_offset Page offset from the TDMR base
 * @param tdmr_entry TDMR entry that defines the reserved areas
 * @param last_rsdv_idx Remembers the last reserved area index
 * @return
 */
bool_t is_page_reserved(uint64_t page_offset, tdmr_entry_t *tdmr_entry, uint32_t* last_rsdv_idx);

/**
 * @brief Gets a covering TDMR for given HPA
 *
 * @param pa
 * @return
 */
tdmr_entry_t* get_covering_tdmr_for_hpa(pa_t pa);

/**
 * @brief This function gets a 4KB page aligned physical address and valid flag and returns a
 * physical pointer to PAMT entries corresponding 1GB PAMT range and its valid state.
 *
 * If [pa] is not covered by any TDMR or the PAMT return NULL.
 *
 * If the PAMT block is not initialized, return NULL;
 *
 * @param pa Physical address corresponding to the PAMT block, the HKID is removed from the PA within the function itself
 * @param pamt_block PAMT block structure to be filled with relevant physical pointers
 *
 * @return Returns TRUE if found PAMT block. FALSE if not found, or if @a pa not initilizaed.
 *
 */
bool_t pamt_get_block(pa_t pa, pamt_block_t* pamt_block);

/**
 * @brief PAMT initialize function that gets a PAMT block.
 *
 * This function implicitly initializes node PAMT entries of 2MB and 1GB pages.
 *
 * @param pamt_block Physical address of the pamt_block that needs to be initialized.
 */
void pamt_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry);

/**
 * @brief Performs PAMT hierarchical walk from top PAMT entry(1GB) to leaf level (1GB...4KB)
 *
 * PAMT walk acquires shared locks on non-leaf entries and shared/exclusive lock on the
 * leaf entry according to exclusive_leaf_lock flag.
 *
 * PAMT walk may fail to acquire PAMT entry lock, in this case, it unlocks all the PAMT
 * entry locks it already acquired and return NULL.
 *
 * @note Returned physical pointer to the PAMT entry should be always mapped to linear.
 *
 * @param pa Physical address corresponding to the PAMT entry
 * @param pamt_block PAMT block virtual structure covering the @a pa
 * @param leaf_lock_type Determines whether on the found PAMT leaf entry, the taken lock should
 *                            be shared or exclusive.
 * @param target_size - Stops at target size if walk_to_leaf_size is true
 * @param walk_to_leaf_size - If true, PAMT walk stops at target_size
 * @param is_guest - Indicates whether the walk+lock request came from the TD guest
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 *
 * @return Error code status
 */
api_error_code_e pamt_walk(pa_t pa, pamt_block_t pamt_block, lock_type_t leaf_lock_type,
                           page_size_t target_size, bool_t walk_to_target_size,
                           bool_t is_guest, pamt_walk_result_t* pamt_walk_result);

/**
 * @brief Performs PAMT lock release in a reverse order to PAMT walk (i.e. from leaf PAMT entry
 *        to top 1GB PAMT entry.
 *
 * @note The function does not perform and check on PAMT entries and assumes the user
 *       is responsible to call it with the same parameters used for the previous PAMT walk.
 *       The leaf entry linear pointer that was received from the corresponding PAMT walk will
 *       also be freed by the unwalk function.
 *
 * @param pamt_walk_result - Uses the reached level, lock type and pointers for the unwalk process.
 *                           Frees all the pointers.
 */
void pamt_unwalk(pamt_walk_result_t* pamt_walk_result);

/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Does not acquires any locks.
 *        Function cannot fail, and failure will result in module halt.
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @return Linear address of the pamt_entry. Should be freed after use.
 */
pamt_entry_t* pamt_implicit_get(pa_t pa, page_size_t leaf_size);

/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Does not acquires any locks.
 *        Function cannot fail, and failure will result in module halt.
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @param pamt_nl_entry If Dynamic PAMT is enabled, and leaf size is 4KB returns pointer to parent 2MB non-leaf entry.
 *                      If the pointer is non-NULL, must be freed
 * @return Linear address of the pamt_entry, and parent non-leaf entry. Both should be freed after use.
 */
pamt_entry_t* pamt_implicit_get_with_nl_entry(pa_t pa, page_size_t leaf_size, pamt_non_leaf_entry_t** pamt_nl_entry);

/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Acquires a lock as stated in
 *        the input parameter
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @param leaf_lock_type Determines whether on the found PAMT leaf entry, the taken lock should
 *                            be shared or exclusive.
 * @param pamt_entry returns the linear address of the PAMT entry if the lock acquisition succeeded.
 *                   Should be freed after use. Returns NULL if lock failed (doesn't need to be freed in that case).
 * @param is_guest Specifies if the lock is for guest or host
 *
 * @return Error code status
 */
api_error_code_e pamt_implicit_get_and_lock(pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                            pamt_entry_t** pamt_entry, bool_t is_guest);

/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Acquires a lock as stated in
 *        the input parameter
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @param leaf_lock_type Determines whether on the found PAMT leaf entry, the taken lock should
 *                            be shared or exclusive.
 * @param pamt_entry returns the linear address of the PAMT entry if the lock acquisition succeeded.
 *                   Should be freed after use. Returns NULL if lock failed (doesn't need to be freed in that case).
 * @param is_guest Specifies if the lock is for guest or host
 * @param pamt_nl_entry If Dynamic PAMT is enabled, and leaf size is 4KB returns pointer to parent 2MB non-leaf entry.
 *                      If the pointer is non-NULL, must be freed
 *
 * @return Error code status
 */
api_error_code_e pamt_implicit_get_with_nl_entry_and_lock(
                                pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                pamt_entry_t** pamt_entry, pamt_non_leaf_entry_t** pamt_nl_entry, bool_t is_guest);

/**
 * @brief Frees the lock of an implicit pamt entry, and also frees the pamt_entry linear address
 * @param pamt_entry Linear pointer to the leaf PAMT entry that will be freed by the function
 * @param leaf_lock_type Determines whether the lock taken on the leaf entry was shared or exclusive.
 */
void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type);

/**
 * @brief Frees the lock of an implicit pamt entry, and also frees the pamt_entry linear address
 * @param pamt_entry Linear pointer to the leaf PAMT entry that will be freed by the function
 * @param leaf_lock_type Determines whether the lock taken on the leaf entry was shared or exclusive.
 */
void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type);

/**
 * @brief Goes over 2MB PAMT range and checks that all 4KB child entries has NDA type
 * @param pa Physical address corresponding to the 2MB PAMT range
 * @param pamt_block PAMT block virtual structure covering the @a pa
 *
 * @return if the 2MB range free or not
 */
bool_t pamt_is_2mb_range_free(pa_t pa, pamt_block_t* pamt_block);

api_error_code_e pamt_promote(pa_t pa, page_size_t new_leaf_size, uint64_t removed_child_pages[DEFAULT_NUM_PAMT_PAGES]);

api_error_code_e pamt_demote(pa_t pa, page_size_t leaf_size, uint64_t pamt_hpa0, uint64_t pamt_hpa1);

#endif /* SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_ */
