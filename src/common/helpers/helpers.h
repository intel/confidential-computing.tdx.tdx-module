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
 * @file helpers.h
 * @brief Common TDX API flow helper functions
 */

#ifndef SRC_COMMON_HELPERS_HELPERS_H_
#define SRC_COMMON_HELPERS_HELPERS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include TD_L2_VMCS_FIELDS_LOOKUP_HEADER
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "data_structures/td_vmcs_init.h"
#include "data_structures/tdx_tdvps.h"
#include "error_reporting.h"

#define PRIVATE_ONLY true
#define PRIVATE_OR_SHARED false

#define CPUID_LOOKUP_IDX_NA        ((uint32_t)-1)
#define CPUID_SUBLEAF_NA           ((uint32_t)-1)

#define QUADWORDS_IN_256b 4

// (Y + (x-1))/x == padded Y to be x aligned
#define CALCULATE_NUMBER_OF_UNITS_WITH_PADDING(entries, alignment_unit) ((entries + alignment_unit -1) / alignment_unit)

_STATIC_INLINE_ bool_t is_equal_256bit(uint256_t a, uint256_t b)
{
    return (((a.qwords[0] ^ b.qwords[0]) | (a.qwords[1] ^ b.qwords[1]) |
             (a.qwords[2] ^ b.qwords[2]) | (a.qwords[3] ^ b.qwords[3])) == 0);
}

/**
 * @brief Program MKTME keys using PCONFIG
 *
 * @param command - MKTME program command to pass to PCONFIG
 * @param key_info_ptr - Points to a key info struct that holds the rest
 *                       of the required MKTME program info
 *                       - i.e. hkid, encryption algo and keys
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e program_mktme_keys(uint16_t hkid);

_STATIC_INLINE_ uint32_t calculate_xsave_area_max_size(ia32_xcr0_t xfam)
{
    // Calculate CPUID leaf 0xD sub-leaf 0x0 ECX value, the  maximum size of the
    // XSAVE/XRSTOR save area required by supported features in XCR0, by temporarily
    // setting XCR0 to the user bits in XFAM, then executing CPUID.  This returns
    // in EBX the maximum size required for XFAM-enabled user-level features.

    ia32_xcr0_t original_xcr0;
    original_xcr0.raw = ia32_xgetbv(0);
    ia32_xsetbv(0, xfam.raw & XCR0_USER_BIT_MASK);

    uint32_t eax, ebx, ecx, edx;
    ia32_cpuid(CPUID_EXT_STATE_ENUM_LEAF, 0, &eax, &ebx, &ecx, &edx);

    ia32_xsetbv(0, original_xcr0.raw);

    return ebx;
}

_STATIC_INLINE_ pa_t page_info_to_pa(page_info_api_input_t page_info)
{
    pa_t pa = { .raw = 0 };
    pa.page_4k_num = page_info.gpa;
    return pa;
}

_STATIC_INLINE_ uint64_t construct_wrmsr_value(uint64_t rdx, uint64_t rax)
{
    return ((rdx << 32) | (rax & BIT_MASK_32BITS));
}

typedef enum
{
    VE_INFO_ARCH = 0x00,
    VE_INFO_PENDING = 0x01,
    VE_INFO_RESERVED_GPA_BITS = 0x02,
    VE_INFO_CONFIG_PARAVIRT = 0x10,
    VE_INFO_NON_CONFIG_PARAVIRT = 0x11,
    VE_INFO_UNSUPPORTED_FEATURE = 0x80
} ve_category_e;

_STATIC_INLINE_ uint16_t construct_msr_status_with_ve_category(uint16_t status, ve_category_e ve_category)
{
    return (uint16_t)(((uint32_t)ve_category << 8) | (uint32_t)status);
}

_STATIC_INLINE_ bool_t are_gpa_bits_above_virt_maxpa_set(uint64_t gpa, bool_t gpaw, uint64_t virt_maxpa)
{
    uint16_t gpa_width = gpaw ? 52 : 48;
    uint16_t shared_pa = gpa_width - 1;

    if (0 == virt_maxpa)
    {
        virt_maxpa = MAX_PA;
    }

    // If the SHARED bit is 47 and virt_max_pa > 48, then any bits in the range virt_max_pa:48 must be 0
    if ((47 == shared_pa) && (virt_maxpa > 48) && ((gpa & BITS(virt_maxpa - 1, 48)) != 0))
    {
        return true;
    }

    if (virt_maxpa < 52)
    {
        return ((gpa & BITS(51, virt_maxpa) & ~BIT(shared_pa)) != 0);
    }

    return false;
}

_STATIC_INLINE_ bool_t get_gpa_shared_bit(uint64_t gpa, bool_t gpaw)
{
    uint16_t gpa_width_minus_1 = gpaw ? 51 : 47;

    // When TD is configured with a 4 level EPT then the S bit is always bit 47 of the GPA.
    // When a TD is configured with 5 level EPT then the S bit is in bit 47 if GPAW
    // is configured to be 48, else it is bit 51.

    return (gpa & BIT(gpa_width_minus_1)) != 0;
}


_STATIC_INLINE_ uint64_t get_addr_from_pa(pa_t pa)
{
    return pa.full_pa & ~(get_global_data()->hkid_mask);
}

_STATIC_INLINE_ uint16_t get_hkid_from_pa(pa_t pa)
{
    tdx_module_global_t* global_data = get_global_data();

    return (uint16_t)((pa.full_pa & global_data->hkid_mask) >> global_data->hkid_start_bit);
}

_STATIC_INLINE_ pa_t set_hkid_to_pa(pa_t pa, uint16_t hkid)
{
    tdx_module_global_t* global_data = get_global_data();

    pa.full_pa &= ~(global_data->hkid_mask);
    pa.full_pa |= ((uint64_t)hkid << global_data->hkid_start_bit);

    return pa;
}

/**
 * @brief Remove HKID from PA, except if a NULL_PA is passed
 *
 * @param pa
 *
 * @return pa_t
 */
_STATIC_INLINE_ pa_t remove_hkid_from_pa(const pa_t pa)
{
    return pa.raw == NULL_PA ? pa : set_hkid_to_pa(pa, 0);
};

_STATIC_INLINE_ bool_t is_addr_aligned_pwr_of_2(uint64_t addr, uint64_t size)
{
    tdx_debug_assert((size > 1) && ((size & (size - 1)) == 0));
    return ((addr & (size - 1)) == 0);
}

_STATIC_INLINE_ bool_t is_addr_aligned_any(uint64_t addr, uint64_t size)
{
    tdx_debug_assert(size > 0);
    return ((addr % size) == 0);
}

_STATIC_INLINE_ bool_t is_gpa_aligned(page_info_api_input_t gpa_mappings)
{
    uint64_t page_gpa = gpa_mappings.gpa << 12;
    uint64_t alignment = (1ULL) << (12 + (gpa_mappings.level * 9));

    return is_addr_aligned_pwr_of_2(page_gpa, alignment);
}

_STATIC_INLINE_ uint64_t align_gpa_on_level(
    const pa_t page_gpa,
    const ept_level_t ept_level)
{
    return page_gpa.raw & ~(BIT(12 + (ept_level * 9)) - 1);
}

_STATIC_INLINE_ bool_t is_private_hkid(uint16_t hkid)
{
    return ((uint32_t)hkid >= get_global_data()->private_hkid_min &&
            (uint32_t)hkid <= get_global_data()->private_hkid_max);
}

_STATIC_INLINE_ bool_t is_pa_smaller_than_max_pa(uint64_t pa)
{
    return (pa < BIT(MAX_PA));
}

_STATIC_INLINE_ bool_t is_valid_integer_range(uint64_t base, uint64_t size)
{
    return (base <= (MAX_UINT64 - size));
}

_STATIC_INLINE_ bool_t is_overlap(uint64_t base, uint64_t size, uint64_t base2, uint64_t size2)
{
    // Check for integer overflow - in all calls to is_overlap, the ranges should be checked
    // before, and create an appropriate error, if the FATAL ERROR is not desired
    // The check here is for DiD only, not functionality
    IF_RARE (!is_valid_integer_range(base, size) || !is_valid_integer_range(base2, size2))
    {
        fatal_error(FATAL_ERROR_ID_37, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    if ((base >= (base2 + size2)) || (base2 >= (base + size)))
    {
        return false;
    }
    return true;
}

_STATIC_INLINE_ uint64_t mask_to_size(uint64_t mask)
{
    if (mask == 0)
    {
        fatal_error(FATAL_ERROR_ID_38, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    uint64_t lsb_position;
    (void)bit_scan_forward64(mask, &lsb_position);

    return BIT(lsb_position);
}

_STATIC_INLINE_ bool_t is_reserved_zero_in_mappings(page_info_api_input_t mappings)
{
    return !(mappings.reserved_0 || mappings.reserved_1);
}

_STATIC_INLINE_ void* map_pa_with_hkid(void* pa, uint16_t hkid, mapping_type_t mapping_type)
{
    pa_t temp_pa = {.raw_void = pa};
    pa_t pa_with_hkid = set_hkid_to_pa(temp_pa, hkid);
    return map_pa((void*) pa_with_hkid.raw, mapping_type);
}

_STATIC_INLINE_ void* map_pa_with_global_hkid(void* pa, mapping_type_t mapping_type)
{
    uint16_t tdx_global_hkid = get_global_data()->hkid;
    return map_pa_with_hkid(pa, tdx_global_hkid, mapping_type);
}


/**
 * @brief Get HPA from EPT entry and GPA
 *
 * @param entry - EPT entry for this GPA
 * @param gpa - GPA
 * @param level - EPT entry level
 *
 * @return Address of HPA
 */
_STATIC_INLINE_ uint64_t leaf_ept_entry_to_hpa(ia32e_sept_t entry, uint64_t gpa, ept_level_t level)
{
    switch(level)
    {
        case LVL_PT:
        {
            return ((entry.base << IA32E_4K_PAGE_OFFSET) | (gpa & IA32E_4K_OFFSET));
        }
        case LVL_PD:
        {
            return (((uint64_t)(entry.fields_2m.base_2m) << IA32E_2M_PAGE_OFFSET) | (gpa & IA32E_2M_OFFSET));
        }
        case LVL_PDPT:
        {
            return (((uint64_t)(entry.fields_1g.base_1g) << IA32E_1G_PAGE_OFFSET) | (gpa & IA32E_1G_OFFSET));
        }
        default:
        {
            // Not supported
            tdx_sanity_check(0, FATAL_ERROR_ID_182, 0);
            return 0;
        }
    }
}

/**
 * @brief Memset functions that use basic memory access (not direct access with MOVDIR64)
 *
 */
void basic_memset(uint64_t dst, uint64_t dst_bytes, uint8_t val, uint64_t nbytes);
void basic_memset_to_zero(void * dst, uint64_t nbytes);
#if (!defined(__cplusplus))
void* memset(void *str, int c, uint32_t n);
#endif // (!defined(__cplusplus))

/**
 * @brief Copies source to destination using movdir64b
 *
 * Source, destination and size need to be cache aligned (64 byte)
 * Uses lfence between movdir64b calls
 *
 * @param src - Source address
 * @param dst - Destination address
 * @param size - Size in bytes to copy
 *
 * @return Address of HPA
 */
void cache_aligned_copy_direct(uint64_t src, uint64_t dst, uint64_t size);

_STATIC_INLINE_ bool_t is_cacheline_aligned(void* dst)
{
    return (((uint64_t)dst % MOVDIR64_CHUNK_SIZE) == 0);
}

/**
 * @brief Fill cache lines with movdir64 using cache aligned & sized chunks
 *
 * @note dst address must be aligned to cache line
 * @note cacheline_with_value must be aligned to cache line
 *
 * @param dst destination address
 * @param cacheline_with_value a cache line aligned and sized array with a value
 * @param num_of_cachelines number of cache lines to write to in dst
 */
_STATIC_INLINE_ void fill_cachelines_no_sfence(void* dst, uint8_t* cacheline_with_value, uint64_t num_of_cachelines)
{
    tdx_debug_assert(((uint64_t)dst % MOVDIR64_CHUNK_SIZE) == 0);
    tdx_debug_assert(((uint64_t)cacheline_with_value % MOVDIR64_CHUNK_SIZE) == 0);
    uint64_t tmp_dst = (uint64_t)dst;

    for (uint64_t i = 0; i < num_of_cachelines; i++, tmp_dst+=MOVDIR64_CHUNK_SIZE)
    {
        movdir64b(cacheline_with_value, tmp_dst);
    }
}

/**
 * @brief Fill cache lines with movdir64 using cache aligned & sized chunks
 *
 * @note dst address must be aligned to cache line
 * @note cacheline_with_value must be aligned to cache line
 *
 * @param dst destination address
 * @param cacheline_with_value a cache line aligned and sized array with a value
 * @param num_of_cachelines number of cache lines to write to in dst
 */
_STATIC_INLINE_ void fill_cachelines(void* dst, uint8_t* cacheline_with_value, uint64_t num_of_cachelines)
{
    fill_cachelines_no_sfence(dst, cacheline_with_value, num_of_cachelines);
    mfence();
}

/**
 * @brief Fill memory area using movdir64
 *
 * @note dst address must be aligned to cache line
 * @note nBytes size must be in complete cache lines
 * @note val64 value to be filled
 *
 * @param dst
 * @param nBytes
 */
_STATIC_INLINE_ void fill_area_cacheline(void* dst, uint64_t nBytes, uint64_t val64)
{
    tdx_debug_assert((nBytes % MOVDIR64_CHUNK_SIZE == 0));
    tdx_debug_assert((uint64_t)dst % MOVDIR64_CHUNK_SIZE == 0);

    // create a cache aligned, cache sized chunk and fill it with 'val'
    ALIGN(MOVDIR64_CHUNK_SIZE) uint64_t chunk[MOVDIR64_CHUNK_SIZE / sizeof(uint64_t)];

    for (uint32_t i = 0; i < MOVDIR64_CHUNK_SIZE / sizeof(uint64_t); i++)
    {
        chunk[i] = val64;
    }

    fill_cachelines(dst, (uint8_t*)chunk, nBytes/MOVDIR64_CHUNK_SIZE);
}

/**
 * @brief Zero memory area using movdir64
 *
 * @note nBytes size must be in complete cache lines
 * @note dst address must be aligned to cache line
 *
 * @param dst
 * @param nBytes
 */
_STATIC_INLINE_ void zero_area_cacheline(void* dst, uint64_t nBytes)
{
    fill_area_cacheline(dst, nBytes, 0);
}

_STATIC_INLINE_ void zero_cacheline(void* dst)
{
    fill_area_cacheline(dst, MOVDIR64_CHUNK_SIZE, 0);
}

_STATIC_INLINE_ void tdx_memcpy(
    const void * dst,
    const uint64_t dst_bytes,
    const void * const src,
    const uint64_t nbytes)
{
    volatile uint64_t junk_a, junk_b, junk_c;

    tdx_sanity_check (dst_bytes >= nbytes, FATAL_ERROR_ID_183, 1);

    _ASM_VOLATILE_ ("rep; movsb;"
                    :"=S"(junk_a), "=D"(junk_b), "=c"(junk_c)
                    :"c"(nbytes), "S"(src), "D"(dst)
                    :"memory");
}


_STATIC_INLINE_ bool_t tdx_memcmp_safe(const void * a, const void * b, uint64_t nbytes)
{
    volatile uint8_t result = 0;
    volatile uint8_t* a_8 = (uint8_t*)a;
    volatile uint8_t* b_8 = (uint8_t*)b;

    for (uint64_t i = 0; i < nbytes; i++)
    {
        result |= (a_8[i] ^ b_8[i]);
    }

    return (result == 0);
}

_STATIC_INLINE_ bool_t tdx_memcmp(void * a, void * b, uint64_t nbytes)
{
    ia32_rflags_t rflags;
    uint64_t junk_a, junk_b, junk_c;
    _ASM_VOLATILE_ ("repe; cmpsb;"
                    "pushfq\n"
                    "popq %0"
                    : "=r"(rflags.raw), "=S"(junk_a), "=D"(junk_b), "=c"(junk_c)
                    :"c"(nbytes), "S"(b), "D"(a)
                    :"memory");
    if (rflags.zf == 0)
    {
        return false;
    }
    return true;
}

_STATIC_INLINE_ bool_t tdx_memcmp_to_zero(void *a, uint64_t nBytes)
{
    uint64_t i = 0;
    uint8_t* a_8 = (uint8_t*)a;

    for ( ; (i + (uint64_t)sizeof(uint64_t)) <= nBytes; i += (uint64_t)sizeof(uint64_t))
    {
        uint64_t* a_64 = (uint64_t*)(&a_8[i]);

        if (*a_64 != 0)
        {
            return false;
        }
    }

    for ( ; i < nBytes; i++)
    {
        if (a_8[i] != 0)
        {
            return false;
        }

    }

    return true;
}

/**
 * @brief Invalidate cache lines using CLFLUSHOPT
 *
 * @note Assuming addr is cache aligned and size is cache line size divisible
 *
 * @param start_addr - Start address (cache aligned) of memory we want to invalidate (linear address)
 * @param size - Size of memory to invalidate
 *
 * @return None
 */
_STATIC_INLINE_ void invalidate_cache_lines(uint64_t start_addr, uint64_t size)
{
    // CLFLUSHOPT works on cache lines
    uint64_t num_of_cache_lines = (size/CACHELINE_SIZE);

    for (uint64_t i = 0; i < num_of_cache_lines; i++)
    {
        ia32_clflushopt((void *)start_addr);
        start_addr += (uint64_t)CACHELINE_SIZE;
    }
    mfence();
}

/*
 * Access semantics internal helpers:
 */

/**
 * @brief PAMT walk and check for non-shared HPA semantics
 *
 *  1) Check that the operand’s HPA is within a TDMR (Trust Domain Memory Range) which is covered by a PAMT.
 *  2) Find the PAMT entry for the page and verify that its metadata is as expected.
 *  3) If asked by walk_to_leaf_size, will also check if a correct leaf was reached
 *
 * @param hpa - HPA that needs to be checked
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param target_size - Stops at target size if walk_to_leaf_size is true
 * @param walk_to_leaf_size - If true, PAMT walk stops at target_size
 * @param is_guest - Indicated whether the PAMT walk/lock request came from the TD guest
 * @param pamt_block - Returns the the pamt_block virtual structure that covers the HPA
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e non_shared_hpa_metadata_check_and_lock(
        pa_t hpa,
        lock_type_t lock_type,
        page_type_t expected_pt,
        page_size_t target_size,
        bool_t walk_to_target_size,
        bool_t is_guest,
        pamt_block_t* pamt_block,
        pamt_walk_result_t* pamt_walk_result
        );

/**
 * @brief Assigns the HKID from given TDR to the given HPA
 *
 *  1) If the target page is TDR (given TDR pointer is NULL), then use the TDX-SEAM global private HKID.
 *  2) Else, read the HKID value associated with the TD from the TDR page.
 *
 * @note If the TDR is not NULL - function assumes that it is already assigned with the HKID
 *
 * @param tdr_p Linear pointer to TDR where HKID will be taken from. If it's NULL then TDX-SEAM global
 *              private HKID will be used
 * @param hpa HPA to which the HKID will be assigned to
 * @return HPA with the assigned HKID
 */
pa_t assign_hkid_to_hpa(tdr_t* tdr_p, pa_t hpa);

/**
 * @brief Check the HPA for shared access semantics
 *
 *  1) Check that the provided HPA is outside SEAMRR.
 *  2) Check that HKID bits in the HPA are in the range configured for shared HKIDs (0 to MAX_MKTME_HKIDS – 1).
 *
 * @param hpa HPA to be checked
 * @param size of the HPA
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e shared_hpa_check(pa_t hpa, uint64_t size);

/**
 * @brief Adds alignment check with power of 2 size to shared_hpa_check
 *
 * @param hpa HPA to be checked
 * @param size Size to be aligned with (MUST be power of 2)
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e shared_hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size);

/**
 * @brief Adds alignment check with power of 2 size to hpa_check
 *
 * @param hpa HPA to be checked
 * @param size Size to be aligned with (MUST be power of 2)
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size);

/*
 * Explicit access semantics helpers:
 */

/**
 * @brief Check an explicit TDR operand for opaque access semantics, given its HPA, get and
 *        lock its PAMT block & entry and map to LA in the TDX-SEAM module address space.
 *
 * @note  Expected page size is 4KB.
 *
 * @param tdr_hpa - Physical address of the TDR page
 * @param operand_id - Operand ID number
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type - should be either PT_NDA during
 *                      TDR creation, or PT_TDR for everything else.
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param tdr_p      - Returns the linear pointer to the TDR page. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_lock_and_map_explicit_tdr(
        pa_t tdr_hpa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked,
        tdr_t** tdr_p
        );

/**
 * @brief Identical to check_lock_and_map_explicit_tdr, but intended to be used by ServTD guest-side API's
 *        in order to check lock and map a TDR of another TD.
 *
 * @param tdr_hpa - Physical address of the TDR page
 * @param operand_id - Operand ID number
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type - should be either PT_NDA during
 *                      TDR creation, or PT_TDR for everything else.
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param tdr_p      - Returns the linear pointer to the TDR page. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
api_error_type othertd_check_lock_and_map_explicit_tdr(
        pa_t tdr_hpa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked,
        tdr_t** tdr_p
        );

/**
 * @brief Check an explicit 4KB page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry, and map to LA in the TDX-SEAM module address space.
 *
 * @note  Expected page size is 4KB.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param la         - Returns mapped linear address of the HPA. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_lock_and_map_explicit_private_4k_hpa(
        pa_t hpa,
        uint64_t operand_id,
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked,
        void**         la);

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param alignment - the hpa alignment
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param target_size  - Returns the PAMT leaf size of the HPA entry
 * @param walk_to_target_size - If it is true, leaf_size is used as an input too, and PAMT walk stops at that level
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_and_lock_explicit_private_hpa(
        pa_t hpa,
        uint64_t operand_id,
        uint64_t alignment,
        lock_type_t lock_type,
        page_type_t expected_pt,
        page_size_t target_size,
        bool_t walk_to_target_size,
        pamt_block_t* pamt_block,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked
        );

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_and_lock_explicit_4k_private_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked
        );

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param range_size - Desired range size to check and lock. Should be only 4KB or 2MB.
 * @param pamt_walk_result - Returns the linear pointers of all PAMT entries reached during the walk.
 *                           Returns the reached level.
 *                           Non-reached levels contain NULL. Must be passed to pamt_unwalk to be freed after use.
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_and_lock_free_range_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_size_t range_size,
        pamt_walk_result_t* pamt_walk_result,
        bool_t* is_locked
        );

/**
 * @brief Checks a GPA validity, including the shared bit
 * @param gpa - GPA that will ne checked
 * @param gpaw - Value of the GPAW of the current TDCS
 * @param check_is_private - Flag to determine whether the GPA will be checked as private GPA
 *                           Use with PRIVATE_ONLY or PRIVATE_OR_SHARED defines.
 * @param virt_maxpa - virtual maxpa from the tdcs
 * @return true if the GPA is valid, otherwise false
 */
bool_t check_gpa_validity(pa_t gpa, bool_t gpaw, bool_t check_is_private, uint8_t virt_maxpa);

/**
 * @brief Checks a GPA to be valid, and GPA.SHARED bit == 0, translates it and returns requested
 *        EPT entry, and the reached walking level.
 *
 * @note Function takes an exclusive lock over SEPT (TDCS.SEPT_LOCK). Lock should be freed after
 *       the returned EPT entry is no longer used.
 *
 * @param tdcs_p - Linear pointer to the TDCS - used to get GPAW, SEPTP and acquire SEPT lock.
 * @param operand_id - Operand ID number
 * @param gpa - GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid - HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param lock_type - Type of lock to take on the SEPT root lock
 * @param sept_entry - Returns a linear pointer to the SEPT entry at the requested level.
 *                     Returns NULL if walk failed and didn't reach the requested level.
 *                     Should be freed after finishing using it (only on success).
 * @param level - Request walk level, at which the walking should stop. Returns a higher level if
 *                the walk failed from any reason and couldn't reach the requested level.
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 * @param is_sept_locked - A boolean flag indicating if the TDCS.SEPT_LOCK was exclusively taken.
 *
 * @return Error code that states the reason of failure
 */
api_error_type lock_sept_check_and_walk_private_gpa(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        lock_type_t lock_type,
        ia32e_sept_t** sept_entry,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry,
        bool_t* is_sept_locked,
        bool_t set_d_bit);


/**
 * @brief Same as lock_sept_check_and_walk_private_gpa, but walks until reaches any leaf,
 *        instead of specific requested level.
 *
 * @param level - Doesn't receives a request walk level. Returns the reached leaf entry level,
 *                or any higher level if the walk failed from any reason.
 *
 */
api_error_type check_and_walk_private_gpa_to_leaf(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        ia32e_sept_t** sept_entry_ptr,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry
        );

/**
 * @brief Return true if gpa_page_info is a legal and aligned GPA.
 *        - Reserved bits are 0
 *        - Level is between specified minimum and maximum
 *        - Aligned to 1 << 12 + 9 * 'level'
 * @param gpa_page_info - Input page_info_api_input_t structure that will be checkd
 * @param min_level - Minimal allowed level for the gpa_page_info
 * @param max_level - Maximum allowed level for the gpa_page_info
 *
 * @return true or false
 */
bool_t verify_page_info_input(page_info_api_input_t gpa_page_info, ept_level_t min_level, ept_level_t max_level);


/**
 * @brief Translates the GPA and returns requested EPT entry, and the reached walking level.
 *
 * @param tdcs_p - Linear pointer to the TDCS - used to get GPAW, SEPTP and acquire SEPT lock.
 * @param gpa - GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid - HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param sept_entry - Returns a linear pointer to the SEPT entry at the requested level.
 *                     Returns NULL if walk failed and didn't reach the requested level.
 *                     Should be freed after finishing using it (only on success).
 * @param level - Request walk level, at which the walking should stop. Returns a higher level if
 *                the walk failed from any reason and couldn't reach the requested level.
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 * @set_d_bit - mark the non-leaf entry as dirty if needed
 *
 * @return Error code that states the reason of failure
 */
api_error_type walk_private_gpa(
        tdcs_t* tdcs_p,
        pa_t gpa,
        uint16_t hkid,
        ia32e_sept_t** sept_entry,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry,
        bool_t set_d_bit);

/**
 * @brief Checks a GPA to be valid, if shared bit is 1, walks the shared EPT (taken from the TD VMCS)
 *        Else walk the SEPT and finally maps the translated GPA
 *
 * @param tdcs_p Linear pointer to the TDCS - used to get GPAW and SEPTP
 * @param tdvps_p Linear pointer to the TDVPS - used for #VE if required
 * @param gpa GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param mapping_type RW access to mapped linear address
 * @param check_gpa_is_private - if true, check that gpa is private. otherwise, it can be private or shared (don't care).
 * @param la Pointer to linear address mapped from translated GPA
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_walk_and_map_guest_side_gpa(
        tdcs_t* tdcs_p,
        tdvps_t* tdvps_p,
        pa_t gpa,
        uint16_t hkid,
        mapping_type_t mapping_type,
        bool_t check_gpa_is_private,
        void ** la
        );

/*
 * Implicit access semantics helpers:
 */

/**
 * @brief Lock an implicit TDR and map as a linear address in the TDX-SEAM module address space.
 *
 * @param tdr_pa - Physical address of the TDR page
 * @param operand_id - Operand ID number
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the PA
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param tdr_p      - Returns the linear pointer to the TDR page
 *
 * @return Error code that states the reason of failure
 */
api_error_type lock_and_map_implicit_tdr(
        pa_t tdr_pa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        tdr_t** tdr_p
        );

/**
 * @brief Map an implicit multi-page TDCS, as a single contiguous structure in the linear
 *        address space of the TDX-SEAM module.
 *        The function retrieves the physical addresses of the TDCS pages from the TDCS_PA
 *        array in the TDR page.
 *
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 * @param other_td - If the mapped TDCS belongs to "other TD" and not the current one
 *
 * @return Returns the linear pointer to the TDCS structure
 */
tdcs_t* map_implicit_tdcs(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        bool_t other_td
        );

/**
 * @brief This functions runs a partial prologue for SEAMCALL functions that run while the
 *        TD life cycle status is TD_KEYS_CONFIGURED.
 *
 *        1. Checks that the TD is not in FATAL state
 *        2. Check that the TDR.TD_LIFECYCLE state is TD_KEYS_CONFIGURED
 *        3. Check that the minimum required TDCS pages have been allocated
 *        4. Map the TDCS
 *        6. Check that the current SEAMCALL leaf is allowed in the current OP_STATE
 *
 *        OP_STATE lock should be unlocked at the end of the API if used with TDX_LOCK_SHARED or
 *        TDX_LOCK_EXCLUSIVE lock type, and TDX_SUCCESS was returned by this helper function.
 *
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 * @param op_state_lock_type - Locking type for the OP state, can be TDX_LOCK_NO_LOCK (when no lock required),
 *                             TDX_LOCK_SHARED or TDX_LOCK_EXCLUSIVE
 * @param map_migsc_links - Whether MIGSC links are required to be part of the mapped TDCS
 * @param current_leaf - Current SEAMCALL leaf that is being executed right now
 * @param tdcs_p - Returns the linear pointer to the mapped TDCS structure. NULL in case of any error.
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_state_map_tdcs_and_lock(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t op_state_lock_type,
        bool_t map_migsc_links,
        seamcall_leaf_opcode_t current_leaf,
        tdcs_t** tdcs_p
        );

/**
 * @brief Similar function to the check_state_map_tdcs_and_lock above, but used exclusively for SERV-TD
 *        related flows (guest and host-side). Intended to perform checks/locks on a TDCS that belongs
 *        to a different TD from the current that requests the checks.
 *
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 * @param op_state_lock_type - Locking type for the OP state, can be TDX_LOCK_NO_LOCK (when no lock required),
 *                             TDX_LOCK_SHARED or TDX_LOCK_EXCLUSIVE
 * @param map_migsc_links - Whether MIGSC links are required to be part of the mapped TDCS
 * @param current_leaf - Current SEAMCALL or TDCALL leaf that is being executed right now
 * @param guest_side_flow - Indicated that the function is invoked by guest-side (TDCALL) flow.
 * @param tdcs_p - Returns the linear pointer to the mapped TDCS structure. NULL in case of any error.
 *
 * @return Error code that states the reason of failure
 */
api_error_type othertd_check_state_map_tdcs_and_lock(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t op_state_lock_type,
        bool_t map_migsc_links,
        uint32_t current_leaf,
        bool_t guest_side_flow,
        tdcs_t** tdcs_p
        );

/**
 * @brief Map a multi-page TDVPS, composed of a TDVPR page and multiple TDCX pages, as a single
 *        contiguous structure in the linear address space of the TDX-SEAM module.
 *        The function works as follows:
 *        - Map the root TDVPR page
 *        - Check that the required number of TDCX pages have been allocated (NUM_TDCX != TDVPS_PAGES - 1)
 *          If not, return NULL.
 *        - Retrieve the physical addresses of the TDCX pages from the TDVPS_PAGE_PA
 *          array in the root page of TDVPS.
 *
 * @param tdvpr_pa - Physical address of the TDVPR page
 * @param hkid - TD ephemeral HKID
 * @param num_l2_vms - Number of currently deployed L2 VM for this TDVPS
 * @param mapping_type - If write access is required
 *
 * @return Returns the linear pointer to the TDVPS structure
 */
tdvps_t* map_tdvps(
        pa_t tdvpr_pa,
        uint16_t hkid,
        uint16_t num_l2_vms,
        mapping_type_t mapping_type
        );


uint8_t get_max_physical_address_space_bits(void);


/**
 * @brief Associate a VCPU with the current LP
 *
 * - Atomically check that the VCPU is not associated with another LP and
 *   associate it with the current LP
 * - Do VMPTRLD of TD VMCS.
 * - If newly associated, update all LP-dependent host state fields
 * - If HKID changed, update all physical address fields
 * Exit with an ERROR if the VCPU is already associated with another LP.
 *
 * @param tvps_ptr - Pointer to a checked, locked and mapped TDVPS
 * @param tdcs_ptr - Pointer to a mapped TDCS
 * @param allow_disabled - Flag that indicates if disabled VCPU needs to be associated
 * @param association_flag - Pointer to a flag to indicate if it is a new association
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e associate_vcpu(tdvps_t * tdvps_ptr,
                                tdcs_t * tdcs_ptr,
                                bool_t* new_association);

/**
 * @brief Associate a VCPU with the current LP
 *
 * - Check that the VCPU has been initialized and is not being torn down
 * - Atomically check that the VCPU is not associated with another LP and
 *   associate it with the current LP
 * - Do VMPTRLD of TD VMCS.
 * - If newly associated, update all LP-dependent host state fields
 * - If HKID changed, update all physical address fields
 * Exit with an ERROR if the VCPU is already associated with another LP.
 *
 * @param tvps_ptr - Pointer to a checked, locked and mapped TDVPS
 * @param tdcs_ptr - Pointer to a mapped TDCS
 * @param association_flag - Pointer to a flag to indicate if it is a new association
 * @param allow_disabled - Allow associating with a disabled VCPU
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_and_associate_vcpu(tdvps_t * tdvps_ptr,
                                          tdcs_t * tdcs_ptr,
                                          bool_t* new_association,
                                          bool_t allow_disabled);

/**
 * @brief Associate a VCPU with the current LP without checks
 *
 * Does exactly what associate_vcpu does, but without checks
 *
 * @param tvps_ptr - Pointer to a checked, locked and mapped TDVPS
 * @param tdcs_ptr - Pointer to a mapped TDCS
 *
 */
void associate_vcpu_initial(tdvps_t * tdvps_ptr,
                            tdcs_t * tdcs_ptr);

/**
 * @brief This function initialize TDVPS field
 *
 * @param tdcs_ptr  - Pointer to a TDCS
 * @param tdvps_ptr - Pointer to a checked, locked and mapped TDVPS
 *
 */
void init_tdvps_fields(tdcs_t * tdcs_ptr, tdvps_t * tdvps_ptr);

/**
 * @brief Set the SEAM VMCS as the active VMCS
 */
_STATIC_INLINE_ void set_seam_vmcs_as_active(void)
{
    // Set the SEAM VMCS as the current VMCS
    // SEAM VMCS addr: seamrr_base + page_size + (lp_id * page_size)
    uint64_t seam_vmcs_pa = get_global_data()->seamrr_base +
                            (TDX_PAGE_SIZE_IN_BYTES * (get_local_data()->lp_info.x2apic_id + 1));

    ia32_vmptrld((vmcs_ptr_t*)seam_vmcs_pa);

    get_local_data()->vp_ctx.active_vmcs = ACTIVE_VMCS_NONE;
}

uint64_t get_guest_cr0_pe(void);

/**
 * @brief Reinjects IDT vectoring event as VOE instead to the TD.
 *
 * @return False if no IDT vectoring event existed, and nothing was done.
 */
bool_t reinject_idt_vectoring_event_if_any(void);

/**
 * @brief Injects #UD exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_ud(void)
{
    if (get_local_data()->vp_ctx.tdvps->management.curr_vm != 0)
    {
        // Before we inject a #UD, reinject IDT vectoring events that happened during VM exit, if any.
        // #UD is lowest priority so just return if there's already an event being injected.
        if (reinject_idt_vectoring_event_if_any())
        {
            return;
        }
    }

    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);

    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, UD_INTERRUPTION_INFO);
}

/**
 * @brief Injects #GP exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_gp(uint32_t error_code)
{
    if (get_local_data()->vp_ctx.tdvps->management.curr_vm != 0)
    {
        // Before we inject a #GP, reinject IDT vectoring events that happened during VM exit, if any.
        if (reinject_idt_vectoring_event_if_any())
        {
            return;
        }
    }

    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);

    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, GP_INTERRUPTION_INFO | (get_guest_cr0_pe() << DELIVER_ERROR_CODE_OFFSET));
    ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, (uint64_t)error_code);
}

/**
 * @brief Injects #VE exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_ve(void)
{
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, VE_INTERRUPTION_INFO);
}

/**
 * @brief Injects #DF exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_df(void)
{
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, DF_INTERRUPTION_INFO | (get_guest_cr0_pe() << DELIVER_ERROR_CODE_OFFSET));
    ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, 0);
}

/**
 * @brief Injects #PF exception in the current active VMCS
 */
void inject_pf(uint64_t gla, pfec_t pfec);

/**
 * @brief Adds an instruction_len offset to Guest RIP of current active VMCS
 *
 * @param instruction_len - If 0 - instruction length will be take from VM-Exit Instruction Length VMCS field
 */
_STATIC_INLINE_ void current_vmcs_guest_rip_advance(uint64_t instruction_len)
{
    uint64_t current_vmm_rip;
    ia32_vmread(VMX_GUEST_RIP_ENCODE, &current_vmm_rip);

    if (instruction_len == 0)
    {
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &instruction_len);
        tdx_sanity_check(instruction_len != 0, FATAL_ERROR_ID_186, 1);
    }

    ia32_vmwrite(VMX_GUEST_RIP_ENCODE, current_vmm_rip + instruction_len);
}

_STATIC_INLINE_ void save_guest_td_extended_state(tdvps_t* tdvps_ptr, uint64_t xfam)
{
    // Set Guest XCR0 and XSS context for saving the state
    ia32_xsetbv(0, xfam & XCR0_USER_BIT_MASK);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, xfam & XCR0_SUPERVISOR_BIT_MASK);

    ia32_xsaves(&tdvps_ptr->guest_extension_state.xbuff, xfam);
}

_STATIC_INLINE_ ia32e_eptp_t get_l2_septp_with_hkid(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id)
{
    pa_t sept_root_hpa = { .raw = tdr_ptr->management_fields.tdcx_pa[get_tdcs_sept_root_page_index(vm_id)] };
    sept_root_hpa = set_hkid_to_pa(sept_root_hpa, tdr_ptr->key_management_fields.hkid);

    ia32e_eptp_t eptp = tdcs_ptr->executions_ctl_fields.eptp;
    eptp.fields.base_pa = sept_root_hpa.page_4k_num;

    return eptp;
}

_STATIC_INLINE_ ia32e_eptp_t get_l2_septp_without_hkid(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id)
{
    pa_t sept_root_hpa = { .raw = tdr_ptr->management_fields.tdcx_pa[get_tdcs_sept_root_page_index(vm_id)] };
    sept_root_hpa = remove_hkid_from_pa(sept_root_hpa);

    ia32e_eptp_t eptp = tdcs_ptr->executions_ctl_fields.eptp;
    eptp.fields.base_pa = sept_root_hpa.page_4k_num;

    return eptp;
}

_STATIC_INLINE_ void flush_td_asid(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id)
{
    ia32e_eptp_t eptp = get_l2_septp_without_hkid(tdr_ptr, tdcs_ptr, vm_id);

    ept_descriptor_t ept_desc = {.ept = eptp.raw, .reserved = 0};
    ia32_invept(&ept_desc, INVEPT_SINGLE_CONTEXT);
}

_STATIC_INLINE_ void flush_all_td_asids(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr)
{
    // Execute INVEPT type 1 for each Secure EPT
    for (uint16_t vm_id = 0; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        flush_td_asid(tdr_ptr, tdcs_ptr, vm_id);
    }
}

/**
 * @brief Atomically increments the REFCOUNT in TD Epoch, and flushes TD asids if required
 *
 * @param tdr_ptr
 * @param tdcs_ptr
 * @param tdvps_tr
 * @param new_association
 *
 * @return If the TD epoch lock acquisition succeeded or not
 */
bool_t adjust_tlb_tracking_state(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr,
                                 bool_t new_association);

/**
 * @brief Checks TLB tracking conditions
 *
 * @param tdcs_t Pointer to TDCS for reading TD's epoch value and refcount
 * @param bepoch The EPOCH value that needs to be checked if tracked
 */
_STATIC_INLINE_ bool_t is_tlb_tracked(tdcs_t * tdcs_ptr, bepoch_t bepoch)
{
    if (bepoch.mig_flag)
    {
        return false;
    }

    epoch_and_refcount_t epoch_and_refcount = {
            .raw = _lock_read_128b(&tdcs_ptr->epoch_tracking.epoch_and_refcount.raw)
                                              };

    if ((bepoch.raw == epoch_and_refcount.td_epoch - 1) &&
        (epoch_and_refcount.refcount[bepoch.raw & 1] == 0))
    {
        return true;
    }

    return (bepoch.raw < epoch_and_refcount.td_epoch - 1);
}

/**
 * @brief Decrement the TLB tracking state if was incremented earlier and need to be reverted
 * @param tdcs_ptr Pointer to TDCS for reading TD's epoch value and refcount
 */
_STATIC_INLINE_ void revert_tlb_tracking_state(tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr)
{
    tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;

    // Sample the TD epoch and atomically decrement the REFCOUNT
    (void)_lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[tdvps_ptr->management.vcpu_epoch & 1], (uint16_t)-1);
}

/**
 * @brief retrieve index in CPUID_LOOKUP matching input leaf_subleaf
 *
 * @param leaf
 * @param subleaf
 * @return the index if exist, otherwise -1
 */
uint32_t get_cpuid_lookup_entry(uint32_t leaf, uint32_t subleaf);

/**
 * @brief retrieve index in ORDERED_CPUID_LOOKUP matching input leaf_subleaf
 *
 * @param leaf
 * @param subleaf
 * @return the index if exist, otherwise -1
 */
uint32_t get_ordered_cpuid_lookup_entry(uint32_t leaf, uint32_t subleaf);


/**
 * @brief Return the current CPL of the guest TD
 * @return the current CPL of the guest TD
 */
uint32_t get_guest_td_cpl(void);


_STATIC_INLINE_ bool_t is_perfmon_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (bool_t)tdcs_ptr->executions_ctl_fields.attributes.perfmon;
}

_STATIC_INLINE_ bool_t is_cet_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return ((tdcs_ptr->executions_ctl_fields.xfam & (BIT(11))) |
            (tdcs_ptr->executions_ctl_fields.xfam & (BIT(12)))) ? true : false;
}

_STATIC_INLINE_ bool_t is_pt_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(8))) ? true : false;
}

_STATIC_INLINE_ bool_t is_uli_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(14))) ? true : false;
}

_STATIC_INLINE_ bool_t is_lbr_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(15))) ? true : false;
}

_STATIC_INLINE_ bool_t is_dca_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.dca_supported;
}
_STATIC_INLINE_ bool_t is_waitpkg_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported;
}
_STATIC_INLINE_ bool_t is_tme_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.tme_supported;
}
_STATIC_INLINE_ bool_t is_pconfig_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.pconfig_supported;
}
_STATIC_INLINE_ bool_t is_pks_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.attributes.pks;
}
_STATIC_INLINE_ bool_t is_xfd_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported;
}

_STATIC_INLINE_ bool_t is_tsc_deadline_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.tsc_deadline_supported;
}

_STATIC_INLINE_ bool_t is_tsx_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.tsx_supported;
}

_STATIC_INLINE_ bool_t is_perfmon_and_pebs_available_supported_in_tdcs (tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.attributes.perfmon &&
        !get_global_data()->plt_common_config.ia32_misc_enable.pebs_unavailable;
}

_STATIC_INLINE_ bool_t is_idt_vectoring_info_valid(void)
{
    vmx_idt_vectoring_info_t idt_vectoring_info;
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring_info.raw);

    return idt_vectoring_info.valid;
}


_STATIC_INLINE_ uint64_t get_gpa_alignment(const page_info_api_input_t gpa_mapping)
{
    return (1ULL) << (12 + (gpa_mapping.level * 9));
}

/**
 * @brief Virtual TSC Calculation
 * @param native_tsc     - Current time stamp counter value
 * @param tsc_multiplier - TSC multiplier VMCS field, in units of 2^-48
 * @param tsc_offset     - TSC offset VMCS field, in units of the virtual TSC
 *
 * @return Calculated virtual TSC
 */
uint64_t calculate_virt_tsc(uint64_t native_tsc, uint64_t tsc_multiplier, uint64_t tsc_offset);

/**
 * @brief CR write status enumeration for return value of the CR-writing helper function below
 */
typedef enum
{
    CR_ACCESS_SUCCESS,   // Access is successful
    CR_ACCESS_GP,        // #GP(0) should be injected if called from guest context
    CR_ACCESS_NON_ARCH,  // #VE should be injected (for L2, possibly L2->L1 exit) if called from guest context
    CR_L2_TO_L1_EXIT
} cr_write_status_e;

/**
 * @brief Checks the validity of input CR0 and writes it to the GUEST_CR0 TD-VMCS field
 *        This function is used when handling CR0 writes from the Guest-TD side
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR0
 * @param allow_pe_disable
 *
 * @return Success status or a #GP/#VE indicator
 */
uint16_t write_guest_cr0(uint64_t value, bool_t allow_pe_disable);

/**
 * @brief Check if CR4 value is allowed by current TD attributes
 *
 * @param cr4
 * @param tdcs_p
 * @param xfam
 *
 * @return true or false
 */
bool_t is_guest_cr4_allowed_by_td_config(ia32_cr4_t cr4, tdcs_t* tdcs_p, ia32_xcr0_t xfam);

/**
 * @brief Checks the validity of input CR4 and writes it to the GUEST_CR4 TD-VMCS field
 *        This function is used when handling CR4 writes from the Guest-TD side
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR4
 * @param tdcs_p - current TDCS
 *
 * @return Success status or a #GP/#VE indicator
 */
cr_write_status_e write_guest_cr4(uint64_t value, tdcs_t* tdcs_p
    , tdvps_t* tdvps_p
    );

/**
 * @brief Checks the validity the TD attributes that will be set in the TDCS
 *
 * @param attributes to be checked
 *
 * @param is_import specifies whether the function was called during import flow
 *
 * @return true of false
 */
bool_t verify_td_attributes(td_param_attributes_t attributes, bool_t is_import);

/**
 * @brief Checks the validity of the TD config flags that will be set in the TDCS
 *
 * @param flags to be checked
 *
 * @return true of false
 */
bool_t verify_td_config_flags(config_flags_t config_flags);

/**
 * @brief Checks the validity the XFAM that will be set in the TDCS
 * @param xfam to be checked
 *
 * @return true of false
 */
bool_t check_xfam(ia32_xcr0_t xfam);

/**
 * @brief Checks the validity the XCR0 that will be set in the TDVPS
 * @param xcr0 to be checked
 * @param xfam current xfam to be used for xcr0 checks
 *
 * @return true or false
 */
bool_t check_guest_xcr0_value(ia32_xcr0_t xcr0, uint64_t xfam);

/**
 * @brief Checks the validity the EPTP control bits and sets it in the TDCS
 * @param tdr_ptr TDR
 * @param tdcs_ptr TDCS
 * @param gpaw mew gpaw value
 * @param eptp to be checked
 *
 * @return true of false
 */
bool_t verify_and_set_td_eptp_controls(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, bool_t gpaw, ia32e_eptp_t eptp);

/**
 * @brief Calculates the virtual TSC params for the TD
 * @param tsc                - Current time stamp counter value
 * @param native_tsc_freq    - Calculated from CPUID(0x15), in 1Hz units
 * @param virt_tsc_frequency - Virtual TSC frequency, in VIRT_TSC_FREQUENCY_UNIT (25MHz) units
 * @param virt_tsc           - Initial virtual TSC value
 * @param tsc_multiplier     - Pointer to output - TSC multiplier VMCS field, in units of 2^-48
 * @param tsc_offset         - Pointer to output - TSC offset VMCS field, in units of the virtual TSC
 *
 * @return tsc_multiplier and tsc_offset
 */
void calculate_tsc_virt_params(uint64_t tsc, uint64_t native_tsc_freq, uint16_t virt_tsc_frequency,
                               uint64_t virt_tsc, uint64_t* tsc_multiplier, uint64_t* tsc_offset);

/**
 * @brief Convert time value in virtual crystal clock units to/from time value is real crystal clock units
 *
 * @param crystal_clock - time value in virtual crystal clock units
 *
 * @return time value is real crystal clock units
 */
_STATIC_INLINE_ uint32_t crystal_clock_virt_to_real(uint32_t crystal_clock)
{
    /* Calculation is done in 64-bit to avoid overflow.
     * The order of calculation is important to avoid underflow.
     */
    return (uint32_t)((uint64_t)crystal_clock * (get_global_data()->crystal_clock_frequency)) / (uint64_t)VIRT_CRYSTAL_CLOCK_FREQUENCY;
}

/**
 * @brief The function supports sending INIT and NMI. Thus it can't use the self-IPI shorthand
 * and must use the actual APIC ID as the destination.
 * The function supports x2APIC and xAPIC modes. The caller must have checked that if
 * the maximum value of local APIC ID on the platform is higher than 255, the local APIC
 * mode is x2APIC.
 *
 * @param apic_base
 * @param delivery_mode
 * @param vector
 */
void send_self_ipi(apic_delivery_mode_t delivery_mode, uint32_t vector);

#define RDRAND_RETRIES_LIMIT 10

/**
 * @brief Have RETRY_LIMIT rertries to get a 64 bit random number
 *
 * @return True if succeeded, false otherwise
 */
bool_t get_random_64b(uint64_t* rand);

/**
 * @brief Helper functions that establish if a SEAMCALL allowed or specific operation required
 *        for a given TD Operation State
 */
_STATIC_INLINE_ bool_t op_state_is_tlb_tracking_required(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].tlb_tracking_required;
}

_STATIC_INLINE_ bool_t op_state_is_any_initialized(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].any_initialized;
}

_STATIC_INLINE_ bool_t op_state_is_any_finalized(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].any_finalized;
}

_STATIC_INLINE_ bool_t op_state_is_export_in_order(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].export_in_order;
}

_STATIC_INLINE_ bool_t op_state_is_export_in_progress(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].export_in_progress;
}

_STATIC_INLINE_ bool_t op_state_is_import_in_order(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].import_in_order;
}

_STATIC_INLINE_ bool_t op_state_is_import_in_progress(op_state_e op_state)
{
    tdx_debug_assert(op_state < NUM_OP_STATES);
    return state_flags_lookup[op_state].import_in_progress;
}


_STATIC_INLINE_ bool_t op_state_is_seamcall_allowed(seamcall_leaf_opcode_t current_leaf,
                                                    op_state_e op_state, bool_t other_td)
{
    tdx_debug_assert(op_state < NUM_OP_STATES && (uint64_t)current_leaf < MAX_SEAMCALL_LEAF);

    bool_t is_allowed = false;

    IF_RARE (other_td)
    {
        is_allowed = othertd_state_lookup[current_leaf][op_state];
    }
    else
    {
        is_allowed = seamcall_state_lookup[current_leaf][op_state];
    }

    return is_allowed;
}

_STATIC_INLINE_ bool_t op_state_is_tdcall_allowed(tdcall_leaf_opcode_t current_leaf,
                                                  op_state_e op_state, bool_t other_td)
{
    tdx_debug_assert(op_state < NUM_OP_STATES && (uint64_t)current_leaf < MAX_TDCALL_LEAF);

    bool_t is_allowed = false;

    IF_COMMON (other_td)
    {
        is_allowed = tdcall_state_lookup[current_leaf][op_state];
    }
    else
    {
        // Not supported yet
        fatal_error(FATAL_ERROR_ID_40, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    return is_allowed;
}

/**
 * @brief Helper routines for MSR bitmap handling
 */
typedef enum
{
    MSR_BITMAP_FIXED_0,
    MSR_BITMAP_FIXED_1,
    MSR_BITMAP_DYN_PERFMON,
    MSR_BITMAP_DYN_XFAM_CET,
    MSR_BITMAP_DYN_XFAM_PT,
    MSR_BITMAP_DYN_XFAM_ULI,
    MSR_BITMAP_DYN_XFAM_LBR,
    MSR_BITMAP_DYN_UMWAIT,
    MSR_BITMAP_DYN_XFD,
    MSR_BITMAP_DYN_PKS,
    MSR_BITMAP_DYN_TSX,
    MSR_BITMAP_PERFMON_AND_LEGACY_PEBS,
    MSR_BITMAP_DYN_OTHER
} msr_bitmap_bit_type;

typedef enum
{
    MSR_ACTION_VE,
    MSR_ACTION_GP,
    MSR_ACTION_GP_OR_VE,
    MSR_ACTION_GP_OR_VE_BY_REDUCED_VE,
    MSR_ACTION_GP_OR_VE_BY_EST,
    MSR_ACTION_GP_OR_VE_BY_TM2,
    MSR_ACTION_GP_OR_VE_BY_DCA,
    MSR_ACTION_GP_OR_VE_BY_TSC_DEADLINE,
    MSR_ACTION_GP_OR_VE_BY_MTRR,
    MSR_ACTION_GP_OR_VE_BY_MCA,
    MSR_ACTION_GP_OR_VE_BY_ACPI,
    MSR_ACTION_GP_OR_VE_BY_RDT_M,
    MSR_ACTION_GP_OR_VE_BY_RDT_A,
    MSR_ACTION_GP_OR_VE_BY_TME,
    MSR_ACTION_GP_OR_VE_BY_PCONFIG,
    MSR_ACTION_GP_OR_VE_BY_CORE_CAPABILITIES,
    MSR_ACTION_FATAL_ERROR,
    MSR_ACTION_OTHER,
} msr_bitmap_action;

bool_t is_msr_dynamic_bit_cleared(tdcs_t* tdcs_ptr, uint32_t msr_addr, msr_bitmap_bit_type bit_meaning);

void set_msr_bitmaps(tdcs_t * tdcs_ptr);

/**
 * @brief Fills the xbuff_offsets and xbuff_size values in the given TDCS,
 *        based on the given xfam
 *
 * @param tdcs_ptr - TDCS pointer
 * @param xfam     - XFAM mask on which the filled values will be based
 */
void set_xbuff_offsets_and_size(tdcs_t* tdcs_ptr, uint64_t xfam);

/**
 * init_imported_td_state_mutable /
 * Initialize TD-scope metadata.
 * For mutable state import:
 *   - Initialize fields marked as "IE" in the TDR/TDCS spreadsheet.
 *   - Update mutable fields that are calculated based on imported fields.
 *
 * @param tdcs_ptr - pointer to tdcs
 */
void init_imported_td_state_mutable (tdcs_t * tdcs_ptr);

/**
 * @brief Cross-check TD-scope immutable state for correctness
 *        Called at the end of TD init or end of TD metadata import
 * @param tdcs_ptr
 * @param is_import
 * @return
 */
api_error_type td_immutable_state_cross_check(tdcs_t* tdcs_ptr, bool_t is_import);

/**
 * init_imported_td_state_immutable /
 * Initialize TD-scope metadata.
 * For immutable state import:
 *   - Initialize fields marked as "IB" and "IBS" in the TDR/TDCS spreadsheet.
 *   - "IBS" initialization is the same as done by TDH.MNG.INIT using set_msr_bitmaps.
 *
 * @param tdcs_ptr - pointer to tdcs
 */
api_error_type check_and_init_imported_td_state_immutable (tdcs_t * tdcs_ptr);

/**
 * check_imported_vp_state /
 * Check and validate imported vp state.
 *
 * @param tdr_p - pointer to tdr
 * @param tdcs_p - pointer to tdcs
 * @param tdvps_p - pointer to tdvps
 */
api_error_type check_imported_vp_state(tdr_t* tdr_p, tdcs_t* tdcs_p, tdvps_t* tdvps_p);

/**
 * @brief Initialize the TD VMCS version identifier and execute VMCLEAR
 * @param tdvps_p - pointer to tdvps struct
 * @param vm_id - requested VM to prepare its VMCS
 */
void prepare_td_vmcs(tdvps_t *tdvps_p, uint16_t vm_id);

/**
 * @brief Calculate TDINFO_STRUCT and its SHA384 hash
 *        The function acquires shared lock to the RTMRs and releases it before it returns
 * @param tdcs_p - pointer to the current TDCS
 * @param ignore_tdinfo - bitmap where each set bit indicates a field to be ignored for TDINFO
 * @param td_info - pointer to the returned TD INFO. Can be NULL, so the function will return only the hash.
 * @param tee_info_hash - pointer to the return TEEINFOHASH
 * @param is_guest - if called from guest-side API
 * @param tdr_p - pointer to the current TDR
 * @param vmid - VMID to be used in TDINFO_STRUCT
 * @param calc_servtd - if true, calculate SERVTD fields in TDINFO_STRUCT
 * @param report_type - type of report
 * @return
 */
api_error_code_e get_tdinfo_and_teeinfohash(tdcs_t* tdcs_p, ignore_tdinfo_bitmap_t ignore_tdinfo, td_info_t* td_info,
                                            measurement_t* tee_info_hash, bool_t is_guest, tdr_t* tdr_p, uint8_t vmid,
                                            bool_t calc_servtd, uint8_t report_type);

/**
 * @brief Calculate TDINFO_STRUCT SHA384 hash
 *
 * @param tdcs_p - pointer to the current TDCS
 * @param ignore_tdinfo - bitmap where each set bit indicates a field to be ignored for TDINFO
 * @param tee_info_hash - pointer to the return TEEINFOHASH
 * @return
 */
api_error_code_e get_teeinfohash(tdcs_t* tdcs_p, ignore_tdinfo_bitmap_t ignore_tdinfo,
                                 measurement_t* tee_info_hash);

/* Abort an import session.
 * Set the TD's OP_STATE to FAILED_IMPORT or to RUNNABLE as appropriate.
 * Calculate and return the appropriate error code.
*/
api_error_type abort_import_session(
    tdcs_t                  *tdcs_p,
    api_error_type           status,
    uint32_t                 status_details);
/**
 * @brief Generates as 256-bit random value by using RDSEED x86 instruction
 * @param rand - Pointer to output random 256-bit value\
 *
 * @return If the generation suceeded or not
 */
bool_t generate_256bit_random(uint256_t* rand);

/**
 * @brief Generates a custom-sized random value by using RDSEED x86 instruction
 * @param rand_array - Pointer to output random custom-sized value
 * @param num_of_qwords - Number of quadwords to generate
 *
 * @return If the generation suceeded or not
 */
bool_t generate_custom_random(uint64_t* rand_array, uint64_t num_of_qwords);

/*------------------------------------------------------------------------------
                 Optimized DR and MSR Write and Init Helpers
-------------------------------------------------------------------------------*/
/**
 * @brief Write 'value' to MSR 'index' if value != cur_value
 *
 * @param addr - MSR address
 * @param new_value - The new value that should be written to the MSR
 * @param cur_value - MSR current value
 */
_STATIC_INLINE_ void wrmsr_opt(uint64_t addr, uint64_t new_value, uint64_t cur_value)
{
    if (new_value != cur_value)
    {
        ia32_wrmsr(addr, new_value);
    }
}

/**
 * @brief Initialized extended states defined in XFAM to their reset values
 *        by invoking XRSTORS
 *
 * @param xfam - XFAM mask that indicate which states will be initialized
 */
void initialize_extended_state(uint64_t xfam);

/**
 * @brief Sets guest PDE.BS bit according to the current state of single-step
 *        trap in RFLAGS and IA32_DEBUGCTL
 */
void set_guest_pde_bs(void);

/**
 * @brief Only this function should be used when guest RIP is advanced to the next instruction,
 *        and clear STI blocking and MOVSS blocking interruptibility state.
 */
void advance_guest_rip(void);

/**
 * @brief This function increments fixed_ctr0 in case perfmon in disabled.
 *
 * @param tdcs_p - tdcs pointer
 */
void increment_fixed_ctr0(tdcs_t* tdcs_p);

/**
 * @brief Terminate MOVSS-blocking and STI blocking.
 */
void clear_movss_sti_blocking(void);

/**
 * @brief Check the memory encryption algorithm configuration based on MCHECK input.
 *
 * @param tme_capability - IA32_TME_CAPABILITY MSR value
 * @param tme_activate - IA32_TME_ACTIVATE MSR value
 *
 * @return O if no error, offending MSR address if error
 */
uint32_t check_mem_enc_alg(ia32_tme_capability_t tme_capability, ia32_tme_activate_t tme_activate);

/**
 * @brief Check that TD is in build phase
 *
 * Check for TDR fatal, init and keys state
 *
 * @param tdr_p - Pointer the checked, locked and mapped TDR
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_td_in_correct_build_state(tdr_t *tdr_p);

_STATIC_INLINE_ uint64_t translate_usec_to_tsc(uint32_t time_usec, uint32_t  tsc_frequency)
{
    /* Calculation is done in 64-bit to avoid overflow.
       The order of calculation is important to avoid underflow. */
    uint64_t tsc = ((uint64_t)time_usec * (uint64_t)tsc_frequency) / 1000000ULL;
    return tsc;
}

/**
 * @brief Complete Global data CPUID_VALUES table calculation
 * @param tdx_global_data_ptr
 */
void complete_cpuid_handling(tdx_module_global_t* tdx_global_data_ptr);

/**
 * @brief Check if a Vector-On-Entry (VOE) is being injected, and if so, if it matches the
 *        VMCS' exception bitmap and #PF filtering.
 *
 * @return True or false
 */
bool_t is_voe_in_exception_bitmap( void );


_STATIC_INLINE_ void reset_to_next_iv(migsc_t *migsc, uint64_t iv_counter, uint16_t migs_index)
{
    migs_iv_t iv;

    // Prepare the IV
    iv.iv_counter = iv_counter;
    iv.migs_index = migs_index;
    iv.reserved = 0;

    // Refresh the context
    if (aes_gcm_refresh_context(&migsc->aes_gcm_context) != AES_GCM_NO_ERROR)
    {
        fatal_error(FATAL_ERROR_ID_41, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    // Calculate the MAC
    if (aes_gcm_reset(&migsc->aes_gcm_context, &iv) != AES_GCM_NO_ERROR)
    {
        fatal_error(FATAL_ERROR_ID_42, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
}

typedef struct PACKED servtd_hash_buff_s
{
    measurement_t       info_hash;
    uint16_t            type;
    servtd_attributes_t attrib;
} servtd_hash_buff_t;
tdx_static_assert(sizeof(servtd_hash_buff_t) == 58, servtd_hash_buff_t);


/* Prepare the temporary buffer for SERVTD_HASH calculation.
   1. Get all service TD binding slots whose SERVTD_BINDING_STATE is not NOT_BOUND.
      If no service TD binding slots apply, return 0.
   2. Sort in ascending order by SERVTD_TYPE as the primary key, SERVTD_INFO_HASH a
      s a secondary key (if multiple service TDs of the same type are bound).
   3. Copy SERVTD_INFO_HASH, SERVTD_TYPE and SERVTD_ATTR of each slot into a
      servtd_has_buff entry.
   4. Return the actual number of entries. */
uint32_t prepare_servtd_hash_buff(tdcs_t* tdcs_ptr, servtd_hash_buff_t* servtd_has_buf);
void calculate_servtd_hash(tdcs_t* tdcs_ptr);


// Update TDCS.CPUID_FLAGS based on TD_CTLS.REDUCE_VE and FEATURE_PARAVIRT_CTLS
// This helper is used on write by the guest TD and at the end of mutable TD state import
void update_mutable_cpuid_flags(tdcs_t* tdcs_p);

// Check the imported CPUID_FIXED0_BITMAP.  Each bit that is set to 1 must pass one of the two conditions:
// The same bit in FIXED0_BITMAP of the local lookup table is 0, or
// The applicable leaf is in the local lookup table, and all its sub-leaves virtual values in TDCS are 0.
bool_t check_imported_cpuid_fixed0_bitmap(tdcs_t* tdcs_p);

_STATIC_INLINE_ bool_t is_td_guest_in_64b_mode(void)
{
    ia32_efer_t ia32_efer;
    uint64_t cs_ar_vmread;
    seg_arbyte_t cs_ar;

    ia32_vmread(VMX_GUEST_IA32_EFER_FULL_ENCODE, &ia32_efer.raw);
    ia32_vmread(VMX_GUEST_CS_ARBYTE_ENCODE, &cs_ar_vmread);
    cs_ar.raw = (uint32_t)cs_ar_vmread;

    if ((ia32_efer.lma != 1) || (cs_ar.l != 1))
    {
        //Not in CPU 64b mode
        return false;
    }

    return true;
}

_STATIC_INLINE_ void set_guest_inter_blocking_by_nmi()
{
    vmx_guest_inter_state_t guest_inter_state;

    ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
    guest_inter_state.blocking_by_nmi = 1;
    ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
}

/**
 * @brief Set the given VM id VMCS as the active VMCS
 *        Optimized to check if the given VM VMCS is already active
 */
_STATIC_INLINE_ void set_vm_vmcs_as_active(tdvps_t* tdvps_p, uint16_t vm_id)
{
    if (get_local_data()->vp_ctx.active_vmcs != vm_id)
    {
        uint64_t vm_vmcs_pa = tdvps_p->management.tdvps_page_pa[get_tdvps_vmcs_page_index(vm_id)];

        ia32_vmptrld((vmcs_ptr_t*)vm_vmcs_pa);
        get_local_data()->vp_ctx.active_vmcs = vm_id;
    }
}

/**
 * @brief Clear the flags indicating that LP-dependent host state fields are up-to-date
 */
_STATIC_INLINE_ void clear_lp_host_state_flags(tdvps_t* tdvps_p)
{
    // Mark all VMs' VMCSes as needing host state HPA updates to match the new LP
    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        tdvps_p->management.lp_dependent_hpa_updated[vm_id] = false;
    }
}

/**
 * @brief Clear the flags indicating that module-dependent host state fields are up-to-date
 */
_STATIC_INLINE_ void clear_module_host_state_flags(tdvps_t* tdvps_p)
{
    // Mark all VMs' VMCSes as needing host state HPA updates to match the new LP
    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        tdvps_p->management.module_dependent_fields_updated[vm_id] = false;
    }
}

/**
 * @brief Updates the Module/LP-dependant host state in a given VMCS
 *        Optimized to check if the given VM VMCS requires an updated state
 */
_STATIC_INLINE_ void update_host_state_in_td_vmcs(tdx_module_local_t* ld_p, tdvps_t* tdvps_p, uint16_t vm_id)
{
    if (!tdvps_p->management.module_dependent_fields_updated[vm_id])
    {
        // TDX module has been updated, need to update host state fields.
        // This also updates LP-dependent host state fields.
        init_module_host_state_in_td_vmcs();

        tdvps_p->management.module_dependent_fields_updated[vm_id] = true;
        tdvps_p->management.lp_dependent_hpa_updated[vm_id] = true;
    }
    else if (!tdvps_p->management.lp_dependent_hpa_updated[vm_id])
    {
        init_module_lp_host_state_in_td_vmcs(ld_p);

        tdvps_p->management.lp_dependent_hpa_updated[vm_id] = true;
    }
}

/**
 * @brief If a pending VOE for L2 VM exists, it will be converted to injected exit to L1
 *        with VMEXIT_REASON_EXCEPTION_OR_NMI exit reason, and details from the L2 VOE
 */
void convert_l2_voe_to_l1_exit(void);

/**
 * @brief Configures and enables VMX preemption timer for a given vm_id
 *
 * @param tdvps_p
 * @param vm_id
 */
void set_vmx_preemption_timer(tdvps_t* tdvps_p, uint16_t vm_id);


/**
 * @brief Translate the TDG.VP.ENTER guest state buffer GPA before L2 VM entry
 *
 * @param tdr_p - inear pointer to TDR
 * @param tdcs_p - inear pointer to TDCS
 * @param tdvps_p - inear pointer to TDVPS
 * @param vm_id
 * @param failed_gpa - output, Failed GPA
 *
 * @return If the translation suceeded or not
 */
bool_t translate_l2_enter_guest_state_gpa(
    tdr_t *    tdr_ptr,
    tdcs_t *   tdcs_ptr,
    tdvps_t *  tdvps_ptr,
    uint16_t   vm_id,
    uint64_t * failed_gpa);

/**
 * @brief Translate soft-translated GPAs before L2 VM entry
 *
 * @param tdr_p - inear pointer to TDR
 * @param tdcs_p - inear pointer to TDCS
 * @param tdvps_p - inear pointer to TDVPS
 * @param vm_id
 * @param failed_gpa - output, Failed GPA
 *
 * @return If the translation suceeded or not
 */
bool_t translate_gpas(
    tdr_t *    tdr_ptr,
    tdcs_t *   tdcs_ptr,
    tdvps_t *  tdvps_ptr,
    uint16_t   vm_id,
    uint64_t * failed_gpa);

/**
 * @brief Calculate the actual write mask for CR4 based on the TD configuration
 *
 * @param attributes
 * @param xfam
 * @return
 */
_STATIC_INLINE_ ia32_cr4_t calc_base_l2_cr4_write_mask(tdcs_t* tdcs_ptr)
{
    td_param_attributes_t attributes = tdcs_ptr->executions_ctl_fields.attributes;
    ia32_xcr0_t xfam = { .raw = tdcs_ptr->executions_ctl_fields.xfam };

    ia32_cr4_t mask;

    // Start with the write mask value as defined in the L2 VMCS spreadsheet
    mask.raw = CR4_L1_VMM_WRITE_MASK;

    // Apply the CPU capabilities:
    // - Any bit set to 1 in IA32_VMX_CR4_FIXED0 must be fixed-1 in CR4, therefore this bit must be 0 in the write mask
    // - Any bit set to 0 in IA32_VMX_CR4_FIXED1 must be fixed-0 in CR4, therefore this bit must be 0 in the write mask

    uint64_t ia32_vmx_cr4_fixed0 = get_global_data()->plt_common_config.ia32_vmx_cr4_fixed0.raw;
    uint64_t ia32_vmx_cr4_fixed1 = get_global_data()->plt_common_config.ia32_vmx_cr4_fixed1.raw;

    mask.raw &= ~ia32_vmx_cr4_fixed0;
    mask.raw &= ia32_vmx_cr4_fixed1;

    // Check if bits for features that are not enabled by XFAM are set
    if (!xfam.pk)
    {
        mask.pke = 0;
    }

    if (!xfam.cet_s || !xfam.cet_u)
    {
        mask.cet = 0;
    }

    if (!xfam.uli)
    {
        mask.uintr = 0;
    }

    // Check if bits for features that are not enabled by ATTRIBUTES are set
    mask.keylocker = 0;

    if (!attributes.pks)
    {
        mask.pks = 0;
    }

    if (!attributes.lass)
    {
        mask.lass = 0;
    }

    return mask;
}

/**
 * @brief Invalidate all soft-translated GPAs of a VM by setting their HPA fields to NULL_PA
 *
 * @param tdvps_p - linear pointer to TDVPS
 * @param vm_id
 */
void invalidate_gpa_translations(tdvps_t *tdvps_p, uint16_t vm_id);

/**
 * @brief Invalidate all soft-translated GPAs of all L1+L2 VM's by setting their HPA fields to NULL_PA
 *
 * @param tdcs_p  - linear pointer to TDCS
 * @param tdvps_p - linear pointer to TDVPS
 */
void invalidate_all_gpa_translations(tdcs_t* tdcs_p, tdvps_t* tdvps_p);

/**
 * @brief VMCLEAR a specific VM's VMCS, and mark the guest-TD as not launched
 *
 * @param tdvps_p - linear pointer to TDVPS
 * @param vm_id
 */
void vmclear_vmcs(tdvps_t *tdvps_p, uint16_t vm_id);

/**
 * @brief L2 SEPT walk initiated in the host context
 *
 * @param tdr_ptr - TDR pointer
 * @param tdcs_ptr - TDCS pointer
 * @param vm_id - on which L2 VM SEPT the walk will done
 * @param page_gpa - GPA to walk
 * @param level - Requested level that should be reached
 * @param l2_septe_ptr - Return the pointer to the SEPT entry. Should be freed even on failure.
 *
 * @return Error code that states the reason of failure
 */
api_error_type l2_sept_walk(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id, pa_t page_gpa,
                            ept_level_t* level, ia32e_sept_t** l2_septe_ptr);

/**
 * @brief L2 SEPT walk initiated in the guest context:
            - Assumes the L1 SEPT entry has been locked and read, and it's not blocked
            - Allows non-leaf L2_NL_BLOCKED entries - continues the walk
 *
 * @param tdr_ptr - TDR pointer
 * @param tdcs_ptr - TDCS pointer
 * @param vm_id - on which L2 VM SEPT the walk will done
 * @param page_gpa - GPA to walk
 * @param level - Requested level that should be reached
 * @param cached_l2_sept_entry - Cached SEPT entry - on walk failure will contain the last reached entry
 * @param l2_septe_ptr - Return the pointer to the SEPT entry. Should be freed after usage.
 *                       Will be set to NULL in case of walk failure (request level not reached)
 *
 * @return Error code that states the reason of failure
 */
api_error_type l2_sept_walk_guest_side(
    tdr_t* tdr_ptr,
    tdcs_t* tdcs_ptr,
    uint16_t vm_id,
    pa_t page_gpa,
    ept_level_t* level,
    ia32e_sept_t* cached_l2_sept_entry,
    ia32e_sept_t **l2_septe_ptr);

/**
 * @brief Check if the attributes are legal:
 *          - If VALID is 0, all other bits must be 0
 *          - Reserved bits must be 0
 *          - If bit W is 1, bit R must be 1
 *          - If bit PWA is 1, bit R must be 1
 *          - Bit SVE must be 0
 *          - If is_mmio is set - Bits Xs, Xu, VGP, PWA, SSS must be 0
 *
 * @param gpa_attr
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t is_gpa_attr_legal(const gpa_attr_single_vm_t gpa_attr_single_vm
)
{
    if ((!gpa_attr_single_vm.valid && gpa_attr_single_vm.raw) ||
         gpa_attr_single_vm.reserved_14_8 ||
        (gpa_attr_single_vm.w && (!gpa_attr_single_vm.r)) ||
        (gpa_attr_single_vm.pwa && (!gpa_attr_single_vm.r)) ||
         gpa_attr_single_vm.sve
        )
    {
        TDX_ERROR("Illegal attributes - 0x%llx\n", gpa_attr_single_vm.raw)
        return false;
    }

    return true;
}

_STATIC_INLINE_ bool_t is_gpa_attr_present(const gpa_attr_single_vm_t gpa_attr_single_vm)
{
    return gpa_attr_single_vm.r ||
           gpa_attr_single_vm.w ||
           gpa_attr_single_vm.xs ||
           gpa_attr_single_vm.xu;
}

_STATIC_INLINE_ bool_t is_interrupt_pending_host_side(void)
{
    ia32_rflags_t vmm_rflags;
    ia32_msr_intr_pending_t intr_pending;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &vmm_rflags.raw);
    intr_pending.raw = ia32_rdmsr(IA32_INTR_PENDING_MSR_ADDR);

    intr_pending.intr &= vmm_rflags.ief;

    return (intr_pending.raw != 0);
}

_STATIC_INLINE_ bool_t is_interrupt_pending_guest_side(void)
{
    return (ia32_rdmsr(IA32_INTR_PENDING_MSR_ADDR) != 0);
}

#define NUM_OF_BHB_CLEARING_ITERATIONS 32 // 194 branch stews in BHB, NUM_ITERS = round-up(194 / 6) = 32

_STATIC_INLINE_ void bhb_drain_sequence(tdx_module_global_t* tdx_global_data_ptr)
{
    // Execute the BHB defense sequence
    if (tdx_global_data_ptr->rtm_supported)
    {
        // TSX abort sequence
        _ASM_VOLATILE_ (
            "xbegin AbortTarget\n"
            "xabort $0\n"
            "lfence\n"
            "AbortTarget: nop\n"
            : : : "eax", "memory", "cc");
    }
    else
    {
        // BHB draining sequence
        // There are 6 taken branches in each iteration (one CALL, four JMPs, and one JNZ),
        // so for GLC (194 branch stews in BHB), NUM_ITERS = round-up(194 / 6) = 32.
        uint64_t num_iters = NUM_OF_BHB_CLEARING_ITERATIONS;
        uint64_t num_iters_multi_8 = 8*num_iters;

        _ASM_VOLATILE_ (
            "movq %0, %%rcx\n"
            "1:  call 2f\n"
            "lfence\n"
            "2:  jmp 3f\n"
            "nop\n"
            "3:  jmp 4f\n"
            "nop\n"
            "4:  jmp 5f\n"
            "nop\n"
            "5:  jmp 6f\n"
            "nop\n"
            "6:  dec %%rcx\n"
            "jnz 1b\n"
            "add %1, %%rsp\n"
            "lfence\n"
            : : "a"(num_iters), "b"(num_iters_multi_8) : "memory", "rcx");
    }
}

/**
 * @brief Check the virtual CPUID(0x1F) configuration and set virtual CPUID(0xB)
 *
 * @param tdcs_p - TDCS pointer
 * @param allow_null - Allow all-0 configuration of CPUID(0x1F), indicating usage of h/w values
 */
api_error_type check_cpuid_1f_and_compute_cpuid_0b(tdcs_t* tdcs_p, bool_t allow_null);

/* Check a virtual MAXPA value for validity:
   - Must not be higher than the native MAXPA (in PL.MAXPA)
   - Must not be lower than the MIN_VIRT_MAXPA
   Note that we allow virt_max_pa to be higher than GPAW, to support import from older TDX
   modules which didn't virtualize MAXPA.
*/
_STATIC_INLINE_ bool_t is_virt_maxpa_on_import_valid(uint32_t virt_maxpa)
{
    return ((virt_maxpa <= get_global_data()->max_pa) && (virt_maxpa >= MIN_VIRT_MAXPA));
}

/* Check a virtual MAXPA value for validity:
   - Must not be higher than the native MAXPA (in global_data.max_pa)
   - Must not be higher than GPAW (note that GPA is boolean, meaning false: 48, true: 52)
   - Must not be lower than the MIN_VIRT_MAXPA
*/
_STATIC_INLINE_ bool_t is_virt_maxpa_valid(bool_t gpaw, uint32_t virt_maxpa)
{
    return ((virt_maxpa <= (uint32_t)(gpaw ? MAX_PA : MAX_PA_FOR_GPA_NOT_WIDE)) && is_virt_maxpa_on_import_valid(virt_maxpa));
}

/**
 * @brief Fills the xbuff_offsets and xbuff_size values in the given TDCS,
 *        based on the given xfam
 *
 * @param tdcs_ptr - TDCS pointer
 * @param xfam     - XFAM mask on which the filled values will be based
 */
void set_xbuff_offsets_and_size(tdcs_t* tdcs_ptr, uint64_t xfam);


// TODO: remove define once WA is removed
#define GNR_A0_CPUID 0xA06D0
#define GNR_D_A0_CPUID 0xA06E0
_STATIC_INLINE_ bool_t is_not_gnr_a0_stepping(void)
{
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    if (tdx_global_data_ptr->is_a0_wa_invoked)
    {
        // WA already invoked
        return !(tdx_global_data_ptr->is_gnr_a0_cpuid || tdx_global_data_ptr->is_gnr_d_cpuid);
    }

    // WA invoked for the first time

    uint32_t eax, ebx, ecx, edx;
    ia32_cpuid(CPUID_VER_INFO_LEAF, 0,
               &eax, &ebx,
               &ecx, &edx);

    tdx_global_data_ptr->is_gnr_a0_cpuid = (eax == GNR_A0_CPUID);
    tdx_global_data_ptr->is_gnr_d_cpuid = (eax == GNR_D_A0_CPUID);

    tdx_global_data_ptr->is_a0_wa_invoked = true;

    return !(tdx_global_data_ptr->is_gnr_a0_cpuid || tdx_global_data_ptr->is_gnr_d_cpuid);
}

#define IA32_SPEC_CTRL_SSBD_BIT        BIT(2)
#define IA32_SPEC_CTRL_IPRED_DIS_S_BIT BIT(4)

_STATIC_INLINE_ uint64_t GET_TDX_MODULE_IA32_SPEC_CTRL(void)
{
    uint64_t res = 0;
    if (is_not_gnr_a0_stepping())
    {
        res |= IA32_SPEC_CTRL_IPRED_DIS_S_BIT;
    }

    res |= IA32_SPEC_CTRL_SSBD_BIT;

    return res;
}



_STATIC_INLINE_ bool_t get_qword_bm(
    uint64_t *bm_arr_ptr,
    uint64_t idx)
{
    return (bm_arr_ptr[idx / 64] & BIT(idx % 64)) > 0;
}

_STATIC_INLINE_ bool_t is_event_allowed(tdcs_t* tdcs_p, uint16_t evt, uint16_t events_num)
{
    int32_t left = 0;
    int32_t right = events_num - 1;

    while (left <= right)
    {
        int32_t mid = left + (right - left) / 2;

        if (tdcs_p->event_filters_internal[mid].raw == evt)
        {
            return true;
        }
        else if (tdcs_p->event_filters_internal[mid].raw < evt)
        {
            left = mid + 1;
        }
        else
        {
            right = mid - 1;
        }
    }

    return false;
}

api_error_type check_host_interrupt_and_hp_bit(sharex_hp_lock_t* lock, bool_t is_resumable);

/**
 * @brief Stores XCR0 and AVX states before usage of AVX and marks AVX regs as 'used'
 * 
 * @param preserve_avx_state If true, the AVX state will be preserved and restored later. If false, AVX state could be reset.
 * @param is_guest Indicates whether the caller is a guest or the host, to determine where to save the XCR0 state
 */
void prepare_state_for_avx_usage(bool_t preserve_avx_state, bool_t is_guest);

/**
 * @brief Restores XCR0 and AVX states after usage.
 * 
 * @param is_guest Determines where the XCR0 state was saved
 */
void restore_xcr0_and_avx_states(bool_t is_guest);

/**
 * @brief Updates the VCPU state details for the L1 guest.
 *
 * This function tracks interrupt and NMI status for the TD guest by updating
 * the vcpu_state_details fields in the TDVPS structure. These fields allow
 * the VMM to efficiently determine guest interrupt state without VM exits.
 *
 * @param tdvps_p Pointer to the TD's VCPU State structure
 * @param update_vnmi Control over vnmi update
 */
void update_vcpu_state_details_for_l1(tdvps_t* tdvps_p, bool_t update_vnmi);

/**
 * @brief Updates the VCPU state details for the L2 guests.
 *
 * Similar to the L1 function, but handles interrupt status tracking for
 * nested virtualization. The L2 state is tracked using different bit positions
 * in the vcpu_state_details field, with each VM ID getting dedicated bit positions.
 *
 * @param tdvps_p Pointer to the TD's VCPU State structure
 */
void update_vcpu_state_details_for_l2(tdvps_t* tdvps_p);

tdx_features_enum0_t get_tdx_features_enum0(void);

void update_eptp_enable_ad_bits(tdcs_t* tdcs_p);

_STATIC_INLINE_ api_error_type is_binding_allowed(tdcs_t* tdcs_p)
{
    if(tdcs_p->service_td_fields.servtd_num)
    {
        TDX_ERROR("The MigTD already has a Service TD bound to it.\n");
        return TDX_SERVTD_NESTING_NOT_ALLOWED;
    }

    if(tdcs_p->executions_ctl_fields.attributes.migratable)
    {
        TDX_ERROR("The MigTD is migratable and cannot have a Service TD bound to it.\n");
        return TDX_SERVTD_CANNOT_BE_MIGRATABLE;
    }

    return TDX_SUCCESS;
}

#endif /* SRC_COMMON_HELPERS_HELPERS_H_ */
