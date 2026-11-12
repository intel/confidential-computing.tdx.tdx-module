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

#ifndef __PRESERVING_DEFS_H__
#define __PRESERVING_DEFS_H__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "data_structures/tdx_global_data.h"

#pragma pack(push, 1)

typedef struct handoff_data_header_s
{
    bool_t   valid;
    uint8_t  reserved;
    uint16_t hv;
    uint32_t size; // Size of the handoff data excluding this header
} handoff_data_header_t;
tdx_static_assert(sizeof(handoff_data_header_t) == 8, handoff_data_header_t);

typedef union handoff_s
{
    struct
    {
        uint64_t handoff_version : 16;
        uint64_t avoid_compat_sensitive : 1;
        uint64_t reserved : 47;
    };

    uint64_t raw;
} handoff_input_param_t;
tdx_static_assert(sizeof(handoff_input_param_t) == 8, handoff_input_param_t);

typedef struct handoff_data_blob_s
{
    struct
    {
        uint16_t uid;     // Unique ID
        uint8_t version;  // Struct version
        uint8_t reserved; // Set to zero
        uint32_t size;    // Blob size including header
    } header;

    uint8_t data; // Data blob, variable size
} handoff_dynamic_blob_t;
tdx_static_assert(sizeof(handoff_dynamic_blob_t) == 9, handoff_dynamic_blob_t);

#define HANDOFF_DYNAMIC_BLOB_HEADER_SIZE (8)
tdx_static_assert(sizeof_field(handoff_dynamic_blob_t, header) == HANDOFF_DYNAMIC_BLOB_HEADER_SIZE, HANDOFF_DYNAMIC_BLOB_HEADER_SIZE);

#define IS_HANDOFF_DYNAMIC_BLOB_SUPPORTED (MODULE_HV >= 3)


#define NBE_FIELD_SIZES (2)

// Used as padding to achieve 4KB alignment
#define HANDOFF_RESERVED_V2_SIZE (3945 - NBE_FIELD_SIZES)

typedef struct td_preserving_hod_s
{
    handoff_data_header_t header;

    // v0 fields
    kot_entry_t kot_entries[MAX_HKIDS];
    wbt_entry_t wbt_entries[MAX_PKGS];
    tdmr_entry_t tdmr_table[MAX_TDMRS];
    uint32_t num_of_tdmr_entries;
    uint16_t hkid;
    uint32_t package_config_bitmap;
    bool_t dynamic_pamt_enabled;

    // v1 fields
    uint16_t td_build_count; // Not naturally aligned
    uint16_t mig_interrupted_count;

    // v2 fields
    bool_t non_blocking_export;
    uint8_t write_blocking_export_used;

    // Padding to complete 4KB alignment
    uint8_t round_up_to_4k_1[HANDOFF_RESERVED_V2_SIZE];
} td_preserving_hod_t;
tdx_static_assert((sizeof(td_preserving_hod_t) % TDX_PAGE_SIZE_IN_BYTES) == 0, td_preserving_hod_t);

#define TD_PRESERVING_HANDOFF_PAGE_COUNT (sizeof(td_preserving_hod_t) / TDX_PAGE_SIZE_IN_BYTES)

// Static asserts to ensure that the field sizes in tdx_module_global_t match td_preserving_hod_t
tdx_static_assert(sizeof_field(tdx_module_global_t, kot.entries) == sizeof_field(td_preserving_hod_t, kot_entries), TD_PRESERVING_HOD_KOT_ENTRY_ARR_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, wbt_entries) == sizeof_field(td_preserving_hod_t, wbt_entries), PRESERVING_HOD_WBT_ENTRY_ARR_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, tdmr_table) == sizeof_field(td_preserving_hod_t, tdmr_table), PRESERVING_HOD_TDMR_ENTRY_ARR_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, num_of_tdmr_entries) == sizeof_field(td_preserving_hod_t, num_of_tdmr_entries), PRESERVING_HOD_NUM_OF_TDMR_ENTRIES_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, hkid) == sizeof_field(td_preserving_hod_t, hkid), PRESERVING_HOD_HKID_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, pkg_config_bitmap) == sizeof_field(td_preserving_hod_t, package_config_bitmap), PRESERVING_HOD_PKG_CONFIG_BITMAP_SIZE2);

tdx_static_assert(sizeof_field(tdx_module_global_t, dynamic_pamt_enabled) == sizeof_field(td_preserving_hod_t, dynamic_pamt_enabled), PRESERVING_HOD_DYNAMIC_PAMT_ENABLED_SIZE2);

tdx_static_assert(sizeof_field(tdx_module_global_t, td_build_count) == sizeof_field(td_preserving_hod_t, td_build_count), PRESERVING_HOD_TD_BUILD_COUNT_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, mig_interrupted_count) == sizeof_field(td_preserving_hod_t, mig_interrupted_count), PRESERVING_HOD_MIG_INTERRUPTED_COUNT_SIZE2);

tdx_static_assert(sizeof_field(tdx_module_global_t, non_blocking_export_configured) == sizeof_field(td_preserving_hod_t, non_blocking_export), PRESERVING_HOD_NON_BLOCKING_EXPORT_SIZE2);
tdx_static_assert(sizeof_field(tdx_module_global_t, write_blocking_export_used) == sizeof_field(td_preserving_hod_t, non_blocking_export), PRESERVING_HOD_WRITE_BLOCKING_EXPORT_USED_SIZ2);

tdx_static_assert((TDX_PAGE_SIZE_IN_BYTES - (offsetof(td_preserving_hod_t, round_up_to_4k_1) % TDX_PAGE_SIZE_IN_BYTES)) == HANDOFF_RESERVED_V2_SIZE, HANDOFF_RESERVED_V2_SIZE);

/**
 * @note, TDX Connect static fields coming from HV 0 (TDX 2.0.12) are deprecated starting from TDX 2.0.14 and therefore skipped during the handoff retrieval process
 */
#define HANDOFF_V0_DEPRECATED_IOMMU_CONFIGS_SIZE (128 * 378)
#define HANDOFF_V0_DEPRECATED_MMIOMT_ROOT_SIZE (32)
#define HANDOFF_V0_DEPRECATED_TDIMT_ROOT_SIZE (8)

#define HANDOFF_DEFAULT_FIELDS_SIZE offsetof(td_preserving_hod_t, dynamic_pamt_enabled)
#define HANDOFF_V0_DYNAMIC_PAMT_OFFSET (101818) // Taken from the handoff spreadsheets
// Padding to achieve 4KB alignment
#define HANDOFF_V0_RESERVED_SIZE (ROUND_UP(                                                     \
                                      HANDOFF_V0_DYNAMIC_PAMT_OFFSET, TDX_PAGE_SIZE_IN_BYTES) - \
                                  (HANDOFF_DEFAULT_FIELDS_SIZE + HANDOFF_V0_DEPRECATED_IOMMU_CONFIGS_SIZE + HANDOFF_V0_DEPRECATED_MMIOMT_ROOT_SIZE + HANDOFF_V0_DEPRECATED_TDIMT_ROOT_SIZE + 1))

typedef struct
{
    uint8_t reserved_0[HANDOFF_DEFAULT_FIELDS_SIZE];
    uint8_t skipped_connect_handoff[HANDOFF_V0_DEPRECATED_IOMMU_CONFIGS_SIZE +
                                    HANDOFF_V0_DEPRECATED_MMIOMT_ROOT_SIZE +
                                    HANDOFF_V0_DEPRECATED_TDIMT_ROOT_SIZE];
    bool_t dynamic_pamt_enabled;
    uint8_t reserved_1[HANDOFF_V0_RESERVED_SIZE];
} td_preserving_skipped_hod_t;
tdx_static_assert((sizeof(td_preserving_skipped_hod_t) % TDX_PAGE_SIZE_IN_BYTES) == 0, td_preserving_hod_t);

// TDX 2.0.12 and earlier handoff size
#define TD_PRESERVING_V0_HANDOFF_PAGE_COUNT (sizeof(td_preserving_skipped_hod_t) / TDX_PAGE_SIZE_IN_BYTES)
tdx_static_assert(TD_PRESERVING_V0_HANDOFF_PAGE_COUNT == 25, td_preserving_skipped_hod_t);

tdx_static_assert(offsetof(td_preserving_skipped_hod_t, dynamic_pamt_enabled) == HANDOFF_V0_DYNAMIC_PAMT_OFFSET, HANDOFF_RESERVED_V2_SIZE);

/**
 * @note The logic behind the define below is only relevant for TDX 2.X, since the PSEAMLDR will be updated to apply this logic on its side in future releases
 *
 * TDX 2.0.12 and above require at least 25 handoff pages
 * TDX 2.1.* require at least 28 handoff pages
 * The handoff size in the sigstruct is set to the max of the two
 */
#define TD_PRESERVING_SIGSTRUCT_HANDOFF_PAGE_COUNT (MAX(TD_PRESERVING_V0_HANDOFF_PAGE_COUNT, TD_PRESERVING_HANDOFF_PAGE_COUNT))
tdx_static_assert(TD_PRESERVING_SIGSTRUCT_HANDOFF_PAGE_COUNT >= 25, TD_PRESERVING_SIGSTRUCT_HANDOFF_PAGE_COUNT);

#pragma pack(pop)

#endif // __PRESERVING_DEFS_H__
