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
 * @file loader_data.h
 * @brief SEAMLDR interface structures
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_
#define SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"

#define STACK_CANARY_OFFSET 0x28

typedef union sysinfo_mcheck_flags_u
{
    struct
    {
        uint32_t act_table                      : 1;
        uint32_t handle_mktme_keyid_aliasing    : 1;
        uint32_t client                         : 1;
        uint32_t reserved                       : 29;
    };

    uint32_t raw;
} sysinfo_mcheck_flags_t;
tdx_static_assert(sizeof(sysinfo_mcheck_flags_t) == 4, sysinfo_mcheck_flags_t);

/**
 * @struct sysinfo_table_t
 *
 * @brief Holds a SYSINFO table representation that is filled by the SEAMLDR
 *
 */
typedef struct PACKED sysinfo_table_s
{
    union
    {
        struct
        {
            // Fields populated by MCHECK
            uint64_t version;               /**< Structure Version – Set to 0 */
            uint32_t tot_num_lps;           /**< Total number of logical processors in platform */
            uint32_t tot_num_sockets;       /**< Total number of sockets in platform */
            fms_info_t socket_cpuid_table[MAX_PKGS]; /**< List of CPUID.leaf_1.EAX values from all sockets */
            uint8_t reserved_0[16];         /**< Reserved */
            bool_t smrr2_not_supported;
            bool_t tdx_without_integrity;
            uint16_t io_sys_info_table_version;
            sysinfo_mcheck_flags_t flags;   /**< SOC specific flags */

            uint8_t reserved_2[56];         /**< Reserved */
        } mcheck_fields;
        struct
        {
            //  SYS_INFO_TABLE information is saved to the last global data page (without corrupting the StackCanary field)
            uint8_t  reserved_1[STACK_CANARY_OFFSET];

            uint64_t canary; // Offset 0x28 of the last data page
        } stack_canary;
    };

    cmr_info_entry_t cmr_data[MAX_CMR]; /**< CMR info (base and size) */
    uint8_t reserved_2[1408];       /**< Reserved */

    // Fields initialized to zero by MCHECK and populated by SEAMLDR ACM
    uint64_t seam_status;           /**< SEAM status */
                                    /**< 0: NOT_LOADED   - module not loaded */
                                    /**< 1: LOADED       - module load complete */
                                    /**< 2: LOAD_IN_PROG - module load in progress */
    uint64_t code_rgn_base;         /**< Base address of Code region */
    uint64_t code_rgn_size;         /**< Size of code region in bytes */
    uint64_t data_rgn_base;         /**< Base address of Data region */
    uint64_t data_rgn_size;         /**< Size of data region in bytes */
    uint64_t stack_rgn_base;        /**< Base address of stack region */
    uint64_t stack_rgn_size;        /**< Size of Stack Region in bytes */
    uint64_t keyhole_rgn_base;      /**< Base address of Keyhole region */
    uint64_t keyhole_rgn_size;      /**< Size of the Keyhole region in bytes */
    uint64_t keyhole_edit_rgn_base; /**< Keyhole Edit Region Base */
    uint64_t keyhole_edit_rgn_size; /**< Size of Keyhole Edit Region in bytes */
    uint64_t num_stack_pages;       /**< Data Stack size per thread unit=(# 4K pages) – 1 */
    uint64_t num_tls_pages;         /**< TLS size per thread - unit=(# 4K pages) – 1 */
    uint16_t module_hv;             /**< The native handoff version that this TDX module should support */
    uint16_t min_update_hv;         /**< The minimum handoff version that this TDX module should support */
    bool_t   no_downgrade;          /**< A boolean flag that indicates whether this TDX module should disallow downgrades */
    uint8_t  reserved_3[1];         /**< Reserved */
    uint16_t num_handoff_pages;     /**< The number of 4KB pages (minus 1) allocated at the beginning of the data region for handoff data. */
    uint8_t  reserved_4[1936];

} sysinfo_table_t;
tdx_static_assert(sizeof(sysinfo_table_t) == TDX_PAGE_SIZE_IN_BYTES, sysinfo_table_t);

#endif /* SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_ */
