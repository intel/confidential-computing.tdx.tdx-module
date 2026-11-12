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
 * @file tdx_global_data.h
 * @brief TDX global data
 */
#ifndef __TDX_GLOBAL_DATA_H_INCLUDED__
#define __TDX_GLOBAL_DATA_H_INCLUDED__

#include "helpers/tdx_locks.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "helpers/smrrs.h"
#include "debug/tdx_debug.h"
#include "tdx_api_defs.h"
#include "x86_defs/msr_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include CPUID_CONFIGURATIONS_DEFINES_HEADER
#include "crypto/sha384.h"


#define AES_XTS_128                BIT(0)
#define AES_XTS_128_WITH_INTEGRITY BIT(1)
#define AES_XTS_256                BIT(2)
#define AES_XTS_256_WITH_INTEGRITY BIT(3)

typedef enum
{
    SYSINIT_PENDING = 0,
    SYSINIT_DONE    = 1,
    SYSCONFIG_DONE  = 2,
    SYS_READY       = 3,
    SYS_SHUTDOWN    = 4,
    SYS_DISABLE     = 5
} sysinit_state_e;

/**
 * @struct xsave_area_no_extended_t
 *
 * @brief Holds xsave legacy region and headers
 */
typedef struct ALIGN(0x1000) PACKED xsave_area_no_extended_s
{
    xsave_legacy_region_t legacy_region;
    xsave_header_t xsave_header;
} xsave_area_no_extended_t;

/**
 * @struct tdx_global_state_t
 *
 * @brief Holds the global key assignment and system init states
 */
typedef struct tdx_global_state_s
{
    /**
     * system init state: SYSINIT_PENDING = 0, SYSINIT_RUNNING,
     *                    SYSINIT_DONE, SYS_READY, SYS_SHUTDOWN
     */
    uint8_t sys_state;
} tdx_global_state_t;

#define KOT_STATE_HKID_FREE      0
#define KOT_STATE_HKID_ASSIGNED  1
#define KOT_STATE_HKID_FLUSHED   2
#define KOT_STATE_HKID_RESERVED  3

#define KOT_ENTRY_ALIGNMENT      4
#define WBT_ENTRY_ALIGNMENT      8
#define TDMR_ENTRY_ALIGNMENT     8

/**
 * @struct kot_entry_t
 *
 * @brief Holds the entry definition of the KOT
 */
typedef struct ALIGN(KOT_ENTRY_ALIGNMENT) PACKED kot_entry_s
{
    /**
     * Bitmap of packages indicating a TDWBINVD is required before the HKID can be freed.
     * If WBINVD_BITMAP[n] is 1, then the entry’s HKID has been reclaimed
     * (by TDHMNGKEYRECLAIMID), but TDWBINVD has not been completed yet on package n.
     */
    uint32_t wbinvd_bitmap;
    /**
     * kot entry state state: KOT_STATE_HKID_FREE = 0, KOT_STATE_HKID_ASSIGNED, KOT_STATE_HKID_RECLAIMED,
     *                        KOT_STATE_HKID_FLUSHED, KOT_STATE_HKID_RESERVED
     */
     uint8_t state;
} kot_entry_t;

#define MAX_HKIDS 2048
/**
 * @struct kot_t
 *
 * @brief KOT = Key Ownership Table
 *
 * KOT is used to manage HKIDs state and ownership by TDs
 */
typedef struct kot_s
{
    sharex_lock_t lock; /**< shared exclusve lock to access the kot */
    /**
     * A table of MAX_HKIDS entries, indexed by HKID
     */
    kot_entry_t entries[NUM_KOT_ENTRIES];
} kot_t;

/**
 * @struct wbt_entry_t
 *
 * @brief WBT is a table which controls the operation of TDWBINVD.
 *
 *  WBT holds an entry WBINVD scope per package.
 */
typedef struct ALIGN(WBT_ENTRY_ALIGNMENT) PACKED wbt_entry_s
{
    uint64_t intr_point; /**< WBINDP handle */
    /**
     * Array of HKIDs, indicating which HKID was in the HKID_FLUSHED state
     * throughout the TDWBINVD cycle.
     * If HKID_FLUSHED[k] is 1, then when TDWBINVD was initiated
     * (not as a resumption of a previously-interrupted TDWBINVD),
     * KOT.ENTRIES[k].STATE was HKID_FLUSHED.
     * This bitmap is only applicable during a TDBWINVD cycle of all HKIDs,
     * from the initial TDWBINVD until a successful TDWBINVD completion.
     */
    uint8_t hkid_flushed[MAX_HKIDS];
    mutex_lock_t entry_lock; /**< mutex to control concurrent execution of TDWBINVD */
} wbt_entry_t;

#define MAX_PKGS  8
#define MAX_TDMRS 64
/**
 * @struct tdmr_entry_t
 *
 * @brief Holds a TDMR region representation and its PAMTs
 *
 */
typedef struct ALIGN(TDMR_ENTRY_ALIGNMENT) PACKED tdmr_entry_s
{
    uint64_t base; /**< base physical address of TDMR */
    uint64_t size; /**< size of TDMR in bytes */
    uint64_t last_initialized; /**< last initialized address of the TDMR region */

    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range, or PAMT bitmap for dynamic PAMT */

    uint32_t num_of_pamt_blocks; /**< number of PAMT blocks in this TDMR region */
    uint32_t num_of_rsvd_areas;

    struct
    {
        // NOTE: this struct is un-reachable for checking natural alignment, take it under consideration if/when adding more fields to the struct.
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

    mutex_lock_t lock; /**< mutex for the initialization process of this TDMR region */
} tdmr_entry_t;

typedef struct
{

    uint64_t                        ia32_tsc_adjust;

    ia32_misc_enable_t              ia32_misc_enable;

    ia32_vmx_basic_t                ia32_vmx_basic;
    ia32_vmx_misc_t                 ia32_vmx_misc;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_pinbased_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_procbased_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_procbased_ctls2;
    vmx_procbased_ctls3_t           ia32_vmx_procbased_ctls3;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_exit_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_entry_ctls;
    uint64_t                        ia32_vmx_ept_vpid_cap;

    ia32_cr0_t                      ia32_vmx_cr0_fixed0;
    ia32_cr0_t                      ia32_vmx_cr0_fixed1;
    ia32_cr4_t                      ia32_vmx_cr4_fixed0;
    ia32_cr4_t                      ia32_vmx_cr4_fixed1;

    ia32_mtrrcap_t                  ia32_mtrrcap;

    ia32_arch_capabilities_t        ia32_arch_capabilities;
    ia32_xapic_disable_status_t     ia32_xapic_disable_status;
    ia32_core_capabilities_t        ia32_core_capabilities;
    ia32_perf_capabilities_t        ia32_perf_capabilities;

    ia32_tme_capability_t           ia32_tme_capability;
    ia32_tme_activate_t             ia32_tme_activate;
    ia32_tme_keyid_partitioning_t   ia32_tme_keyid_partitioning;

    ia32_misc_package_ctls_t        ia32_misc_package_ctls;
    ia32_platform_id_t              ia32_platform_id;

    smrr_range_t smrr[2];
} platform_common_config_t;

/* TD VMCS field values computed by TDHSYSINIT
*/
typedef struct
{
    uint32_t pinbased_ctls;
    uint32_t procbased_ctls;
    uint32_t procbased_ctls2;
    uint64_t procbased_ctls3;
    uint32_t exit_ctls;
    uint32_t entry_ctls;
} td_vmcs_values_t;

typedef struct vmcs_fields_info_s
{
    uint64_t encoding;
    uint64_t value;
} vmcs_fields_info_t;

/**
 *  @brief Host TD VMCS values
 */
typedef struct vmcs_host_values_s
{
    vmcs_fields_info_t CR0;
    vmcs_fields_info_t CR3;
    vmcs_fields_info_t CR4;
    vmcs_fields_info_t CS;
    vmcs_fields_info_t SS;
    vmcs_fields_info_t FS;
    vmcs_fields_info_t GS;
    vmcs_fields_info_t TR;
    vmcs_fields_info_t IA32_S_CET;
    vmcs_fields_info_t IA32_PAT;
    vmcs_fields_info_t IA32_EFER;
    vmcs_fields_info_t FS_BASE;
    vmcs_fields_info_t IDTR_BASE;
    vmcs_fields_info_t GDTR_BASE;
} vmcs_host_values_t;

typedef struct xsave_component_info_s
{
    uint32_t size;
    bool_t   align;
} xsave_component_info_t;

#define SEALKEY_SIZE_128_BIT 0
#define SEALKEY_SIZE_256_BIT 1

typedef enum
{
    WRITE_BLOCKING_EXPORT_UNUSED        = 0,
    WRITE_BLOCKING_EXPORT_POSSIBLY_USED = 1,
    WRITE_BLOCKING_EXPORT_USED          = 2
} write_blocking_export_used_e;

typedef enum
{
    SYS_DISABLE_START = 0,
    SYS_DISABLE_MEMORY_RESET,
    SYS_DISABLE_PAMT_RESET,
    SYS_DISABLE_LP_STATE_RESET,
    SYS_DISABLE_KEYHOLE_STATE_RESET,
    SYS_DISABLE_HANDOFF_RESET
} sys_disable_interruption_point;

typedef enum
{
    PT_4KB  = 0,
    PT_2MB  = 1,
    PT_1GB  = 2
} page_size_t;

typedef struct sys_disable_interruption_state_s
{
    sys_disable_interruption_point intr_point;
    uint32_t working_lp;
    uint32_t tdmr_index;
    uint64_t offset_from_base;
    page_size_t page_size;
    uint64_t offset_in_page;
    uint64_t lp_num;
} sys_disable_interruption_state_t;

/**
 * @struct tdx_module_global_t
 *
 * @brief Holds the global per-package data
 *
 */
typedef struct tdx_module_global_s
{
    // DO NOT MOVE BELOW FIELDS - REQUIRED FOR TDH.SYS.DISABLE FUNCTIONALITY
    sharex_lock_t global_lock; /**< shared exclusive lock to access the global data per-package */
    tdx_global_state_t global_state;
    sys_disable_interruption_state_t sys_disable_intr_state;
    // DO NOT MOVE ABOVE FIELDS - REQUIRED FOR TDH.SYS.DISABLE FUNCTIONALITY

    xsave_area_no_extended_t xbuf;

    uint64_t hkid_mask; /**< mask hkid bits from physical address */
    uint32_t hkid_start_bit;
    uint64_t max_pa; /**< Maximum PA bits supported by the platform */
    uint32_t num_of_lps; /**< total number of logical processors */
    uint32_t num_of_pkgs; /**< total number of packages */
    uint32_t num_of_init_lps; /**< number of initialized lps */
    uint32_t num_of_init_pkgs; /**< number of initialized packages */
    uint16_t module_hv;
    uint16_t min_update_hv;
    uint16_t no_downgrade;
    uint16_t num_handoff_pages;
    bool_t update_compatibility;
    uint16_t td_build_count;
    uint16_t mig_interrupted_count;

    /* SEAMDB_INDEX/NONCE are sampled by TDH.SYS.INIT using SEAMOPS(SEAMDB_GETREF).  If TD preserving
       is not supported by the CPU, they are set to 0. */
    uint64_t   seamdb_index;
    uint256_t  seamdb_nonce;

    /**
     * Bitmap that indicates on which package the global private key has been configured.
     */
    uint32_t pkg_config_bitmap;
    uint32_t private_hkid_min; /**< minimum value for a private tdx hkid */
    uint32_t private_hkid_max; /**< maximum ... */
    uint16_t hkid;
    kot_t kot;
    wbt_entry_t wbt_entries[MAX_PKGS];
    tdmr_entry_t tdmr_table[MAX_TDMRS];
    uint32_t num_of_tdmr_entries;
    platform_common_config_t plt_common_config;
    uint64_t seamrr_base; /**< SEAMRR base physical address */
    uint64_t seamrr_size; /**< SEAMRR size in bytes */
    /**
     * Indicates the number of blocks that need to be invalidated when running a WBINVD cycle.
     */
    uint64_t num_of_cached_sub_blocks;

    uint32_t x2apic_core_id_shift_count;  // # of bits to shift to get Core ID
    uint32_t x2apic_core_id_mask;
    uint32_t x2apic_pkg_id_shift_count;   // # of bits to shift to get Package ID

    bool_t waitpkg_supported;
    bool_t kl_loadiwk_no_backup;
    bool_t xfd_supported;
    bool_t hle_supported;
    bool_t rtm_supported;
    bool_t ddpd_supported;
    bool_t la57_supported;
    bool_t lam_supported;
    bool_t perfmon_ext_leaf_supported;
    bool_t lass_supported;

    uint64_t crystal_clock_frequency;
    uint64_t native_tsc_frequency;

    uint32_t xcr0_supported_mask;
    uint32_t ia32_xss_supported_mask;
    uint32_t xfd_faulting_mask;

    xsave_component_info_t xsave_comp[XCR0_MAX_BIT+1];

    // Values of CPUID, sampled @ TDHSYSINIT and verified @ TDHSYSINITLP
    cpuid_config_t cpuid_values[MAX_NUM_CPUID_LOOKUP];
    uint32_t cpuid_last_base_leaf;      // Calculated on TDH.SYS.INIT, based on CPUID(0).EAX (may be higher)
    uint32_t cpuid_last_extended_leaf;  // Calculated on TDH.SYS.INIT, based on CPUID(0x80000000).EAX

    // Values of TD VMCS fields, computed @ TDHSYSINIT
    td_vmcs_values_t td_vmcs_values;

    // Values of L2 VMCS fields, computed @ TDHSYSINIT
    td_vmcs_values_t l2_vmcs_values;

    // Values of SEAM VMCS host fields. initialized @ TDHSYSINIT
    // used when a TD VMCS needs to be initialized
    vmcs_host_values_t seam_vmcs_host_values;

    // Perfmon and tracing information
    uint32_t         max_lbr_depth;
    uint8_t          num_fixed_ctrs;
    uint32_t         fc_bitmap;


    bool_t is_arch_pebs_supported;

    // ATTRIBUTES fixed bits masks
    uint64_t     attributes_fixed0;   // Bit value of 0 means ATTRIBUTES bit must be 0
    uint64_t     attributes_fixed1;   // Bit value of 1 means ATTRIBUTES bit must be 1

    // CONFIG_FLAGS fixed bits masks
    config_flags_t config_flags_fixed0;
    config_flags_t config_flags_fixed1;

    // Array of TDMR info
    tdmr_info_entry_t tdmr_info_copy[MAX_TDMRS];

    seam_ops_capabilities_t seam_capabilities;
    bool_t     seamverifyreport_available;
    bool_t     sealing_supported;
    uint8_t    sealing_supported_sizes_bitmap; // bitmap of supported sealing key sizes

    uint8_t num_rdseed_retries;
    uint8_t num_rdseed_pauses;

    // Hash method buffers for IPP crypto lib - should be initialized before usage
    hash_method_t         sha384_method;

    fms_info_t      platform_fms;
    cpuid_1a_eax_t  native_model_info;

    // fatal error diagnostics
    uint64_t fatal_info_config_hpa;
    uint64_t fatal_info_icr;

    // interruption checking interval
    uint64_t twenty_usec_in_tsc;

    bool_t          dynamic_pamt_enabled;

    bool_t non_blocking_export_configured;
    uint8_t write_blocking_export_used;
    bool_t scan_export_restore;

    bool_t tdid_vmid_reporting_enabled;


#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    debug_control_t debug_control;
    debug_message_t trace_buffer[TRACE_BUFFER_SIZE];
#endif // DEBUGFEATURE_TDX_DBG_TRACE


    // TODO: remove define once WA is removed
    bool_t is_a0_wa_invoked;
    bool_t is_gnr_a0_cpuid;
    bool_t is_gnr_d_cpuid;

    uint16_t num_dynamic_blobs;

} tdx_module_global_t;
tdx_static_assert(offsetof(tdx_module_global_t, global_lock) % 2 == 0, global_lock);

// validate that all variables in kot are aligned to their natural size
tdx_static_assert(sizeof(kot_t) == 16388, kot_t);
tdx_static_assert((offsetof(tdx_module_global_t, kot) + offsetof(kot_t, lock)) % sizeof(sharex_lock_t) == 0, kot_t);
tdx_static_assert((offsetof(tdx_module_global_t, kot) + offsetof(kot_t, entries) + offsetof(kot_entry_t, wbinvd_bitmap)) % sizeof_field(kot_entry_t, wbinvd_bitmap) == 0, kot_t);

// validate that all variables in wbt_entries are aligned to their natural size
tdx_static_assert(sizeof(wbt_entry_t) == 2064, wbt_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, wbt_entries) + offsetof(wbt_entry_t, intr_point)) % sizeof(uint64_t) == 0, wbt_entry_t);

// validate that all variables in tdmr_table are aligned to their natural size
tdx_static_assert(sizeof(tdmr_entry_t) == 320, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, base)) % sizeof_field(tdmr_entry_t, base) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, size)) % sizeof_field(tdmr_entry_t, size) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, last_initialized)) % sizeof_field(tdmr_entry_t, last_initialized) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, pamt_4k_base)) % sizeof_field(tdmr_entry_t, pamt_4k_base) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, pamt_2m_base)) % sizeof_field(tdmr_entry_t, pamt_2m_base) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, pamt_1g_base)) % sizeof_field(tdmr_entry_t, pamt_1g_base) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, num_of_pamt_blocks)) % sizeof_field(tdmr_entry_t, num_of_pamt_blocks) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, num_of_rsvd_areas)) % sizeof_field(tdmr_entry_t, num_of_rsvd_areas) == 0, tdmr_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_table) + offsetof(tdmr_entry_t, rsvd_areas)) % sizeof(uint64_t) == 0, tdmr_entry_t);

// validate that all variables in tdmr_info_copy are aligned to their natural size
tdx_static_assert(sizeof(tdmr_info_entry_t) == 320, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, tdmr_base)) % sizeof_field(tdmr_info_entry_t, tdmr_base) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, tdmr_size)) % sizeof_field(tdmr_info_entry_t, tdmr_size) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_1g_base)) % sizeof_field(tdmr_info_entry_t, pamt_1g_base) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_1g_size)) % sizeof_field(tdmr_info_entry_t, pamt_1g_size) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_2m_base)) % sizeof_field(tdmr_info_entry_t, pamt_2m_base) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_2m_size)) % sizeof_field(tdmr_info_entry_t, pamt_2m_size) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_4k_base)) % sizeof_field(tdmr_info_entry_t, pamt_4k_base) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, pamt_4k_size)) % sizeof_field(tdmr_info_entry_t, pamt_4k_size) == 0, tdmr_info_entry_t);
tdx_static_assert((offsetof(tdx_module_global_t, tdmr_info_copy) + offsetof(tdmr_info_entry_t, rsvd_areas)) % sizeof(uint64_t) == 0, tdmr_info_entry_t);

#endif // __TDX_GLOBAL_DATA_H_INCLUDED__
