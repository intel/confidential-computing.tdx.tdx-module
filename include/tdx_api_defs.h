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
 * @file tdx_api_defs.h
 * @brief TDX API Definitions
 */
#ifndef __TDX_API_DEFS_H_INCLUDED__
#define __TDX_API_DEFS_H_INCLUDED__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "crypto/sha384.h"
#include "metadata_sorter.h"
#include CPUID_CONFIGURATIONS_DEFINES_HEADER
#include GLOBAL_CONSTANTS_HEADER

#pragma pack(push)
#pragma pack(1)

/**< Enum for SEAMCALL leaves opcodes */
typedef enum seamcall_leaf_opcode_e
{
    TDH_VP_ENTER_LEAF                = 0,
    TDH_MNG_ADDCX_LEAF               = 1,
    TDH_MEM_PAGE_ADD_LEAF            = 2,
    TDH_MEM_SEPT_ADD_LEAF            = 3,
    TDH_VP_ADDCX_LEAF                = 4,
    TDH_MEM_PAGE_RELOCATE            = 5,
    TDH_MEM_PAGE_AUG_LEAF            = 6,
    TDH_MEM_RANGE_BLOCK_LEAF         = 7,
    TDH_MNG_KEY_CONFIG_LEAF          = 8,
    TDH_MNG_CREATE_LEAF              = 9,
    TDH_VP_CREATE_LEAF               = 10,
    TDH_MNG_RD_LEAF                  = 11,
    TDH_MEM_RD_LEAF                  = 12,
    TDH_MNG_WR_LEAF                  = 13,
    TDH_MEM_WR_LEAF                  = 14,
    TDH_MEM_PAGE_DEMOTE_LEAF         = 15,
    TDH_MR_EXTEND_LEAF               = 16,
    TDH_MR_FINALIZE_LEAF             = 17,
    TDH_VP_FLUSH_LEAF                = 18,
    TDH_MNG_VPFLUSHDONE_LEAF         = 19,
    TDH_MNG_KEY_FREEID_LEAF          = 20,
    TDH_MNG_INIT_LEAF                = 21,
    TDH_VP_INIT_LEAF                 = 22,
    TDH_MEM_PAGE_PROMOTE_LEAF        = 23,
    TDH_PHYMEM_PAGE_RDMD_LEAF        = 24,
    TDH_MEM_SEPT_RD_LEAF             = 25,
    TDH_VP_RD_LEAF                   = 26,
    TDH_MNG_KEY_RECLAIMID_LEAF       = 27,
    TDH_PHYMEM_PAGE_RECLAIM_LEAF     = 28,
    TDH_MEM_PAGE_REMOVE_LEAF         = 29,
    TDH_MEM_SEPT_REMOVE_LEAF         = 30,
    TDH_SYS_KEY_CONFIG_LEAF          = 31,
    TDH_SYS_INFO_LEAF                = 32,
    TDH_SYS_INIT_LEAF                = 33,
    TDH_SYS_RD_LEAF                  = 34,
    TDH_SYS_LP_INIT_LEAF             = 35,
    TDH_SYS_TDMR_INIT_LEAF           = 36,
    TDH_SYS_RDALL_LEAF               = 37,
    TDH_MEM_TRACK_LEAF               = 38,
    TDH_MEM_RANGE_UNBLOCK_LEAF       = 39,
    TDH_PHYMEM_CACHE_WB_LEAF         = 40,
    TDH_PHYMEM_PAGE_WBINVD_LEAF      = 41,
    TDH_MEM_SEPT_WR_LEAF             = 42,
    TDH_VP_WR_LEAF                   = 43,
    TDH_SYS_LP_SHUTDOWN_LEAF         = 44,
    TDH_SYS_CONFIG_LEAF              = 45,
    TDH_SERVTD_BIND_LEAF             = 48,
    TDH_SERVTD_PREBIND_LEAF          = 49,
    TDH_SYS_SHUTDOWN_LEAF            = 52,
    TDH_SYS_UPDATE_LEAF              = 53,

    TDH_PHYMEM_PAMT_ADD_LEAF         = 58,
    TDH_PHYMEM_PAMT_REMOVE_LEAF      = 59,


    TDH_EXPORT_ABORT_LEAF            = 64,
    TDH_EXPORT_BLOCKW_LEAF           = 65,
    TDH_EXPORT_RESTORE_LEAF          = 66,
    TDH_EXPORT_MEM_LEAF              = 68,
    TDH_SYS_DISABLE_LEAF             = 69,
    TDH_EXPORT_PAUSE_LEAF            = 70,
    TDH_EXPORT_TRACK_LEAF            = 71,
    TDH_EXPORT_STATE_IMMUTABLE_LEAF  = 72,
    TDH_EXPORT_STATE_TD_LEAF         = 73,
    TDH_EXPORT_STATE_VP_LEAF         = 74,
    TDH_EXPORT_UNBLOCKW_LEAF         = 75,
    TDH_IMPORT_ABORT_LEAF            = 80,
    TDH_IMPORT_END_LEAF              = 81,
    TDH_IMPORT_COMMIT_LEAF           = 82,
    TDH_IMPORT_MEM_LEAF              = 83,
    TDH_IMPORT_TRACK_LEAF            = 84,
    TDH_IMPORT_STATE_IMMUTABLE_LEAF  = 85,
    TDH_IMPORT_STATE_TD_LEAF         = 86,
    TDH_IMPORT_STATE_VP_LEAF         = 87,
    TDH_MEM_SCAN_RANGE_LEAF          = 92,
    TDH_MEM_SCAN_COMP_LEAF           = 93,
    TDH_MEM_SCAN_CONFIG_LEAF         = 94,
    TDH_MEM_SCAN_RESET_LEAF          = 95,
    TDH_MIG_STREAM_CREATE_LEAF       = 96,
    TDH_SERVTD_REBIND_LEAF           = 97
    ,TDH_IOMMU_SETREG_LEAF           = 128,
    TDH_IOMMU_GETREG_LEAF            = 129,
    TDH_SPDM_CREATE_LEAF             = 130,
    TDH_SPDM_DELETE_LEAF             = 131,
    TDH_IDE_STREAM_CREATE_LEAF       = 132,
    TDH_IDE_STREAM_BLOCK_LEAF        = 133,
    TDH_IDE_STREAM_DELETE_LEAF       = 134,
    TDH_IDE_STREAM_IDEKMREQ_LEAF     = 135,
    TDH_IDE_STREAM_IDEKMRSP_LEAF     = 136,
    TDH_DEVIF_CREATE_LEAF            = 137,
    TDH_DEVIF_REMOVE_LEAF            = 138,
    TDH_DEVIF_REQUEST_LEAF           = 139,
    TDH_DEVIF_RESPONSE_LEAF          = 140,
    TDH_DMAR_ADD_LEAF                = 150,
    TDH_DMAR_BLOCK_LEAF              = 151,
    TDH_DMAR_READ_LEAF               = 152,
    TDH_DMAR_REMOVE_LEAF             = 153,
    TDH_MMIO_MT_ADD_LEAF             = 154,
    TDH_MMIO_MT_SET_LEAF             = 155,
    TDH_MMIO_MT_RD_LEAF              = 156,
    TDH_MMIO_MT_REMOVE_LEAF          = 157,
    TDH_MMIO_MAP_LEAF                = 158,
    TDH_MMIO_BLOCK_LEAF              = 159,
    TDH_MMIO_UNMAP_LEAF              = 160,
    TDH_IQ_INV_REQUEST_LEAF          = 161,
    TDH_IQ_INV_PROCESS_LEAF          = 162,
    TDH_MEM_SHARED_SEPT_WR_LEAF      = 163,
    TDH_DEVIF_MT_ADD_LEAF            = 164,
    TDH_DEVIF_MT_REMOVE_LEAF         = 165,
    TDH_DEVIF_MT_RD_LEAF             = 166


#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    ,TDDEBUGCONFIG_LEAF = 0xFE
#endif // DEBUGFEATURE_TDX_DBG_TRACE


} seamcall_leaf_opcode_t;

/**< Enum for TDCALL leaves opcodes */
typedef enum tdcall_leaf_opcode_e
{
    TDG_VP_VMCALL_LEAF           = 0,
    TDG_VP_INFO_LEAF             = 1,
    TDG_MR_RTMR_EXTEND_LEAF      = 2,
    TDG_VP_VEINFO_GET_LEAF       = 3,
    TDG_MR_REPORT_LEAF           = 4,
    TDG_VP_CPUIDVE_SET_LEAF      = 5,
    TDG_MEM_PAGE_ACCEPT_LEAF     = 6,
    TDG_VM_RD_LEAF               = 7,
    TDG_VM_WR_LEAF               = 8,
    TDG_VP_RD_LEAF               = 9,
    TDG_VP_WR_LEAF               = 10,
    TDG_SYS_RD_LEAF              = 11,
    TDG_SYS_RDALL_LEAF           = 12,

    TDG_SERVTD_RD_LEAF           = 18,
    TDG_SERVTD_WR_LEAF           = 20,
    TDG_SERVTD_REBIND_APPROVE_LEAF = 33,

    TDG_MR_VERIFYREPORT_LEAF     = 22,
    TDG_MEM_PAGE_ATTR_RD_LEAF    = 23,
    TDG_MEM_PAGE_ATTR_WR_LEAF    = 24,
    TDG_VP_ENTER_LEAF            = 25,
    TDG_VP_INVEPT_LEAF           = 26,
    TDG_VP_INVVPID_LEAF          = 27

    ,TDG_MR_KEY_GET_LEAF         = 29


    ,TDG_SPDM_TPA_SET_LEAF        = 64,
    TDG_SPDM_TPA_GET_LEAF        = 65,
    TDG_DEVIF_VALIDATE_LEAF      = 66,
    TDG_DEVIF_RD_LEAF            = 67,
    TDG_DEVIF_REQUEST_LEAF       = 68,
    TDG_DEVIF_RESPONSE_LEAF      = 69,
    TDG_DMAR_ACCEPT_LEAF         = 70,
    TDG_TDI_MMIO_ACCEPT_LEAF     = 71,
    TDG_IQ_INV_REQUEST_LEAF      = 72
} tdcall_leaf_opcode_t;

typedef union tdx_leaf_and_version_u
{
    struct
    {
        uint64_t leaf            : 16;
        uint64_t version         : 8;
        uint64_t reserved0       : 8;
        uint64_t reserved1       : 32;
    };
    uint64_t raw;
} tdx_leaf_and_version_t;
tdx_static_assert(sizeof(tdx_leaf_and_version_t) == 8, tdx_leaf_and_version_t);

/**
 * @struct page_info_api_input_t
 *
 * @brief Input info for SEPT API calls.
 */
typedef union page_info_api_input_s {
    struct
    {
        uint64_t
            level          : 3,  /**< Level */
            reserved_0     : 9,  /**< Must be 0 */
            gpa            : 40, /**< GPA of the page */
            reserved_1     : 12; /**< Must be 0 */
    };
    uint64_t raw;
} page_info_api_input_t;
tdx_static_assert(sizeof(page_info_api_input_t) == 8, page_info_api_input_t);


/**
 * @struct hkid_api_input_t
 *
 * @brief Input for HKID info
 */
typedef union hkid_api_input_s {
    struct
    {
        uint64_t
            hkid          : 16,  /**< HKID */
            reserved      : 48;  /**< Must be 0 */
    };
    uint64_t raw;
} hkid_api_input_t;
tdx_static_assert(sizeof(hkid_api_input_t) == 8, hkid_api_input_t);

/**
 * @struct sys_config_options_t
 *
 * @brief SYS.CONFIG input for HKID info and dynamic PAMT config
 */
typedef union sys_config_options_s {
    struct
    {
        uint64_t
            hkid          : 16,  /**< HKID */
            dynamic_pamt  : 1,   /**< Enable dynamic PAMT mode */
            reserved      : 47;  /**< Must be 0 */
    };
    uint64_t raw;
} sys_config_options_t;
tdx_static_assert(sizeof(sys_config_options_t) == 8, sys_config_options_t);


#define PAMT_4K 0
#define PAMT_2M 1
#define PAMT_1G 2

/**
 * @struct page_size_api_input_t
 *
 * @brief Input for page size (level) info
 */
typedef union page_size_api_input_s {
    struct
    {
        uint64_t
            level         : 3,  /**< Level PAMT_4K=0, PAMT_2M=1, PAMT_1G=2 */
            reserved1     : 9,  /**< Must be 0 */
            hpa           : 40,
            reserved2     : 12;
    };
    uint64_t raw;
} page_size_api_input_t;
tdx_static_assert(sizeof(page_size_api_input_t) == 8, page_size_api_input_t);

/**
 * @struct tdvmcall_control_t - TDVMCALL RCX input parameter
 */
typedef union tdvmcall_control_u
{
    struct
    {
        uint16_t gpr_select;
        uint16_t xmm_select;
        uint32_t reserved;
    };
    uint64_t raw;
} tdvmcall_control_t;


/**
 * @struct vmcs_field_code_t
 */
typedef union vmcs_field_code_s {

    struct
    {
        uint32_t access_type : 1;  // 0
        uint32_t index       : 9;  // 1-9
        uint32_t type        : 2;  // 10-11
        uint32_t reserved0   : 1;  // 12
        uint32_t width       : 2;  // 13-14
        uint32_t reserved1   : 17; // 15-31
    };

    uint32_t raw;
} vmcs_field_code_t;
tdx_static_assert(sizeof(vmcs_field_code_t) == 4, vmcs_field_code_t);

#define VMCS_FIELD_ACCESS_TYPE_FULL         0
#define VMCS_FIELD_ACCESS_TYPE_HIGH         1

#define VMCS_FIELD_WIDTH_16B                0
#define VMCS_FIELD_WIDTH_64B                1
#define VMCS_FIELD_WIDTH_32B                2
#define VMCS_FIELD_WIDTH_NATURAL            3

typedef union cpuid_values_field_code_u
{
    struct
    {
        uint16_t subleaf           : 7;
        uint16_t subleaf_na        : 1;
        uint16_t leaf              : 7;
        uint16_t leaf_bit31        : 1;
    };
    uint16_t raw;
} cpuid_values_field_code_t;
tdx_static_assert(sizeof(cpuid_values_field_code_t) == 2, cpuid_values_field_code_t);

typedef union md_field_id_u
{
    struct
    {
        union
        {
            struct
            {
                uint32_t field_code : 24;
                uint32_t reserved_0 : 8;
            }; // default field code

            struct
            {
                uint32_t element     : 1;  // 0
                uint32_t subleaf     : 7;  // 1-7
                uint32_t subleaf_na  : 1;  // 8
                uint32_t leaf        : 7;  // 9-15
                uint32_t leaf_bit31  : 1;  // 16
                uint32_t reserved    : 15; // 17-31
            } cpuid_field_code;
        };

        struct
        {
            uint32_t element_size_code      : 2;    // Bits 33:32
            uint32_t last_element_in_field  : 4;    // Bits 37:34
            uint32_t last_field_in_sequence : 9;    // Bits 46:38
            uint32_t reserved_1             : 3;    // Bits 49:47
            uint32_t inc_size               : 1;    // Bit 50
            uint32_t reserved_2             : 1;    // Bit 51
            uint32_t context_code           : 3;    // Bits 54:52
            uint32_t reserved_3             : 1;    // Bit 55
            uint32_t class_code             : 6;    // Bits 61:56
            uint32_t reserved_4             : 1;    // Bit 62
            uint32_t ignored                : 1;    // Bit 63
        };
    };
    uint64_t raw;
} md_field_id_t;
tdx_static_assert(sizeof(md_field_id_t) == 8, md_field_id_t);

/**
 * CPUID configurations
 */

typedef union
{
    struct
    {
        uint32_t leaf;     //0..31
        uint32_t subleaf;  //32..63
    };
    uint64_t raw;
} cpuid_config_leaf_subleaf_t;

typedef union
{
    struct
    {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    };
    struct
    {
        uint64_t low;
        uint64_t high;
    };
    uint32_t values[4];
} cpuid_config_return_values_t;
tdx_static_assert(sizeof(cpuid_config_return_values_t) == 16, cpuid_config_return_values_t);

typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;
    cpuid_config_return_values_t values;
} cpuid_config_t;
tdx_static_assert(sizeof(cpuid_config_t) == 24, cpuid_config_t);



/**
 * @struct td_param_attributes_t
 *
 * @brief TD attributes.
 *
 * The value set in this field must comply with ATTRIBUTES_FIXED0 and ATTRIBUTES_FIXED1 enumerated by TDSYSINFO
 */
typedef union td_param_attributes_s {
    struct
    {
        uint64_t debug           : 1;   // Bit 0
        uint64_t reserved_tud    : 3;   // Bits 3:1
        uint64_t tup             : 2;   // Bits 5:4
        uint64_t pmt_prof        : 1;   // Bits 6
        uint64_t reserved_tup2   : 9;   // Bits 15:7
        uint64_t icssd           : 1;   // Bit 16
        uint64_t servtdext       : 1;   // Bit 17
        uint64_t reserved_p      : 5;   // Bits 22:18
        uint64_t reserved_n      : 4;   // Bits 26:23
        uint64_t lass            : 1;   // Bit 27
        uint64_t sept_ve_disable : 1;   // Bit 28 - disable #VE on pending page access
        uint64_t migratable      : 1;   // Bit 29
        uint64_t pks             : 1;   // Bit 30
        uint64_t kl              : 1;   // Bit 31
        uint64_t reserved_other  : 30;  // Bits 62:32
        uint64_t tpa             : 1;   // Bit 62
        uint64_t perfmon         : 1;   // Bit 63
    };
    uint64_t raw;
} td_param_attributes_t;
tdx_static_assert(sizeof(td_param_attributes_t) == 8, td_param_attributes_t);


/**
 * @struct eptp_controls_t
 *
 * @brief Control bits of EPTP, copied to each TD VMCS on TDHVPINIT
 */
typedef union eptp_controls_s {
    struct
    {
        uint64_t ept_ps_mt          : 3;   // Bits 0-2
        uint64_t ept_pwl            : 3;   // 1 less than the EPT page-walk length
        uint64_t enable_ad_bits     : 1;
        uint64_t enable_sss_control : 1;
        uint64_t reserved_0         : 4;
        uint64_t base_pa            : 40; // Root Secure-EPT page address
        uint64_t reserved_1         : 12;
    };
    uint64_t raw;
} eptp_controls_t;
tdx_static_assert(sizeof(eptp_controls_t) == 8, eptp_controls_t);

/**
 * @struct config_flags_t
 *
 * @brief Non-measured TD-scope execution controls.
 *
 * Most fields are copied to each TD VMCS TSC-offset execution control on TDHVPINIT.
 */
typedef union config_flags_s {
    struct
    {
        uint64_t
        gpaw                : 1,  /**< TD-scope Guest Physical Address Width execution control. */
        flexible_pending_ve : 1,  /**< Controls the guest TD’s ability to change the PENDING page access behavior */
        no_rbp_mod          : 1,  /**< Controls whether RBP value can be modified by TDG.VP.VMCALL and TDH.VP.ENTER. */
        maxpa_virt          : 1,  /**< Controls MAXPA Virtualization. */
        maxgpa_virt         : 1,  /**< Controls MAXGPA Virtualization. */
        tdx_connect         : 1,  /**< Enables TDX Connect for the current TD. */
        page_release        : 1,  /**< Enables TDG.MEM.PAGE.RELEASE for the current TD. */
        sealing             : 1,  /**< Enables TDG.MR.KEY.GET for the current TD. */
        reserved            : 56; /**< Must be 0. */
    };
    uint64_t raw;
} config_flags_t;
tdx_static_assert(sizeof(config_flags_t) == 8, config_flags_t);


#define SIZE_OF_TD_PARAMS_IN_BYTES     1024
#define TD_PARAMS_ALIGN_IN_BYTES       1024
#define SIZE_OF_SHA384_HASH_IN_QWORDS  6
#define SIZE_OF_SHA256_HASH_IN_QWORDS  4

#define TD_PARAMS_RESERVED0_SIZE       4

#define TD_PARAMS_RESERVED1_SIZE       38

#define TD_PARAMS_RESERVED2_SIZE       24

#define TD_PARAMS_RESERVED3_SIZE       (768 - (sizeof(cpuid_config_return_values_t) * MAX_NUM_CPUID_CONFIG))

/**
 * @struct td_params_t
 *
 * @brief TD_PARAMS is provided as an input to TDHMNGINIT, and some of its fields are included in the TD report.
 *
 * The format of this structure is valid for a specific MAJOR_VERSION of the TDX-SEAM module,
 * as reported by TDSYSINFO.
 */
typedef struct PACKED td_params_s
{
    td_param_attributes_t        attributes;
    /**
     * Extended Features Available Mask.
     * Indicates the extended state features allowed for the TD.
     * XFAM’s format is the same as XCR0 and IA32_XSS MSR
     */
    uint64_t                     xfam;
    uint16_t                     max_vcpus; /**< Maximum number of VCPUs */
    uint8_t                      num_l2_vms;

    struct
    {
        uint8_t  ia32_arch_cap : 1;   // Bit 0
        uint8_t  reserved_0    : 7;   // Bits 7:1
    } msr_config_ctls;

    uint8_t                      reserved_0[TD_PARAMS_RESERVED0_SIZE]; /**< Must be 0 */
    eptp_controls_t              eptp_controls;
    config_flags_t               config_flags;


    uint16_t                     tsc_frequency;

    uint8_t                      reserved_1[TD_PARAMS_RESERVED1_SIZE]; /**< Must be 0 */

    /**
     * Software defined ID for additional configuration for the SW in the TD
     */
    measurement_t                mr_config_id;
    /**
     * Software defined ID for TD’s owner
     */
    measurement_t                mr_owner;
    /**
     * Software defined ID for TD’s owner configuration
     */
    measurement_t                mr_owner_config;

    uint64_t                     ia32_arch_capabilities_config;

    uint8_t                      reserved_2[TD_PARAMS_RESERVED2_SIZE]; /**< Must be 0 */

    /**
     * CPUID leaves/sub-leaves configuration.
     * The number and order of entries must be equal to
     * the number and order of configurable CPUID leaves/sub-leaves reported by TDSYSINFO.
     * Note that the leaf and sub-leaf numbers are implicit.
     * Only bits that have been reported as 1 by TDSYSINFO may be set to 1.
     */
    cpuid_config_return_values_t cpuid_config_vals[MAX_NUM_CPUID_CONFIG];

    uint8_t                      reserved_3[TD_PARAMS_RESERVED3_SIZE];
} td_params_t;
tdx_static_assert(sizeof(td_params_t) == SIZE_OF_TD_PARAMS_IN_BYTES, td_params_t);



/**
 * @struct cmr_info_entry_t
 *
 * @brief CMR_INFO provides information about a Convertible Memory Range (CMR).
 *
 * As configured by BIOS and verified and stored securely by MCHECK.
 *
 */
typedef struct PACKED cmr_info_entry_s
{
    /**
     * Base address of the CMR.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     */
    uint64_t  cmr_base;
    /**
     * Size of the CMR, in bytes.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     * A value of 0 indicates a null entry.
     */
    uint64_t  cmr_size;
} cmr_info_entry_t;
tdx_static_assert(sizeof(cmr_info_entry_t) == 16, cmr_info_entry_t);

typedef union
{
    struct
    {
        uint32_t rsvd :31, debug_module :1;
    };
    uint32_t raw;
} tdsysinfo_attributes_t;


#define SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES      1024
#define OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO     32
#define OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO    48
#define OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO 64

/**
 * @struct td_sys_info_t
 *
 * @brief TDSYSINFO_STRUCT provides enumeration information about the TDX-SEAM module.
 *
 * It is an output of the SEAMCALL(TDSYSINFO) leaf function.
 *
 */
typedef struct PACKED td_sys_info_s
{
    /**
     * TDX Module Info
     */
    tdsysinfo_attributes_t attributes;
    uint32_t vendor_id; /**< 0x8086 for Intel */
    uint32_t build_date;
    uint16_t build_num;
    uint16_t minor_version;
    uint16_t major_version;
    uint8_t  sys_rd;
    uint8_t reserved_0[13]; /**< Must be 0 */

    /**
     * Memory Info
     */
    uint16_t max_tdmrs; /**< The maximum number of TDMRs supported. */
    uint16_t max_reserved_per_tdmr; /**< The maximum number of reserved areas per TDMR. */
    uint16_t pamt_entry_size; /**< The number of bytes that need to be reserved for the three PAMT areas. */
    uint8_t reserved_1[10]; /**< Must be 0 */

    /**
     * Control Struct Info
     */
    uint16_t tdcs_base_size; /**< Base value for the number of bytes required to hold TDCS. */
    uint8_t reserved_2[2]; /**< Must be 0 */
    uint16_t tdvps_base_size; /**< Base value for the number of bytes required to hold TDVPS. */
    /**
     * A value of 1 indicates that additional TDVPS bytes are required to hold extended state,
     * per the TD’s XFAM.
     * The host VMM can calculate the size using CPUID.0D.01.EBX.
     * A value of 0 indicates that TDVPS_BASE_SIZE already includes the maximum supported extended state.
     */
    bool_t tdvps_xfam_dependent_size;
    uint8_t reserved_3[9]; /**< Must be 0 */

    /**
     * TD Capabilities
     */
    uint64_t attributes_fixed0; /**< If bit X is 0 in ATTRIBUTES_FIXED0, it must be 0 in any TD’s ATTRIBUTES. */
    uint64_t attributes_fixed1; /**< If bit X is 1 in ATTRIBUTES_FIXED1, it must be 1 in any TD’s ATTRIBUTES. */
    uint64_t xfam_fixed0; /**< If bit X is 0 in XFAM_FIXED0, it must be 0 in any TD’s XFAM. */
    uint64_t xfam_fixed1; /**< If bit X is 1 in XFAM_FIXED1, it must be 1 in any TD’s XFAM. */

    uint8_t reserved_4[32]; /**< Must be 0 */

    uint32_t num_cpuid_config;
    cpuid_config_t cpuid_config_list[MAX_NUM_CPUID_CONFIG];
    uint8_t reserved_5[892 - (sizeof(cpuid_config_t) * MAX_NUM_CPUID_CONFIG)];
} td_sys_info_t;

tdx_static_assert(offsetof(td_sys_info_t, max_tdmrs) == OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, tdcs_base_size) == OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, attributes_fixed0) == OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(sizeof(td_sys_info_t) == SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES, td_sys_info_t_incorrect_struct_size);


/**
 * @struct td_gpaw_t
 *
 * @brief Output info for TDGVPINFO API calls.
 */
typedef union td_gpaw_s {
    struct
    {
        uint64_t
            /**
             * The effective GPA width (in bits) for this TD (don’t confuse with MAXPA).
             * SHARED bit is at GPA bit GPAW-1.
             */
            gpaw         : 6,
            reserved     : 58;  /**< Reserved, always 0 */
    };
    uint64_t raw;
} td_gpaw_t;
tdx_static_assert(sizeof(td_gpaw_t) == 8, td_gpaw_t);


/**
 * @struct td_num_of_vcpus_t
 *
 * @brief Output info for TDGVPINFO API calls.
 */
typedef union td_num_of_vcpus_s
{
    struct
    {
        uint64_t
            num_vcpus     : 32,  /**< Number of Virtual CPUs that are usable, i.e. either active or ready */
            max_vcpus     : 32;  /**< TD's maximum number of Virtual CPUs (provided as input to TDHMNGINIT) */
    };
    uint64_t raw;
} td_num_of_vcpus_t;
tdx_static_assert(sizeof(td_num_of_vcpus_t) == 8, td_num_of_vcpus_t);


/**
 * @struct tdg_commands_available_t
 *
 * @brief Output info for TDGVPINFO in R10
 */
typedef union tdg_commands_available_u
{
    struct
    {
        uint64_t tdg_sys_rd_available : 1;
        uint64_t reserved : 63;
    };
    uint64_t raw;
} tdg_commands_available_t;
tdx_static_assert(sizeof(tdg_commands_available_t) == 8, tdg_commands_available_t);

#define TDX_REPORT_TYPE                   0x81
#define TDX_REPORT_SUBTYPE                0
#define TDX_REPORT_VERSION_NO_SERVTDS     0
#define TDX_REPORT_VERSION_WITH_SERVTDS   1
#define TDX_REPORT_VERSION_WITH_UUID_VMID 3

/**
 * @struct td_report_type_s
 *
 * @brief REPORTTYPE indicates the reported Trusted Execution Environment (TEE) type, sub-type and version.
 */
typedef union PACKED td_report_type_s
{
    struct
    {
        /**
         * Trusted Execution Environment (TEE) Type:
         *      0x00:   SGX
         *      0x7F-0x01:  Reserved (TEE implemented by CPU)
         *      0x80:   Reserved (TEE implemented by SEAM module)
         *      0x81:   TDX
         *      0xFF-0x82:  Reserved (TEE implemented by SEAM module)
         *
         */
        uint8_t type;
        uint8_t subtype; /**< TYPE-specific subtype */
        uint8_t version; /**< TYPE-specific version. */
        uint8_t reserved; /**< Reserved - must be 0 - checked by SEAMOPS  */
    };
    uint32_t raw;
} td_report_type_t;
tdx_static_assert(sizeof(td_report_type_t) == 4, td_report_type_t);


#define CPUSVN_SIZE                       16 /**< CPUSVN is a 16B Security Version Number of the CPU. */
#define SIZE_OF_REPORTDATA_IN_BYTES       64
#define SIZE_OF_REPORTMAC_STRUCT_IN_BYTES 256

/**
 * @struct report_mac_struct_s
 *
 * @brief REPORTMACSTRUCT is common to all TEEs (SGX and TDX).
 */
typedef struct PACKED report_mac_struct_s
{
    td_report_type_t  report_type; /**< Type Header Structure */
    uint8_t           reserved_0[12]; /**< Must be 0 */
    uint8_t           cpusvn[CPUSVN_SIZE]; /**< CPU SVN */
    /**
     * SHA384 of TEETCBINFO for TEEs implemented using a SEAM
     */
    uint64_t          tee_tcb_info_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    /**
     * SHA384 of TEEINFO, which is a TEE-specific info structure (TDINFO or SGXINFO), or 0 if no TEE is represented
     */
    uint64_t          tee_info_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    /**
     * A set of data used for communication between the caller and the target.
     */
    uint8_t           report_data[SIZE_OF_REPORTDATA_IN_BYTES];
    uint8_t           reserved_1[32];
    uint64_t          mac[SIZE_OF_SHA256_HASH_IN_QWORDS]; /**< The MAC over the REPORTMACSTRUCT with model-specific MAC */
} report_mac_struct_t;
tdx_static_assert(sizeof(report_mac_struct_t) == SIZE_OF_REPORTMAC_STRUCT_IN_BYTES, report_mac_struct_t);


#define SIZE_OF_TEE_TCB_SVN_IN_BYTES         16
#define SIZE_OF_TEE_TCB_INFO_STRUCT_IN_BYTES 239
#define SIZE_OF_TEE_TCB_SVN_STRUCT_IN_BYTES 16

/**
 * @struct tee_tcb_svn_t
 *
 * @brief
 */
typedef struct PACKED tee_tcb_svn_s
{
    uint8_t        tdx_module_svn_minor;
    uint8_t        tdx_module_svn_major;
    uint8_t        seam_last_patch_svn;
    uint8_t        reserved[13];
} tee_tcb_svn_t;
tdx_static_assert(sizeof(tee_tcb_svn_t) == SIZE_OF_TEE_TCB_SVN_STRUCT_IN_BYTES, tee_tcb_svn_t);

/**
 * @struct tee_tcb_info_t
 *
 * @brief
 */
typedef struct PACKED tee_tcb_info_s
{
    /**
     * Indicates TEE_TCB_INFO fields which are valid.
     * - 1 in the i-th significant bit reflects that the field starting at offset (8 * i)
     * - 0 in the i-th significant bit reflects that either no field starts at offset (8 * i)
     *   or that field is not populated and is set to zero.
     */
    uint64_t       valid;
    uint8_t        tee_tcb_svn[SIZE_OF_TEE_TCB_SVN_IN_BYTES];  /**< TEE_TCB_SVN Array */
    measurement_t  mr_seam;  /**< Measurement of the SEAM module */
    /**
     * Measurement of SEAM module signer if non-intel SEAM module was loaded
     */
    measurement_t  mr_signer_seam;
    uint64_t       attributes;  /**< Additional configuration ATTRIBUTES if non-intel SEAM module was loaded */
    uint8_t        tee_tcb_svn2[SIZE_OF_TEE_TCB_SVN_IN_BYTES];
    uint8_t        reserved[95];  /**< Must be 0 */
} tee_tcb_info_t;
tdx_static_assert(sizeof(tee_tcb_info_t) == SIZE_OF_TEE_TCB_INFO_STRUCT_IN_BYTES, tee_tcb_info_t);


#define NUM_OF_RTMRS                    4
#define SIZE_OF_TD_INFO_STRUCT_IN_BYTES 512

#define SERVTD_HASH_VALID_BIT 0x0
#define TD_UUID_VALID_BIT     0x8
#define VMID_VALID_BIT        0x9

/**
 * @struct td_info_s
 *
 * @brief TDINFO_STRUCT is the TDX-specific TEEINFO part of TDGMRREPORT.
 *
 * It contains the measurements and initial configuration of the TD that was locked at initialization,
 * and a set of measurement registers that are run-time extendible.
 * These values are copied from the TDCS by the TDGMRREPORT function.
 */
typedef struct PACKED td_info_s
{
    uint64_t       attributes; /**< TD’s ATTRIBUTES */
    uint64_t       xfam; /**< TD’s XFAM**/
    measurement_t  mr_td; /**< Measurement of the initial contents of the TD */
    /**
     * 48 Software defined ID for additional configuration for the software in the TD
     */
    measurement_t  mr_config_id;
    measurement_t  mr_owner; /**< Software defined ID for TD’s owner */
    /**
     * Software defined ID for owner-defined configuration of the guest TD,
     * e.g., specific to the workload rather than the runtime or OS.
     */
    measurement_t  mr_owner_config;
    measurement_t  rtmr[NUM_OF_RTMRS]; /**<  Array of NUM_RTMRS runtime extendable measurement registers */

    measurement_t  servtd_hash;
    uint256_t      tdid256;
    uint8_t        reserved0[24];
    uint8_t        vmid;
    uint8_t        reserved1[3];
    uint32_t       valid;
} td_info_t;
tdx_static_assert(sizeof(td_info_t) == SIZE_OF_TD_INFO_STRUCT_IN_BYTES, td_info_t);


#define SIZE_OF_TD_REPORT_STRUCT_IN_BYTES 1024

/**
 * @struct td_report_t
 *
 * @brief TDREPORT_STRUCT is the output of the TDGMRREPORT function.
 *
 * If is composed of a generic MAC structure, a SEAMINFO structure and
 * a TDX-specific TEE info structure.
 */
typedef struct PACKED td_report_s
{
    report_mac_struct_t  report_mac_struct; /**< REPORTMACSTRUCT for the TDGMRREPORT */
    /**
     * Additional attestable elements in the TD’s TCB not reflected in the REPORTMACSTRUCT.CPUSVN.
     * Includes the SEAM measurements.
     */
    tee_tcb_info_t       tee_tcb_info;
    uint8_t              reserved[17];
    td_info_t            td_info; /**< TD’s attestable properties */
} td_report_t;
tdx_static_assert(sizeof(td_report_t) == SIZE_OF_TD_REPORT_STRUCT_IN_BYTES, td_report_t);


#define SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES 64

/**
 * @struct td_report_data_t
 *
 * @brief TDREPORTDATA is a set of data used for communication between the caller and the target of TDGMRREPORT
 *
 */
typedef struct PACKED td_report_data_s
{
    uint8_t              data[SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES];
} td_report_data_t;
tdx_static_assert(sizeof(td_report_data_t) == SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES, td_report_data_t);


#define TDH_PHYMEM_CACHEWB_START_CMD  0
#define TDH_PHYMEM_CACHEWB_RESUME_CMD 1

typedef uint64_t api_error_code_e;

typedef union api_error_code_u
{
    struct
    {
        union
        {
            uint32_t operand;
            uint32_t details_l2;
            struct
            {
                uint16_t details_l2_low;
                uint16_t details_l2_high;
            };
        };
        uint32_t details_l1               : 8,
                 clas                     : 8,
                 reserved                 : 12,
                 host_recoverability_hint : 1, // 60
                 fatal                    : 1, // 61
                 non_recoverable          : 1, // 62
                 error                    : 1; // 63
    };

    struct
    {
        uint64_t info_0 : 8;
        uint64_t info_1 : 8;
        uint64_t info_2 : 8;
        uint64_t info_3 : 8;
        uint64_t rsrvd  : 32;
    };

    uint64_t raw;
} api_error_code_t;
tdx_static_assert(sizeof(api_error_code_t) == 8, api_error_code_t);

typedef uint64_t api_error_type;

_STATIC_INLINE_ api_error_type api_error_with_operand_id(api_error_type error, uint64_t operand_id)
{
    api_error_code_t error_code = {.raw = error};
    error_code.operand = (uint32_t)operand_id;
    return error_code.raw;
}

_STATIC_INLINE_ api_error_type api_error_with_operand_id_fatal(api_error_type error, uint64_t operand_id)
{
    api_error_code_t error_code = {.raw = error};
    error_code.operand = (uint32_t)operand_id;
    error_code.fatal = 1;
    return error_code.raw;
}

_STATIC_INLINE_ api_error_type api_error_with_l2_details(api_error_type error, uint16_t details_l2_high,
                                                         uint16_t details_l2_low)
{
    api_error_code_t error_code = {.raw = error};
    error_code.details_l2_high = details_l2_high;
    error_code.details_l2_low  = details_l2_low;
    return error_code.raw;
}

_STATIC_INLINE_ api_error_type api_error_with_multiple_info(api_error_type error, uint8_t info_0,
                                                            uint8_t info_1, uint8_t info_2, uint8_t info_3)
{
    api_error_code_t error_code = {.raw = error};
    error_code.info_0 = (uint8_t)info_0;
    error_code.info_1 = (uint8_t)info_1;
    error_code.info_2 = (uint8_t)info_2;
    error_code.info_3 = (uint8_t)info_3;

    return error_code.raw;
}

_STATIC_INLINE_ api_error_type api_error_fatal(api_error_type error)
{
    api_error_code_t error_code;

    error_code.raw = (uint64_t)error;
    error_code.fatal = 1;

    return error_code.raw;
}

#define MAX_RESERVED_AREAS 16U

#define TDMR_INFO_ENTRY_ALIGNMENT              8

/**
 * @struct tdmr_info_entry_t
 *
 * @brief TDMR_INFO provides information about a TDMR and its associated PAMT
 *
 * An array of TDMR_INFO entries is passed as input to SEAMCALL(TDHSYSCONFIG) leaf function.
 *
 * - The TDMRs must be sorted from the lowest base address to the highest base address,
 *   and must not overlap with each other.
 *
 * - Within each TDMR entry, all reserved areas must be sorted from the lowest offset to the highest offset,
 *   and must not overlap with each other.
 *
 * - All TDMRs and PAMTs must be contained within CMRs.
 *
 * - A PAMT area must not overlap with another PAMT area (associated with any TDMR), and must not
 *   overlap with non-reserved areas of any TDMR. PAMT areas may reside within reserved areas of TDMRs.
 *
 */
typedef struct ALIGN(TDMR_INFO_ENTRY_ALIGNMENT) PACKED tdmr_info_entry_s
{
    uint64_t tdmr_base;    /**< Base address of the TDMR (HKID bits must be 0). 1GB aligned. */
    uint64_t tdmr_size;    /**< Size of the CMR, in bytes. 1GB aligned. */
    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_1g_size; /**< Size of the PAMT_1G range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_2m_size; /**< Size of the PAMT_2M range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_4k_size; /**< Size of the PAMT_4K range associated with the above TDMR. 4K aligned. */

    struct
    {
        // NOTE: this struct is un-reachable for checking natural alignment, take it under consideration if/when adding more fields to the struct.
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

} tdmr_info_entry_t;

#define TDMR_INFO_ENTRY_PTR_ARRAY_ALIGNMENT              512

#define TD_EXTENDED_STATE_NOT_PASSED_TO_VMM_AND_BACK     0ULL
#define TD_XMM_STATE_PASSED_TO_VMM_AND_BACK              2ULL



#define MAX_CMR             32
// check (MAX_CMRS * cmr_info_entry) equals 512B
tdx_static_assert((MAX_CMR * sizeof(cmr_info_entry_t)) == 512, MAX_CMR);

typedef union tdaccept_vmx_eeq_info_u
{
    struct
    {
        // Requested SEPT level
        uint32_t    req_sept_level   : 3;
        // Level in SEPT in which the error was detected
        uint32_t    err_sept_level   : 3;
        // TDX SEPT state of the entry in which the error was detected
        uint32_t    err_sept_state   : 8;
        // TDX SEPT state of the entry in which the error was detected
        uint32_t    err_sept_is_leaf : 1;
        uint32_t    rsvd_0           : 5;
        // VM index for L2 violation errors
        uint32_t    vm_index         : 2;
        uint32_t    rsvd_1           : 10;
    };

    uint32_t raw;
} tdaccept_vmx_eeq_info_t;
tdx_static_assert(sizeof(tdaccept_vmx_eeq_info_t) == 4, tdaccept_vmx_eeq_info_t);

#define NUM_CACHELINES_IN_PAGE 64
#define NUM_SEPT_ENTRIES_IN_CACHELINE 8
#define VCPU_NO_LP ((uint32_t)~0)

typedef union vcpu_and_flags_u
{
    struct
    {
        uint64_t reserved_0               : 12;  // Bits 11:0
        uint64_t tdvpra_hpa_51_12         : 40;  // Bits 51:12
        uint64_t host_recoverability_hint : 1;   // Bit 52
        uint64_t resume_l1                : 1;   // Bit 53
        uint64_t reserved_1               : 10;  // Bits 63:54
    };
    uint64_t raw;
} vcpu_and_flags_t;
tdx_static_assert(sizeof(vcpu_and_flags_t) == 8, vcpu_and_flags_t);

typedef enum gpa_list_format_e
{
    GPA_LIST_FORMAT_GPA_ONLY      = 0,
    GPA_LIST_FORMAT_GPA_AND_ATTR  = 1,
    GPA_LIST_FORMAT_LIST_OF_LISTS = 2,
    // Compute MAX based on enabled features
    GPA_LIST_FORMAT_MAX = 2
} gpa_list_info_format_t;

typedef union gpa_list_info_u
{
    struct
    {
        uint64_t format         : 3;
        uint64_t first_entry    : 9;
        uint64_t hpa            : 40;
        uint64_t reserved_0     : 3;
        uint64_t last_entry     : 9;
    };
    uint64_t raw;
} gpa_list_info_t;
tdx_static_assert(sizeof(gpa_list_info_t) == 8, gpa_list_info_t);

typedef union gpa_list_entry_s
{
    struct
    {
        uint64_t level          : 2;   // Bits 1:0  :  Mapping level
        uint64_t pending        : 1;   // Bit 2     :  Page is pending
        uint64_t state          : 2;   // Bits 4:3
        uint64_t reserved_0     : 2;   // Bits 6:5
        uint64_t l2_map         : 3;   // Bits 9:7  :  L2 mapping flags
        uint64_t mig_type       : 2;   // Bits 11:10:  Migration type, see above
        uint64_t gpa            : 40;  // Bits 51:12
        uint64_t operation      : 2;   // Bits 53:52:  Operation, see above
        uint64_t reserved_1     : 2;   // Bits 55:54
        uint64_t status         : 5;   // Bits 56:52:  Status, see above
        uint64_t reserved_2     : 3;   // Bits 63:61
    };
    uint64_t raw;
} gpa_list_entry_t;
tdx_static_assert(sizeof(gpa_list_entry_t) == 8, gpa_list_entry_t);

typedef enum gpa_list_entry_operation_e
{
    GPA_ENTRY_OP_NOP             = 0b00,   // 0
    GPA_ENTRY_OP_MIGRATE         = 0b01,   // 1
    GPA_ENTRY_OP_CANCEL          = 0b10,   // 2
    GPA_ENTRY_OP_REMIGRATE       = 0b11,   // 3
    GPA_ENTRY_OP_EXPORT_NOP_MASK = 0b01

    ,GPA_ENTRY_OP_EXPORT          = 0b01,   // 1
    GPA_ENTRY_OP_NOP2            = 0b10,   // 2
    GPA_ENTRY_OP_NOP3            = 0b11,   // 3
} gpa_list_entry_operation_t;

// Values of MIG_TYPE
typedef enum gpa_list_entry_mig_type_e
{
    GPA_ENTRY_MIG_TYPE_PAGE_4K  = 0
} gpa_list_entry_mig_type_t;

// Value of STATUS
typedef enum gpa_list_entry_status_e
{
    GPA_ENTRY_STATUS_SUCCESS                        = 0,
    GPA_ENTRY_STATUS_SKIPPED                        = 1,
    GPA_ENTRY_STATUS_SEPT_WALK_FAILED               = 2,
    GPA_ENTRY_STATUS_SEPT_ENTRY_BUSY_HOST_PRIORITY  = 3,
    GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT     = 4,
    GPA_ENTRY_STATUS_TLB_TRACKING_NOT_DONE          = 5,
    GPA_ENTRY_STATUS_OP_STATE_INCORRECT             = 6,
    GPA_ENTRY_STATUS_MIGRATED_IN_CURRENT_EPOCH      = 7,
    GPA_ENTRY_STATUS_MIG_BUFFER_NOT_AVAILABLE       = 8,
    GPA_ENTRY_STATUS_NEW_PAGE_NOT_AVAILABLE         = 9,
    GPA_ENTRY_STATUS_INVALID_PAGE_MAC               = 10,
    GPA_ENTRY_STATUS_DISALLOWED_IMPORT_OVER_REMOVED = 11,
    GPA_ENTRY_STATUS_TD_PAGE_BUSY_HOST_PRIORITY     = 12,
    GPA_ENTRY_STATUS_L2_SEPT_WALK_FAILED            = 13,
    GPA_ENTRY_STATUS_ATTR_LIST_ENTRY_INVALID        = 14,
    GPA_ENTRY_STATUS_GPA_LIST_ENTRY_INVALID         = 15,
    GPA_ENTRY_STATUS_INVALID_MIGRATION_BUFFER_HPA   = 16,
    GPA_ENTRY_STATUS_PAGE_DIRTY                     = 17
} gpa_list_entry_status_t;

#define NUM_TDX_FEATRUES        1   // Number of TDX_FEATURES entries

// First field that enumerates TDX features
typedef union tdx_features_enum0_u
{
    struct
    {
        uint64_t td_migration                      : 1;    // Bit      0
        uint64_t td_preserving                     : 1;    // Bit      1
        uint64_t service_td                        : 1;    // Bit      2
        uint64_t tdg_vp_rdwr                       : 1;    // Bit      3
        uint64_t relaxed_mem_mng_concurrency       : 1;    // Bit      4
        uint64_t cpuid_virt_guest_ctrl             : 1;    // Bit      5
        uint64_t tdx_io                            : 1;    // Bit      6
        uint64_t td_partitioning                   : 1;    // Bit      7
        uint64_t local_attestation                 : 1;    // Bit      8
        uint64_t td_entry_enhancements             : 1;    // Bit      9
        uint64_t host_priority_locks               : 1;    // Bit     10
        uint64_t config_ia32_arch_cap              : 1;    // Bit     11
        uint64_t hw_sealing                        : 1;    // Bit     12
        uint64_t reserved_1                        : 3;    // Bits 15:13
        uint64_t pending_ept_violation_v2          : 1;    // Bit     16
        uint64_t fms_config                        : 1;    // Bit     17
        uint64_t no_rbp_mod                        : 1;    // Bit     18
        uint64_t l2_tlb_invd_opt                   : 1;    // Bit     19
        uint64_t topology_enum                     : 1;    // Bit     20
        uint64_t partitioned_td_migration          : 1;    // Bit     21
        uint64_t reserved_2                        : 2;    // Bits 23:22
        uint64_t event_filtering                   : 1;    // Bit     24
        uint64_t icssd                             : 1;    // Bit     25
        uint64_t fixed_ctr12_prof                  : 1;    // Bit     26
        uint64_t maxpa_virt                        : 1;    // Bit     27
        uint64_t apx                               : 1;    // Bit     28
        uint64_t cpuid2_virt                       : 1;    // Bit     29
        uint64_t ve_reduction                      : 1;    // Bit     30
        uint64_t enhanced_event_filtering          : 1;    // Bit     31
        uint64_t tdx_connect_partitioning          : 1;    // Bit     32
        uint64_t maxgpa_virt                       : 1;    // Bit     33
        uint64_t reserved_5                        : 2;    // Bits 35:34
        uint64_t dynamic_pamt                      : 1;    // Bit     36
        uint64_t fatal_diagnostics                 : 1;    // Bit     37
        uint64_t page_release                      : 1;    // Bit     38
        uint64_t nrx                               : 1;    // Bit     39
        uint64_t enhanced_intr_state               : 1;    // Bit     40
        uint64_t non_blocking_export               : 1;    // Bit     41
        uint64_t perf_mask                         : 1;    // Bit     42
        uint64_t scan_export_restore               : 1;    // Bit     43
        uint64_t import_page_status                : 1;    // Bit     44
        uint64_t enhanced_intr_virtualization      : 1;    // Bit     45
        uint64_t ve_info_intr_state                : 1;    // Bit     46
        uint64_t update_compatibility              : 1;    // Bit     47
        uint64_t servtd_rebind                     : 1;    // Bit     48
        uint64_t tdid_vmid_reporting               : 1;    // Bit     49
        uint64_t reserved_6                        : 1;    // Bit     50
        uint64_t enhanced_demote_interruptibility  : 1;    // Bit     51
        uint64_t debug_ro_td_migration             : 1;    // Bit     52
        uint64_t sys_disable                       : 1;    // Bit     53
        uint64_t list_error_count                  : 1;    // Bit     54
        uint64_t reserved_7                        : 1;    // Bit     55
        uint64_t sealkey_128                       : 1;    // Bit     56
        uint64_t sealkey_256                       : 1;    // Bit     57
        uint64_t reserved_8                        : 6;    // Bits 63:58
    };
    uint64_t raw;
} tdx_features_enum0_t;
tdx_static_assert(sizeof(tdx_features_enum0_t) == 8, tdx_features_enum0_t);
/**
 * @struct gprs_state_t
 *
 * @brief Holds the state of the GPRs
 */

#define GPR_LIST_R9_INDEX           9

typedef union gprs_state_u
{
    struct
    {
        uint64_t rax;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rbx;
        uint64_t rsp;
        uint64_t rbp;
        uint64_t rsi;
        uint64_t rdi;
        uint64_t r8;
        uint64_t r9;
        uint64_t r10;
        uint64_t r11;
        uint64_t r12;
        uint64_t r13;
        uint64_t r14;
        uint64_t r15;
    };

    uint64_t gprs[16];
} gprs_state_t;

/**
 * @struct l2_enter_guest_state_t
 *
 * @brief Fixed-format L2 VCPU register list
 */
typedef union l2_enter_guest_state_u
{
    struct
    {
        gprs_state_t gpr_state;
        uint64_t rflags;
        uint64_t rip;
        uint64_t ssp;
        uint16_t interrupt_status;
    };
    struct
    {
        uint64_t gprs[16];
        uint8_t other_regs[26];
    };
} l2_enter_guest_state_t;

/**
 * @struct td_exit_qualification_t
 *
 * @brief TD exit information provided as an output of TDH.VP.ENTER
 */
typedef union td_exit_qualification_u
{
    struct
    {
        union
        {
            uint32_t exit_qualification;   // On async TD exit, lower 32 bits of the VMCS exit qualification
            struct                         // On sync TD exit, lower 32 bits or the mask passed to TDG.VP.VMCALL
            {
                uint16_t gpr_select;
                uint16_t xmm_select;
            };
        };

        uint16_t vm              : 2,   // Bits 33:32
                 reserved_0      : 14;  // Bits 47:34
        uint16_t reserved_1      : 15,  // Bits 62:48
                 imm_resume_hint : 1;   // Bit 63
    };

    uint64_t     raw;
} td_exit_qualification_t;
tdx_static_assert(sizeof(td_exit_qualification_t) == 8, td_exit_qualification_t);

/**
 * @struct l2_enter_seg_details_t
 *
 * @brief Segment details structure
 */
typedef union l2_enter_seg_details_u
{
    struct
    {
        uint16_t selector;
        uint16_t ar;
        uint32_t limit;
    };
    uint64_t raw;
} l2_enter_seg_details_t;
tdx_static_assert(sizeof(l2_enter_seg_details_t) == 8, l2_enter_seg_details_t);

typedef union l2_enter_additional_exit_info_u
{
    struct
    {
        uint64_t cpl           : 2;   // Bits 1:0
        uint64_t reserved      : 62;  // Bits 63:2
    };
    uint64_t raw;
} l2_enter_additional_exit_info_t;
tdx_static_assert(sizeof(l2_enter_additional_exit_info_t) == 8, l2_enter_additional_exit_info_t);

typedef union td_handle_and_flags_u
{
    struct
    {
        uint64_t allow_existing    : 1;  // Used for TDH.MEM.SEPT.ADD only

        uint64_t reserved_0        : 11; // Used for all relevant API's...
        uint64_t tdr_hpa_51_12     : 40;
        uint64_t reserved_1        : 12;
    };

    struct
    {
        uint64_t l2_sept_add_mode  : 1;  // Used for TDH.MEM.PAGE.DEMOTE only
        uint64_t _other_bits       : 63;
    };
    uint64_t raw;
} td_handle_and_flags_t;
tdx_static_assert(sizeof(td_handle_and_flags_t) == 8, td_handle_and_flags_t);


typedef union gpa_mapping_and_flags_u
{
    struct
    {
        uint64_t level          : 3;
        uint64_t reserved_11_3  : 9;
        uint64_t gpa            : 40;
        uint64_t reserved_61_52 : 10;
        uint64_t pending        : 1;
        uint64_t reserved_63    : 1;
    };
    uint64_t raw;
} gpa_mapping_and_flags_t;
tdx_static_assert(sizeof(gpa_mapping_and_flags_t) == 8, gpa_mapping_and_flags_t);

typedef union gpa_attr_single_vm_u
{
    struct
    {
        uint16_t r             : 1;   // Bit 0
        uint16_t w             : 1;   // Bit 1
        uint16_t xs            : 1;   // Bit 2
        uint16_t xu            : 1;   // Bit 3
        uint16_t vgp           : 1;   // Bit 4 - Verify Guest Paging
        uint16_t pwa           : 1;   // Bit 5 - Paging-Write Access
        uint16_t sss           : 1;   // Bit 6 - Supervisor Shadow Stack
        uint16_t sve           : 1;   // Bit 7 - Suppress #VE
        uint16_t reserved_14_8 : 7;   // Bits 14:8
        uint16_t valid         : 1;   // Bit 15
    };
    uint16_t raw;
} gpa_attr_single_vm_t;
tdx_static_assert(sizeof(gpa_attr_single_vm_t) == 2, gpa_attr_single_vm_t);

#define GUEST_L2_GPA_ATTR_MASK                      (BITS(6,0) | BIT(15))

#define GPA_ATTR_VM_SIZE (4)
typedef union gpa_attr_u
{
    gpa_attr_single_vm_t attr_arr[GPA_ATTR_VM_SIZE];
    uint64_t raw;
} gpa_attr_t;
tdx_static_assert(sizeof(gpa_attr_t) == 8, gpa_attr_t);

typedef union gla_list_entry_u
{
    struct
    {
        uint64_t last_gla_index : 12;  // Bits 11:0:  Index of the last 4KB page to be processed
        uint64_t base_gla       : 52;  // Bits 63:12: Bits 63:12 of the guest linear address of the first 4KB page to be processed
    };
    uint64_t raw;
} gla_list_entry_t;
tdx_static_assert(sizeof(gla_list_entry_t) == 8, gla_list_entry_t);

#define PAGE_GLA_LIST_MAX_ENTRIES       512

typedef union gla_list_info_u
{
    struct
    {
        uint64_t first_entry    : 9;  // Bits 8:0:   Index of the first entry of the list to be processed
        uint64_t reserved_0     : 3;  // Bits 11:9
        uint64_t list_gpa       : 40; // Bits 51:12: Bits 51:12 of the guest physical address of the GLA list page, which must be a private GPA
        uint64_t num_entries    : 10; // Bits 61:52: Number of entries in the GLA list, must be between 0 through 512
        uint64_t reserved_1     : 2;  // Bits 63:62:
    };
    uint64_t raw;
} gla_list_info_t;
tdx_static_assert(sizeof(gla_list_info_t) == 8, gla_list_info_t);

typedef union exit_reason_and_ve_category_u
{
    struct
    {
        uint64_t exit_reason  : 32;
        uint64_t ve_category  :  8;
        uint64_t reserved     : 24;
    };
    uint64_t raw;
} exit_reason_and_ve_category_t;
tdx_static_assert(sizeof(exit_reason_and_ve_category_t) == 8, exit_reason_and_ve_category_t);

#define TDX_CONNECT_FEATURES_MASK (BIT(0) | BIT(7) | BIT(9) | BIT(12))

typedef union td_key_policy_u
{
    struct
    {
        uint64_t mrtd           : 1;  // Include MRTD
        uint64_t mrowner        : 1;  // Include MROWNER
        uint64_t mrconfigid     : 1;  // Include MRCONFIGID & CONFIGIDSVN
        uint64_t mrownerconfig  : 1;  // Include MROWNERCONFIG & OWNERCONFIGSVN
        uint64_t reserved_0     : 4;  // Must be 0
        uint64_t mrsigroot      : 1;  // Include MRSIGROOT
        uint64_t mrsigner       : 1;  // Include MRSIGNER
        uint64_t mrprodid       : 1;  // Include ISVPRODID & ISVSVN
        uint64_t reserved_1     : 21; // Must be 0
        uint64_t rtmr           : 16; // Include RTMR n
        uint64_t reserved_2     : 16; // Must be 0
    };

    uint64_t raw;
} td_key_policy_t;
tdx_static_assert(sizeof(td_key_policy_t) == 8, td_key_policy_t);

#define TD_KEY_REQUEST_ALIGNMENT_IN_BYTES 128
#define MR_KEY_ALIGNMENT_IN_BYTES 32
#define SIZE_OF_SALT_IN_BYTES 32

typedef struct PACKED td_key_request_s
{
    uint16_t              keyname;
    uint8_t               sw_keyname;
    uint8_t               keysize_bitmap;
    uint8_t               reserved_0[4];
    td_key_policy_t       tdkeypolicy;
    td_param_attributes_t attributes_mask;
    uint64_t              xfam_mask;
    uint8_t               cpusvn[CPUSVN_SIZE];
    tee_tcb_svn_t         tee_tcb_svn;
    uint16_t              isvsvn;
    uint16_t              mrconfigsvn;
    uint16_t              mrownerconfigsvn;
    uint8_t               salt[SIZE_OF_SALT_IN_BYTES];
    uint8_t               reserved_1[26];
} td_key_request_t;
tdx_static_assert(sizeof(td_key_request_t) == 128, td_key_request_t);

typedef struct PACKED tdgetkey_derivation_string_s
{
    uint16_t              keyname;
    uint8_t               sw_keyname;
    uint8_t               requestor;
    uint8_t               reserved_0[4];
    td_key_policy_t       keypolicy;
    td_param_attributes_t masked_attributes;
    uint64_t              attributes_mask;
    uint64_t              masked_xfam;
    uint64_t              xfam_mask;
    measurement_t         mrtd;
    measurement_t         mrconfig;
    measurement_t         mrowner;
    measurement_t         mrownerconfig;
    measurement_t         rtmr[NUM_OF_RTMRS];
    measurement_t         mrsigroot;
    measurement_t         mrsigner;
    uint128_t             isvprodid;
    uint16_t              isvsvn;
    uint16_t              mrconfigsvn;
    uint16_t              mrownerconfigsvn;
    uint8_t               reserved_1[10];
    measurement_t         servtd_hash;
    uint8_t               salt[SIZE_OF_SALT_IN_BYTES];
    uint8_t               reserved_2[64];
} tdgetkey_derivation_string_t;
tdx_static_assert(sizeof(tdgetkey_derivation_string_t) == 704, tdgetkey_derivation_string_t);

#define REQUESTOR_TYPE_MAX 0x3

typedef union requestor_info_u
{
    struct
    {
        uint64_t requestor      :  8; // Bits  7: 0
        uint64_t reserved       : 56; // Bits 63: 8
    };

    uint64_t raw;
} requestor_info_t;
tdx_static_assert(sizeof(requestor_info_t) == 8, requestor_info_t);

typedef union phymem_page_rdmd_pt_ret_u
{
    struct
    {
        uint64_t pt         : 4;
        uint64_t reserved   : 59;
        uint64_t non_leaf   : 1;
    };
    uint64_t raw;
} phymem_page_rdmd_pt_ret_t;
tdx_static_assert(sizeof(phymem_page_rdmd_pt_ret_t) == 8, phymem_page_rdmd_pt_ret_t);

#define TEE_MODEL_SIZE_IN_BYTES     12

typedef struct tee_model_struct_s
{
    uint16_t custom;
    uint16_t platform_id;
    uint32_t fmsp;
    uint32_t reserved;
} tee_model_struct_t;
tdx_static_assert(sizeof(tee_model_struct_t) == TEE_MODEL_SIZE_IN_BYTES, tee_model_struct_t);

#define SERVTD_EXT_STRUCY_SIZE_IN_BYTES     272

typedef struct servtd_ext_struct_s
{
    uint64_t init_servtd_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    uint64_t init_servtd_attr;
    uint8_t reserved_0[8];
    uint8_t init_cpusvn[CPUSVN_SIZE];
    uint8_t init_tee_tcb_svn[SIZE_OF_TEE_TCB_SVN_IN_BYTES];
    tee_model_struct_t init_tee_model;
    uint8_t reserved_1[4];
    uint64_t curr_servtd_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    uint64_t curr_servtd_attr;
    uint8_t reserved_2[8];
    uint8_t reserved_3[48]; // Reserved for Cascading hash of Audit Log.
    uint8_t reserved_4[48];

} servtd_ext_struct_t;
tdx_static_assert(sizeof(servtd_ext_struct_t) == SERVTD_EXT_STRUCY_SIZE_IN_BYTES, servtd_ext_struct_t);

#pragma pack(pop)


#endif // __TDX_API_DEFS_H_INCLUDED__
