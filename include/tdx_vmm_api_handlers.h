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
 * @file tdx_vmm_api_handelrs.h
 * @brief TDX VMM API Handelrs
 */
#ifndef __TDX_VMM_API_HANDLERS_H_INCLUDED__
#define __TDX_VMM_API_HANDLERS_H_INCLUDED__


#include "tdx_api_defs.h"
#include "helpers/service_td.h"

/**
 * @brief Add a 4KB private page to a TD.
 *
 * Page is mapped to the specified GPA,
 * filled with the given page image and encrypted using the TD ephemeral key,
 * and update the TD measurement with the page properties.
 *
 * @note
 *
 * @param gpa_page_info Guest physical address and level of to be mapped for the target page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param target_page_pa Host physical address of the target page to be added to the TD
 * @param source_page_pa Host physical address of the source page image
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_add(page_info_api_input_t gpa_page_info,
                           uint64_t tdr_pa,
                           uint64_t target_page_pa,
                           uint64_t source_page_pa);


/**
 * @brief Add and map a 4KB Secure EPT page to a TD.
 *
 * @note
 *
 * @param sept_level_and_gpa Level and to-be-mapped GPA of the Secure EPT page
 * @param target_tdr_and_flags Host physical address of the parent TDR page and additional flags
 * @param sept_page_pa Host physical address of the new Secure EPT page to be added to the TD
 * @param version Version of the API
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_add(page_info_api_input_t sept_level_and_gpa,
                                td_handle_and_flags_t target_tdr_and_flags,
                                uint64_t sept_page_pa,
                                uint64_t version);


/**
 * @brief Add a TDCX page to a TD.
 *
 * @note
 *
 * @param tdcx_pa The physical address of a page where TDCX will be added
 * @param tdr_pa The physical address of the owner TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_add_cx(uint64_t tdcx_pa, uint64_t tdr_pa);


/**
 * @brief Add a TDVPX page, as a child of a given TDVPR, to memory.
 *
 * @note
 *
 * @param tdcx_pa The physical address of a page where the TDCX page will be added
 * @param tdvpr_pa The physical address of a TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_addcx(uint64_t tdcx_pa, uint64_t tdvpr_pa);


/**
 * @brief Dynamically add a 4KB private page to an initialized TD, mapped to the specified GPAs.
 *
 * @note
 *
 * @param gpa_page_info Guest physical address and level of to be mapped for the target page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param target_page_pa Host physical address of the target page to be added to the TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_aug(page_info_api_input_t gpa_page_info,
                           uint64_t tdr_pa,
                           uint64_t target_page_pa);

/**
 * @brief Relocate a 4KB mapped page from its current host physical address to another.
 *
 * @note
 *
 * @param target_tdr_pa Host physical address of the target page to be added to the TD
 * @param tdr_pa Host physical address of the parent TDR page
 * @param source_page_pa Guest physical address of the private page to be relocated
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_relocate(uint64_t source_page_pa,
                                   uint64_t target_tdr_pa,
                                   uint64_t target_page_pa);

/**
 * @brief Block a TD private GPA range.
 *
 * Block a TD private GPA range, i.e., a Secure EPT page or a TD private page,
 * at any level (4KB, 2MB, 1GB, 512GB, 256TB etc.)
 * from creating new GPA-to-HPA address translations.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be blocked
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_range_block(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Configure the TD ephemeral private key on a single package.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_config(uint64_t tdr_pa);


/**
 * @brief Create a new guest TD and its TDR root page.
 *
 * @note
 *
 * @param target_tdr_pa The physical address of a page where TDR will be created
 * @param hkid The TD’s ephemeral private HKID
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_create(uint64_t target_tdr_pa, hkid_api_input_t hkid_info);


/**
 * @brief Create a guest TD VCPU and its root TDVPR page.
 *
 * @note
 *
 * @param target_tdvpr_pa The physical address of a page where TDVPR will be added
 * @param tdr_pa The physical address of the owner TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_create(uint64_t target_tdvpr_pa, uint64_t tdr_pa);


/**
 * @brief Read a TD-scope control structure field of a debuggable TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param field_code Field access code
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_rd(uint64_t target_tdr_pa, uint64_t requested_field_code, uint64_t version);


/**
 * @brief Read a 64b chunk from a debuggable guest TD private memory.
 *
 * @note
 *
 * @param aligned_page_pa The physical address of a naturally-aligned 64b chuck of a guest TD private page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_rd(uint64_t aligned_page_pa, uint64_t target_tdr_pa);


/**
 * @brief Write a TD-scope control structure field of a debuggable TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param field_code Field access code
 * @param data Data to write to the field
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_wr(uint64_t target_tdr_pa, uint64_t requested_field_code,
                          uint64_t wr_data, uint64_t wr_mask);


/**
 * @brief Write a 64b chunk to a debuggable guest TD private memory.
 *
 * @note
 *
 * @param aligned_page_pa The physical address of a naturally-aligned 64b chuck of a guest TD private page
 * @param data Data to write to memory
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_wr(uint64_t aligned_page_pa, uint64_t target_tdr_pa, uint64_t data);


/**
 * @brief Split a large (2MB or 1GB) private TD page into 512 small (4KB or 2MB respectively) pages.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be split
 * @param target_tdr_and_flags Host physical address of the parent TDR page and flags
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_demote(page_info_api_input_t page_info,
                              td_handle_and_flags_t target_tdr_and_flags,
                              uint64_t pamt_hpa0, uint64_t pamt_hpa1);


/**
 * @brief Enter TDX non-root operation.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of the TD VCPU’s TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_enter(uint64_t tdvpr_pa);


/**
 * @brief Extend the MRTD measurement register in the TDCS with the measurement of the indicated chunk of a TD page.
 *
 * @note
 *
 * @param page_gpa The GPA of the TD page chunk to be measured
 * @param tdr_pa The TDR page of the target TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mr_extend(uint64_t page_gpa, uint64_t tdr_pa);


/**
 * @brief Complete measurement of the initial TD contents and mark the as initialized.
 *
 * @note
 *
 * @param tdr_pa The physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mr_finalize(uint64_t tdr_pa);


/**
 * @brief Flush the address translation caches and cached TD VMCS associated with a TD VCPU,
 *        on the current logical processor.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_flush(uint64_t tdvpr_pa);


/**
 * @brief Verify that none of the TD’s VCPUs is associated with an LP.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_vpflushdone(uint64_t tdr_pa);


/**
 * @brief End the platform cache flush sequence and mark applicable HKIDs in KOT as free.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_freeid(uint64_t tdr_pa);


/**
 * @brief Initialize TD-scope control structures TDR and TDCS.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param td_params_pa The physical address of an input TD_PARAMS struct
 * @param event_filters_info_params HPA (including HKID) of an array of EVENT_FILTER entries
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_init(uint64_t tdr_pa, uint64_t td_params_pa, uint64_t event_filters_info_params);


/**
 * @brief Initialize the saved state of a TD VCPU.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param td_vcpu_rcx Initial value of the guest TD VCPU RCX
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_init(uint64_t tdvpr_pa, uint64_t td_vcpu_rcx);


/**
 * @brief Merge 512 consecutive small (4KB or 2MB) private TD pages into one large (2MB or 1GB respectively) page.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be merged
 * @param tdr_pa Host physical address of the parent TDR page
 * @param version API version
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_promote(page_info_api_input_t page_info, uint64_t tdr_pa, uint64_t version);


/**
 * @brief Read the metadata of a page in TDMR.
 *
 * @note
 *
 * @param tdmr_page_pa A physical address of a 4KB page in TDMR
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_rdmd(uint64_t tdmr_page_pa);


/**
 * @brief Read a Secure EPT entry.
 *
 * @note
 *
 * @param sept_page_info Level and GPA of SEPT entry to read
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_rd(page_info_api_input_t sept_page_info, uint64_t tdr_pa);


/**
 * @brief Read a TDVPS field.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param field_code  Field code
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_rd(uint64_t tdvpr_pa, md_field_id_t field_code, uint64_t version);


/**
 * @brief Reclaim all the HKIDs assigned to a TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_reclaimid(uint64_t tdr_pa);


/**
 * @brief Remove a physical 4KB, 2MB or 1GB TD-owned page
 *
 * Remove a TD private page, Secure EPT page or a control structure page from a TD.
 *
 * @note
 *
 * @param page_pa The physical address of a page to be reclaimed
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_reclaim(uint64_t page_pa);


/**
 * @brief Remove a GPA-mapped 4KB, 2MB or 1GB private page from a TD.
 *
 * @note
 *
 * @param page_info Level and GPA of the to-be-removed page
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_remove(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Remove an empty 4KB Secure EPT page from a TD.
 *
 * @note
 *
 * @param sept_page_info Level and GPA of the to-be-removed SEPT page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param version Version of the API
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_remove(page_info_api_input_t sept_page_info, uint64_t tdr_pa, uint64_t version);


/**
 * @brief Globally configure the TDX-SEAM module.
 *
 * @note
 *
 * @param tdmr_info_array_pa The physical address of an array of TDMR_INFO entries
 * @param num_of_tdmr_entries The number of TDMR_INFO entries in the about buffer
 * @param global_private_hkid TDX-SEAM global private HKID value
 * @param version
 * @param enabling_flags TDX module feature enabling flags, formatted similarly to TDX_FEATURES0
 * @param reserved_r10 must be zero
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_config(uint64_t tdmr_info_array_pa,
                              uint64_t num_of_tdmr_entries,
                              sys_config_options_t sysconfig_options,
                              uint8_t version,
                              uint64_t enabling_flags,
                              uint64_t reserved_r10);


/**
 * @brief Configure the TDX-SEAM global private key on the current package.
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_key_config(void);

/**
 * @brief Disable the TDX Module, reset its internal state and reclaim all memory resources that have been assigned to TDX.
 * 
 * @note Once the TDH.SYS.DISABLE completes successfully, the host VMM may reinitialize the TDX Module (TDH.SYS.INIT etc.).
 * 
 * @return Success or Error type
 */
api_error_type tdh_sys_disable(void);

/**
 * @brief Provide information about the TDX-SEAM module and the convertible memory.
 *
 * @note
 *
 * @param tdsysinfo_output_pa The physical address of a buffer where the output TDSYSINFO_STRUCT will be written
 * @param num_of_bytes_in_buffer The number of bytes in the above buffer
 * @param cmr_info_pa The physical address of a buffer where an array of CMR_INFO will be written
 * @param num_of_cmr_info_entries The number of CMR_INFO entries in the above buffer
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_info(uint64_t tdhsysinfo_output_pa,
                           uint64_t num_of_bytes_in_buffer,
                           uint64_t cmr_info_pa,
                           uint64_t num_of_cmr_info_entries);

/**
 * @brief Read a TDX Module global-scope metadata field
 *
 * @note
 *
 * @param field_id FIELD ID to read
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_rd(md_field_id_t field_id);

/**
 * @brief Read all host-readable TDX Module global-scope metadata fields
 *
 * @note
 *
 * @param md_list_hpa Physical address of output metadata list
 * @param field_id FIELD ID to read
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_rdall(uint64_t md_list_hpa, md_field_id_t field_id);

/**
 * @brief Globally initialize the TDX-SEAM module.
 *
 * @note
 *
 * @param version Version of the API
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_init(uint8_t version);


/**
 * @brief Initialize the TDX-SEAM module at the current logical processor scope.
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_lp_init(void);


/**
 * @brief Partially initialize a TDX Memory Range (TDMR) and its associated PAMT.
 *
 * @note
 *
 * @param tdmr_pa The physical base address of a TDMR
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_tdmr_init(uint64_t tdmr_pa);


/**
 * @brief Initiate TDX-SEAM module shutdown and prevent further SEAMCALL on the current logical processor.
 *
 * @note Marks the TDX-SEAM module as being shut down and prevents further SEAMCALL on the current LP.
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_lp_shutdown(void);


/**
 * @brief Increment the TD’s TLB epoch counter.
 *
 * @note
 *
 * @param tdr_pa The physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_track(uint64_t tdr_pa);


/**
 * @brief Remove the blocking of a TD private GPA range.
 *
 * Remove the blocking of a TD private GPA range, i.e.,
 * a Secure EPT page or a TD private page, at any level (4KB, 2MB, 1GB, 512GB, 256TB etc.)
 * previously blocked by TDHMEMRANGEBLOCK.
 *
 * @note
 *
 * @param page_info Level and GPA of page to be unblocked
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_range_unblock(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Interruptible and restartable function to write back the cache hierarchy on a package or a core.
 *
 * @note
 *
 * @param cachewb_cmd PHYMEMCACHEWB command option
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_cache_wb(uint64_t cachewb_cmd);


/**
 * @brief Write back and invalidate all cache lines associated with the specified memory page and HKID.
 *
 * @note
 *
 * @param tdmr_page_pa Physical address of a 4KB page in TDMR, including HKID bits
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_wbinvd(uint64_t tdmr_page_pa);

/**
 * @brief Write a TDVPS field.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param field_code Field code in TDVPS
 * @param wr_data 64b data to write to the field
 * @param wr_mask 64b write mask to be applied on the write data
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_wr(uint64_t tdvpr_pa,
                         md_field_id_t field_code,
                         uint64_t wr_data,
                         uint64_t wr_mask);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_servtd_bind(uint64_t target_tdr_pa, uint64_t servtd_tdr, uint64_t servtd_slot,
        uint64_t servtd_type, servtd_attributes_t servtd_attr);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_servtd_prebind(uint64_t target_tdr_pa, uint64_t servtd_info_hash, uint64_t servtd_slot,
        uint64_t servtd_type, servtd_attributes_t servtd_attr);


/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_abort(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                                uint64_t mig_stream_indx);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_state_td(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_state_immutable(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
        uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_import_state_immutable(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
        uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_mig_stream_create(uint64_t migsc_pa, uint64_t target_tdr_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_state_vp(uint64_t target_tdvpr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_import_state_td(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_import_state_vp(uint64_t target_tdvpr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_track(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t idx_and_cmd);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_import_track(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t idx_and_cmd);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_pause(uint64_t target_tdr_pa);


/**
 * @brief API handler for TDH_EXPORT_MEM_LEAF
 *
 * @param gpa_list_info - HPA of a GPA list page
 * @param target_tdr_pa - HPA of the TDR
 * @param hpa_and_size_pa - HPA and size of the mbmd page
 * @param mig_buff_list_pa_val - HPA (including HKID bits) of a migration buffer list
 * @param migs_i_and_cmd_val - Migration stream index and command
 * @param mac_list_0_pa - HPA (including HKID bits) of a MAC list
 * @param mac_list_1_pa - HPA (including HKID bits) of a MAC list
 * @param version - Can be 0 or 1
 *
 * @return  Success or Error type
 */
api_error_type tdh_export_mem(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                              uint64_t mig_buff_list_pa_val, uint64_t migs_i_and_cmd_val,
                              uint64_t  mac_list_0_pa, uint64_t  mac_list_1_pa, uint8_t version);

/**
 * @brief API handler for TDH_IMPORT_MEM_LEAF
 *
 * @param gpa_list_info - HPA of a GPA list page
 * @param target_tdr_pa - HPA of the TDR
 * @param hpa_and_size_pa - HPA and size of the mbmd page
 * @param mig_buff_list_pa_val - HPA (including HKID bits) of a migration buffer list
 * @param migs_i_and_cmd_pa - Migration stream index and command
 * @param mac_list_0_pa - HPA (including HKID bits) of a MAC list
 * @param mac_list_1_pa - HPA (including HKID bits) of a MAC list
 * @param new_page_list_pa_val - HPA (including HKID bits) of a destination page if in-place import is not requested,
 *                               otherwise, should be set to NULL_PA (all 1's).
 * @param version - Can be either 0 or 1
 *
 * @return  Success or Error type
 */
api_error_type tdh_import_mem(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                              uint64_t mig_buff_list_pa_val, uint64_t migs_i_and_cmd_pa, uint64_t mac_list_0_pa,
                              uint64_t  mac_list_1_pa, uint64_t new_page_list_pa_val, uint8_t version);

/**
 * @brief API handler for TDH_IMPORT_ABORT_LEAF
 *
 * @param target_tdr_pa - HPA of the TDR
 * @param hpa_and_size_pa - HPA of the mbmd page
 * @param migs_i - migration stream index
 *
 * @return  Success or Error type
 */
api_error_type tdh_import_abort(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t migs_i);

/**
 * @brief API handler for TDH_IMPORT_COMMIT_LEAF
 *
 * @param target_tdr_pa - HPA of the TDR
 *
 * @return  Success or Error type
 */
api_error_type tdh_import_commit(uint64_t target_tdr_pa);

/**
 * @brief API handler for TDH_IMPORT_END_LEAF
 *
 * @param target_tdr_pa - HPA of the TDR
 *
 * @return  Success or Error type
 */
api_error_type tdh_import_end(uint64_t target_tdr_pa);

/**
 * @brief API handler for TDH_IMPORT_PAGE_CANCEL_LEAF
 *
 * @param target_tdr_pa
 * @param hpa_and_size_pa
 * @param migs_i
 *
 * @return  Success or Error type
 */
api_error_type tdh_import_page_cancel(uint64_t target_tdr_pa,
        uint64_t hpa_and_size_pa, uint64_t migs_i);

/**
 * @brief API handler for TDH_EXPORT_BLOCKW_LEAF
 *
 * @param gpa_list_info
 * @param target_tdr_pa
 * @param version
 *
 * @return Success or Error type
 */
api_error_type tdh_export_blockw(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa, uint8_t version);

/**
 * @brief API handler for TDH_EXPORT_RESTORE_LEAF
 *
 * @param gpa_list_info
 * @param target_tdr_pa
 * @param version
 *
 * @return Success or Error type
 */
api_error_type tdh_export_restore(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa, uint8_t version);

/**
 * @brief
 *
 * @return Success or Error type
 */
api_error_type tdh_export_unblockw(uint64_t page_pa, uint64_t target_tdr_pa);

/**
 * @brief Scan a range of the TD’s private GPA space and perform the requested operation.
 *
 * @note
 *
 * @param list_of_lists_info - HPA of a list-of-lists in shared memory, and first and last entries to process.  The list contains up to 512 PAGE_LIST_INFO entries, each pointing to a GPA list containing up to 512 entries.
 * @param tdr - HPA of the source TD’s TDR page (HKID bits must be 0).
 * @param controls - SCAN control fields.
 * @param range_start - The start address of the private GPA range to scan. Must be a valid private GPA, aligned on 4KB.
 * @param range_size - The size of the GPA range to scan. Must be a multiple of 4KB.  Bits 63:52 must be 0.
 * @param overall_next_entry - The next overall index of the GPA List entry to be written by TDH.MEM.SCAN.RANGE.
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_scan_range(uint64_t list_of_lists_info, uint64_t tdr, uint64_t controls, uint64_t range_start, uint64_t range_size, uint64_t overall_next_entry);

/**
 * @brief Do a comprehensive scan of the TD’s private GPA space and perform the requested operation.
 *
 * @note
 *
 * @param list_of_lists_info - HPA of a list-of-lists in shared memory, and first and last entries to process.  The list contains up to 512 PAGE_LIST_INFO entries, each pointing to a GPA list containing up to 512 entries.
 * @param tdr - HPA of the source TD’s TDR page (HKID bits must be 0).
 * @param controls - SCAN control fields.
 * @param overall_next_entry - The next overall index of the GPA List entry to be written by TDH.MEM.SCAN.COMP.
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_scan_comp(uint64_t list_of_lists_info, uint64_t tdr, uint64_t controls, uint64_t overall_next_entry);

/**
 * @brief Configure memory scan and add control structure pages.
 *
 * @note
 *
 * @param range_list_info - The shared physical address (including HKID) of a page where memory scan control page will be created.
 * @param tdr - The physical address of the owner TDR page (HKID bits must be 0).
 * @param cx0_hpa - The physical address where memory scan control page 0 will be created (HKID bits must be 0).
 * @param cx1_hpa - The physical address where memory scan control page 1 will be created (HKID bits must be 0).
 * @param cx2_hpa - The physical address where memory scan control page 2 will be created (HKID bits must be 0).
 * @param cx3_hpa - The physical address where memory scan control page 3 will be created (HKID bits must be 0).
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_scan_config(uint64_t range_list_info, uint64_t tdr, uint64_t cx0_hpa, uint64_t cx1_hpa, uint64_t cx2_hpa, uint64_t cx3_hpa);

/**
 * @brief Reset the TDX module’s comprehensive memory scan internal state for the specified TD.
 *
 * @note
 *
 * @param tdr - HPA of the source TD’s TDR page (HKID bits must be 0).
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_scan_reset(uint64_t tdr);

/**
 * @brief Shuts down the system and prepared handoff data buffer for the next module
 *
 * @param hv_input Handoff version input
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_shutdown(uint64_t hv_input);

/**
 * @brief Finished updating TDX module by retrieving and loading handoff data from the previous module
 *
 * @param version
 * @param enabling_flags TDX module feature enabling flags, formatted similarly to TDX_FEATURES0
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_update(uint8_t version, uint64_t enabling_flags, uint64_t reserved_r10);

api_error_type tdh_phymem_pamt_add(page_size_api_input_t page_info,
                                   uint64_t pamt_hpa0,
                                   uint64_t pamt_hpa1);

api_error_type tdh_phymem_pamt_remove(page_size_api_input_t page_info);



#endif // __TDX_VMM_API_HANDLERS_H_INCLUDED__
