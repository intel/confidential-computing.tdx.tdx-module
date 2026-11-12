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
 * @file tdh_mng_init
 * @brief TDHMNGINIT API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "x86_defs/vmcs_defs.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "helpers/virt_msr_helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "crypto/sha384.h"
#include MSR_CONFIG_LOOKUP_HEADER
#include CPUID_CONFIGURATIONS_HEADER
#include "helpers/cpuid_fms.h"

static void apply_cpuid_xfam_masks(volatile cpuid_config_return_values_t* cpuid_values,
                                   uint64_t xfam,
                                   const cpuid_config_return_values_t* cpuid_masks)
{
    uint64_t xfam_mask;   // 1-bit mask

    xfam_mask = 1ULL;
    for (uint32_t xfam_bit = 0; xfam_bit <= XCR0_MAX_BIT; xfam_bit++)
    {
        if ((xfam & xfam_mask) == 0)
        {
            // Loop on all 4 CPUID values
            for (uint32_t i = 0; i < 4; i++)
            {
                cpuid_values->values[i] &= ~cpuid_masks[xfam_bit].values[i];
            }
        }
        xfam_mask <<= 1;
    }
}

static api_error_type read_and_set_td_configurations(tdr_t * tdr_ptr,
                                                     tdcs_t * tdcs_ptr,
                                                     td_params_t * td_params_ptr)
{
    volatile ia32e_eptp_t   target_eptp = { .raw = 0 };
    volatile td_param_attributes_t tmp_attributes;
    volatile ia32_xcr0_t    tmp_xfam;

    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Read and verify ATTRIBUTES
    tmp_attributes.raw = td_params_ptr->attributes.raw;
    if (!verify_td_attributes(tmp_attributes, false))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_ATTRIBUTES);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.attributes.raw = tmp_attributes.raw;

    tdcs_ptr->executions_ctl_fields.td_ctls.pending_ve_disable = tmp_attributes.sept_ve_disable;

    // Read and verify XFAM
    tmp_xfam.raw = td_params_ptr->xfam;
    if (!check_xfam(tmp_xfam))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_XFAM);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.xfam = tmp_xfam.raw;

    set_xbuff_offsets_and_size(tdcs_ptr, tmp_xfam.raw);

    // Read and verify MAX_VCPUS
    volatile uint32_t max_vcpus = (uint32_t)td_params_ptr->max_vcpus;
    if ((max_vcpus == 0) || (max_vcpus > MAX_VCPUS_PER_TD))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_MAX_VCPUS);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.max_vcpus = max_vcpus;

    volatile uint16_t num_l2_vms = (uint16_t)td_params_ptr->num_l2_vms;
    if (num_l2_vms > MAX_L2_VMS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_NUM_L2_VMS);
        goto EXIT;
    }

    // Now that we know the number of L2 VMs, check that enough pages have been allocated for TDCS
    if (!is_required_tdcs_allocated(tdr_ptr, num_l2_vms))
    {
        return_val = TDX_TDCS_NOT_ALLOCATED;
        goto EXIT;
    }

    // Only now we can safely update TDCS; NUM_L2_VMS is used by TDH.MNG.RD/WR to calculate offset into TDCS
    tdcs_ptr->management_fields.num_l2_vms = num_l2_vms;

    // Check reserved0 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_0, TD_PARAMS_RESERVED0_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Read and verify CONFIG_FLAGS
    volatile config_flags_t config_flags_local_var;
    config_flags_local_var.raw = td_params_ptr->config_flags.raw;

    if (!verify_td_config_flags(config_flags_local_var))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EXEC_CONTROLS);
        goto EXIT;
    }

    // Read and verify EPTP_CONTROLS
    target_eptp.raw = td_params_ptr->eptp_controls.raw;
    config_flags_t config_flags_local_var_tmp = {.raw = config_flags_local_var.raw};
    ia32e_eptp_t target_eptp_tmp = {.raw = target_eptp.raw};
    if (!verify_and_set_td_eptp_controls(tdr_ptr, tdcs_ptr, config_flags_local_var_tmp.gpaw, target_eptp_tmp))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EPTP_CONTROLS);
        goto EXIT;
    }

    tdcs_ptr->executions_ctl_fields.config_flags.raw = config_flags_local_var.raw;
    tdcs_ptr->executions_ctl_fields.gpaw = config_flags_local_var.gpaw;

    volatile uint16_t virt_tsc_freq = td_params_ptr->tsc_frequency;
    if ((virt_tsc_freq < VIRT_TSC_FREQUENCY_MIN) || (virt_tsc_freq > VIRT_TSC_FREQUENCY_MAX))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_TSC_FREQUENCY);
        goto EXIT;
    }

    tdcs_ptr->executions_ctl_fields.tsc_frequency = virt_tsc_freq;

    // We read TSC below.  Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    // to make sure the host VMM doesn't play any trick on us.
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
        goto EXIT;
    }

    // Calculate TSC multiplier of offset that will be written in every TD VMCS, such that
    // virtual TSC will advance at the configured frequency, and will start from 0 at this
    // moment.
    calculate_tsc_virt_params(ia32_rdtsc(),tdx_global_data_ptr->native_tsc_frequency,
                              virt_tsc_freq, 0,
                              &tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                              &tdcs_ptr->executions_ctl_fields.tsc_offset);


    // Check reserved1 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_1, TD_PARAMS_RESERVED1_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdx_memcpy(tdcs_ptr->measurement_fields.mrconfigid.bytes, sizeof(measurement_t),
               td_params_ptr->mr_config_id.bytes, sizeof(measurement_t));
    tdx_memcpy(tdcs_ptr->measurement_fields.mrowner.bytes, sizeof(measurement_t),
               td_params_ptr->mr_owner.bytes, sizeof(measurement_t));
    tdx_memcpy(tdcs_ptr->measurement_fields.mrownerconfig.bytes, sizeof(measurement_t),
               td_params_ptr->mr_owner_config.bytes, sizeof(measurement_t));

    if (td_params_ptr->msr_config_ctls.reserved_0 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Check reserved2 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_2, TD_PARAMS_RESERVED2_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}


static api_error_type read_and_set_cpuid_configurations(uint64_t target_tdr_pa,
                                                        tdcs_t * tdcs_ptr,
                                                        td_params_t * td_params_ptr,
                                                        tdx_module_global_t * global_data_ptr,
                                                        tdx_module_local_t * local_data_ptr)
{
    uint32_t cpuid_index = 0;
    cpuid_config_leaf_subleaf_t cpuid_leaf_subleaf;
    volatile cpuid_config_return_values_t config_values;
    volatile cpuid_config_return_values_t final_tdcs_values;
    td_param_attributes_t attributes;
    ia32_xcr0_t xfam;
    api_error_type return_val = UNINITIALIZE_ERROR;
    cpuid_23_0_eax_t tmp_cpuid_23_eax_val = { .raw = 0 };

    attributes.raw = tdcs_ptr->executions_ctl_fields.attributes.raw;
    xfam.raw = tdcs_ptr->executions_ctl_fields.xfam;

    // Initialize CPUID_FIXED0_BITMAP to the constant derived from the CPUID spreadsheet.
    // This value is migrated with the TD.
    tdcs_ptr->executions_ctl2_fields.cpuid_fixed0_bitmap = CPUID_FIXED0_BITMAP;

    for (cpuid_index = 0; cpuid_index < MAX_NUM_CPUID_LOOKUP; cpuid_index++)
    {
        cpuid_leaf_subleaf = cpuid_lookup[cpuid_index].leaf_subleaf;

        // Start with the native CPUID value, collected on TDHSYSINIT
        final_tdcs_values.low = global_data_ptr->cpuid_values[cpuid_index].values.low;
        final_tdcs_values.high = global_data_ptr->cpuid_values[cpuid_index].values.high;

        uint32_t config_index = cpuid_lookup[cpuid_index].config_index;

        if (cpuid_lookup[cpuid_index].valid_entry && (config_index != CPUID_CONFIG_NULL_IDX))
        {
            config_values = td_params_ptr->cpuid_config_vals[config_index];

            tdx_debug_assert((cpuid_leaf_subleaf.raw == cpuid_configurable[config_index].leaf_subleaf.raw));

            // Loop on all 4 CPUID values
            for (uint32_t i = 0; i < 4; i++)
            {
                // Any bit configured to 1 must be either:
                //   - Directly Configurable, or
                //   - Directly Allowable
                if ((config_values.values[i] &
                     ~(cpuid_configurable[config_index].config_direct.values[i] |
                       cpuid_configurable[config_index].allow_direct.values[i])) != 0)
                {
                    local_data_ptr->vmm_regs.rcx = cpuid_leaf_subleaf.raw;
                    return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                    goto EXIT;
                }

                // Compute the virtualized CPUID value and store in TDCS:
                // Note:  The bits in the lookup tables are mutually exclusive

                // Clear to 0 any bits that are FIXED0 or DYNAMIC
                final_tdcs_values.values[i] &= ~cpuid_lookup[cpuid_index].fixed0_or_dynamic.values[i];

                // Set to 1 any bits that are FIXED1
                final_tdcs_values.values[i] |= cpuid_lookup[cpuid_index].fixed1.values[i];

                // Set any bits that are CONFIG_DIRECT to their input values
                final_tdcs_values.values[i] &= ~cpuid_configurable[config_index].config_direct.values[i];
                final_tdcs_values.values[i] |= config_values.values[i] & cpuid_configurable[config_index].config_direct.values[i];

                // Clear to 0 any bits that are ALLOW_DIRECT, if their input value is 0
                final_tdcs_values.values[i] &= config_values.values[i] | ~cpuid_configurable[config_index].allow_direct.values[i];
            }
        }

        if (cpuid_leaf_subleaf.leaf == CPUID_VER_INFO_LEAF)
        {
            // CPUID(1).EAX is the virtual Family/Model/Stepping configuration
            fms_info_t cpuid_01_eax = { .raw = final_tdcs_values.eax };

            if (cpuid_01_eax.raw == 0)
            {
                // A value of 0 means use the native configuration
                cpuid_01_eax = global_data_ptr->platform_fms;

                final_tdcs_values.eax = cpuid_01_eax.raw;
            }
            else if (tdcs_ptr->executions_ctl_fields.attributes.migratable)
            {
                if (!check_fms_config(cpuid_01_eax))
                {
                    // The configured F/M/S value is not valid
                    local_data_ptr->vmm_regs.rcx = cpuid_leaf_subleaf.raw;
                    return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                    goto EXIT;
                }
            }
            else if (cpuid_01_eax.raw != global_data_ptr->platform_fms.raw)
            {
                // For a non-migratable TD, only a value of 0 (updated above) or the native FMS is allowed
                local_data_ptr->vmm_regs.rcx = cpuid_leaf_subleaf.raw;
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                goto EXIT;
            }

            // Leaf 0x1 has ECX bits configurable by AVX (XFAM[2]).
            // If XFAM[2] is 0, the applicable bits are cleared.
            if (!xfam.avx)
            {
                final_tdcs_values.ecx &= ~(xfam_mask_0x1_0xffffffff[2].ecx);
            }

            cpuid_01_ecx_t cpuid_01_ecx;
            cpuid_01_ecx.raw = final_tdcs_values.ecx;

            tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported = cpuid_01_ecx.monitor;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.dca_supported           = cpuid_01_ecx.dca;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.tsc_deadline_supported  = cpuid_01_ecx.tsc_deadline;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.est_supported           = cpuid_01_ecx.est;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.tm2_supported           = cpuid_01_ecx.tm2;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.xtpr_update_supported   = cpuid_01_ecx.xtpr_update_control;

            cpuid_01_edx_t cpuid_01_edx;
            cpuid_01_edx.raw = final_tdcs_values.edx;

            // By default, the following flags don't depend on CPUID configuration.  This gets updated later if the TD sets TDCS.TD_CTLS.REDUCE_VE.
            tdcs_ptr->executions_ctl_fields.cpuid_flags.mce_not_supported  = false;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.mca_not_supported  = false;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.mtrr_not_supported = false;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.acpi_supported =  cpuid_01_edx.acpi;
        }
        else if (cpuid_leaf_subleaf.leaf == 4)
        {
            // Sample the native values of the first NUM_CPUID4_NATIVE subleaves into TDCS.  They were sampled on TDH.SYS.INIT.
            if (cpuid_leaf_subleaf.subleaf < NUM_CPUID4_NATIVE)
            {
                tdcs_ptr->executions_ctl2_fields.cpuid4_native_values[cpuid_leaf_subleaf.subleaf] = global_data_ptr->cpuid_values[cpuid_index].values;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 5)
        {
            if (!tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == CPUID_EXT_FEATURES_LEAF)
        {
           if (cpuid_leaf_subleaf.subleaf == CPUID_EXT_FEATURES_SUBLEAF)
           {
               cpuid_07_00_ecx_t cpuid_07_00_ecx;
               cpuid_07_00_edx_t cpuid_07_00_edx;

               apply_cpuid_xfam_masks(&final_tdcs_values, xfam.raw, xfam_mask_0x7_0x0);

               cpuid_07_00_ebx_t cpuid_07_00_ebx = { .raw = final_tdcs_values.ebx };

               // Both CPUID bits that enumerate TSX must have the same virtual value
               if (cpuid_07_00_ebx.hle != cpuid_07_00_ebx.rtm)
               {
                   local_data_ptr->vmm_regs.rcx = cpuid_leaf_subleaf.raw;
                   return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                   goto EXIT;
               }
               // If virtual TSX is enabled, IA32_TSX_CTRL must exist
               if (cpuid_07_00_ebx.hle && !global_data_ptr->plt_common_config.ia32_arch_capabilities.tsx_ctrl)
               {
                   return_val = api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_ARCH_CAPABILITIES_MSR_ADDR);
                   goto EXIT;
               }

               tdcs_ptr->executions_ctl_fields.cpuid_flags.tsx_supported = cpuid_07_00_ebx.hle;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.rdt_a_supported = cpuid_07_00_ebx.rdt_a;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.rdt_m_supported = cpuid_07_00_ebx.rdt_m;

               cpuid_07_00_ecx.raw = final_tdcs_values.ecx;
               // CPUID(0x7, 0x0).ECX.PKS reflects ATTRIBUTES.PKS
               cpuid_07_00_ecx.pks = attributes.pks;

               // CPUID(0x7, 0x0).ECX.KL_SUPPORTED reflects ATTRIBUTES.KL
               cpuid_07_00_ecx.kl_supported = 0;

               final_tdcs_values.ecx = cpuid_07_00_ecx.raw;

               tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported = cpuid_07_00_ecx.waitpkg;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.tme_supported = cpuid_07_00_ecx.tme;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.la57_supported = cpuid_07_00_ecx.la57;

               cpuid_07_00_edx.raw = final_tdcs_values.edx;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.pconfig_supported = cpuid_07_00_edx.pconfig_mktme;
               // By default, the following flag doesn't depend on CPUID configuration.  This gets updated later if the TD sets TDCS.TD_CTLS.REDUCE_VE.
               tdcs_ptr->executions_ctl_fields.cpuid_flags.core_capabilities_not_supported = false;
           }
           else if (cpuid_leaf_subleaf.subleaf == 1)
           {
               apply_cpuid_xfam_masks(&final_tdcs_values, xfam.raw, xfam_mask_0x7_0x1);

               cpuid_07_01_eax_t cpuid_07_01_eax = { .raw = final_tdcs_values.eax };
               tdcs_ptr->executions_ctl_fields.cpuid_flags.perfmon_ext_leaf_supported =
                       cpuid_07_01_eax.perfmon_ext_leaf;

               cpuid_07_01_eax.lass = tdcs_ptr->executions_ctl_fields.attributes.lass;

               final_tdcs_values.eax = cpuid_07_01_eax.raw;
           }
           else if (cpuid_leaf_subleaf.subleaf == 2)
           {
               // Check CPU side channel protection support
               cpuid_07_02_edx_t cpuid_07_02_edx;
               cpuid_07_02_edx.raw = final_tdcs_values.edx;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported = cpuid_07_02_edx.ddpd;

               if (is_not_gnr_a0_stepping())
               {

                   // The TD will never be configured with DDPD support if the CPU doesn't support DDPD
                   tdx_debug_assert(!tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported ||
                                    global_data_ptr->ddpd_supported);

                   // IA32_SPEC_CTRL virtualization is required in the following case:
                   //  - The TD is configured without DDPD support, and
                   //  - The CPU supports DDPD
                   // Because in this case we enable DDPD without the TD knowing about this.
                   tdx_debug_assert(tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported ||
                                    !global_data_ptr->ddpd_supported ||
                                    global_data_ptr->plt_common_config.ia32_vmx_procbased_ctls3.virt_ia32_spec_ctrl);
               }
           }
           else
           {
               extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_td_handle(target_tdr_pa);
               fatal_error(FATAL_ERROR_ID_57, FATAL_INFO_FORMAT_TD_HANDLE_INFO, &extended_fatal_info);
           }
        }
        else if (cpuid_leaf_subleaf.leaf == 0xA)
        {
            // Leaf 0xA's values are defined as "ALLOW_PERFMON", i.e., if ATTRRIBUTES.PERFMON
            //   is set they return the native values, else they return 0.
            if (!attributes.perfmon)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == CPUID_EXT_STATE_ENUM_LEAF)
        {
            if (cpuid_leaf_subleaf.subleaf == 0)
            {
                apply_cpuid_xfam_masks(&final_tdcs_values, xfam.raw, xfam_mask_0xd_0x0);

                final_tdcs_values.ecx = calculate_xsave_area_max_size(xfam);
            }
            else if (cpuid_leaf_subleaf.subleaf == 1)
            {
                apply_cpuid_xfam_masks(&final_tdcs_values, xfam.raw, xfam_mask_0xd_0x1);

                // Update CPUID leaf 0xD sub-leaf 0x1 EAX[2] value.  This bit enumerates XFD support, and is
                // virtualized as 1 only if the CPU supports XFD and any of the applicable extended feature
                // set, per XFAM, supports XFD.
                cpuid_0d_01_eax_t cpuid_0d_01_eax;
                cpuid_0d_01_eax.raw = final_tdcs_values.eax;

                if ((global_data_ptr->xfd_faulting_mask & xfam.raw) == 0)
                {
                    cpuid_0d_01_eax.xfd_support = 0;
                }

                tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported = cpuid_0d_01_eax.xfd_support;
                final_tdcs_values.eax = cpuid_0d_01_eax.raw;
            }
            else if (cpuid_leaf_subleaf.subleaf <= XCR0_MAX_BIT)
            {
                // Each sub-leaf n, where 2 <= n <= 18, is configured by XFAM[n]
                if ((xfam.raw & BIT(cpuid_leaf_subleaf.subleaf)) == 0)
                {
                    final_tdcs_values.low = 0;
                    final_tdcs_values.high = 0;
                }
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 0x14)
        {
            // Leaf 0x14 is wholly configured by PT (XFAM[8])
            if (!xfam.pt)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == CPUID_TSC_ATTRIBUTES_LEAF)
        {
            // Handle CPUID Configuration by TSC_FREQUENCY
            // The following assumes:
            // - CPUID(0x15).EAX (denominator) is virtualized as a FIXED value of 1
            // - CPUID(0x15).ECX (nominal ART frequency) is virtualized as a FIXED value of 25,000,000
            // Therefore CPUID(0x15).EBX (numerator) is the configured virtual TSC frequency, in units of 25MHz.
            // The virtual TSC frequency is CPUID(0x15).ECX * CPUID(0x15).EBX / CPUID(0x15).EAX,
            // i.e., the configured virtual TSC frequency, in units of 1Hz.
            final_tdcs_values.ebx = tdcs_ptr->executions_ctl_fields.tsc_frequency;
        }
        else if (cpuid_leaf_subleaf.leaf == CPUID_KEYLOCKER_ATTRIBUTES_LEAF)
        {
            final_tdcs_values.low = 0;
            final_tdcs_values.high = 0;
        }
        else if (cpuid_leaf_subleaf.leaf == 0x1C)
        {
            // Leaf 0x1C is wholly configured by LBR (XFAM[15])
            if (xfam.lbr == 0)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 0x1D)
        {
            // Leaf 0x1D is wholly configured by AMX (XFAM[18:17])
            if (!xfam.amx_xtilecfg || !xfam.amx_xtiledata)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 0x1A)
        {
            // For migratable TDs, native model information is N/A, and is set to 0.
            // This information is used for Perfmon, which is not enabled for migratable TDs. */
            if (tdcs_ptr->executions_ctl_fields.attributes.migratable)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 0x23)
        {
            // Leaf 0x23's values are defined as "ALLOW_ATTRIBUTES(PERFMON)", i.e., if ATTRRIBUTES.PERFMON
            // is set they return the native values, else they return 0.
            if (!attributes.perfmon || !tdcs_ptr->executions_ctl_fields.cpuid_flags.perfmon_ext_leaf_supported)
            {
                final_tdcs_values.low = 0;
                final_tdcs_values.high = 0;
            }
            else
            {
                if (cpuid_leaf_subleaf.subleaf == 0)
                {
                    tmp_cpuid_23_eax_val.raw = final_tdcs_values.eax;
                    tdcs_ptr->executions_ctl_fields.perfmon_ext_subleaves_bitmap = final_tdcs_values.eax;
                }
                else
                {
                    if ((tmp_cpuid_23_eax_val.raw & BIT(cpuid_leaf_subleaf.subleaf)) == 0)
                    {
                        final_tdcs_values.low = 0;
                        final_tdcs_values.high = 0;
                    }
                }
            }
        }
        else if (cpuid_leaf_subleaf.leaf == 0x80000008)
        {
            cpuid_80000008_eax_t cpuid_80000008_eax = { .raw = final_tdcs_values.eax };

            // Set LA_BITS based on LA57 from CPUID(7, 0).ECX[16]
            if (tdcs_ptr->executions_ctl_fields.cpuid_flags.la57_supported)
            {
                cpuid_80000008_eax.la_bits = LA57_LINEAR_ADDRESS_WIDTH;
            }
            else
            {
                cpuid_80000008_eax.la_bits = LEGACY_LINEAR_ADDRESS_WIDTH;
            }

            if (td_params_ptr->config_flags.maxgpa_virt)
            {
                cpuid_80000008_eax.pa_bits = (uint32_t)global_data_ptr->max_pa;
                cpuid_80000008_eax.gpa_bits = (uint32_t)MIN(global_data_ptr->max_pa,
                        (tdcs_ptr->executions_ctl_fields.gpaw ? MAX_PA : MAX_PA_FOR_GPA_NOT_WIDE));

                // Save the virtual MAXPA for easy access
                tdcs_ptr->executions_ctl_fields.virt_maxpa = cpuid_80000008_eax.gpa_bits;
            }
            else
            {
                if (td_params_ptr->config_flags.maxpa_virt)
                {
                    if (cpuid_80000008_eax.pa_bits)
                    {
                        if (!is_virt_maxpa_valid(tdcs_ptr->executions_ctl_fields.gpaw, cpuid_80000008_eax.pa_bits))
                        {
                            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                            goto EXIT;
                        }
                    }
                    else
                    {
                        // A configured MAXPA value of 0 means the minimum of the native MAXPA and of GPAW should be used
                        cpuid_80000008_eax.pa_bits = (uint32_t)MIN(global_data_ptr->max_pa,
                                (tdcs_ptr->executions_ctl_fields.gpaw ? MAX_PA : MAX_PA_FOR_GPA_NOT_WIDE));
                    }
                }
                else
                {
                    cpuid_80000008_eax.pa_bits = (uint32_t)global_data_ptr->max_pa;
                }

                cpuid_80000008_eax.gpa_bits = 0;

                // Save the virtual MAXPA for easy access
                tdcs_ptr->executions_ctl_fields.virt_maxpa = cpuid_80000008_eax.pa_bits;
            }

            final_tdcs_values.eax = cpuid_80000008_eax.raw;
        }

        // Write the CPUID values to TDCS and set the CPUID_VALID flag
        tdcs_ptr->cpuid_values[cpuid_index].low = final_tdcs_values.low;
        tdcs_ptr->cpuid_values[cpuid_index].high = final_tdcs_values.high;
        tdcs_ptr->executions_ctl_fields.cpuid_valid[cpuid_index] = true;
    }

    // Check the virtual topology configuration of CPUID(0x1F) and derive CPUID(0xB).
    // If configured as all-0, use the h/w values.
    return_val = check_cpuid_1f_and_compute_cpuid_0b(tdcs_ptr, true);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // May be cleared later if not configured for all VCPUs
    tdcs_ptr->executions_ctl_fields.topology_enum_configured = true;
    tdcs_ptr->executions_ctl_fields.ve_reduction_valid = true;

    // Check reserved3 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_3, TD_PARAMS_RESERVED3_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}


api_error_type tdh_mng_init(uint64_t target_tdr_pa, uint64_t target_td_params_pa, uint64_t event_filters_info_params)
{
    // Global data
    tdx_module_global_t * global_data_ptr = get_global_data();
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_walk_result_t    tdr_pamt_walk_result;
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // TD_PARAMS variables
    pa_t                  td_params_pa;              // Physical address of the params structure
    td_params_t         * td_params_ptr = NULL;      // Pointer to the parameters structure

    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    bool_t event_filtering = target_tdr_pa & BIT(0);
    tdr_pa.raw = target_tdr_pa & BITS(63, 1);
    td_params_pa.raw = target_td_params_pa;
    event_filter_info_t event_filters_info = { .raw = event_filters_info_params };
    event_filter_t* event_filters_p = NULL;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_LIMIT_CPUID_MAXVAL_BIT ) != 0)
    {
        return_val = TDX_LIMIT_CPUID_MAXVAL_SET;
        goto EXIT;
    }

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_walk_result,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %lld\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_MNG_INIT_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    tdcs_ptr->executions_ctl2_fields.event_filters_num = 0;

    // Check that TD PARAMS page is TD_PARAMS_ALIGN_IN_BYTES
    // Verify the TD PARAMS physical address is canonical and shared
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(td_params_pa, TD_PARAMS_ALIGN_IN_BYTES)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check - error = %llx\n", td_params_pa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Map the TD PARAMS address
    td_params_ptr = (td_params_t *)map_pa((void*)td_params_pa.raw, TDX_RANGE_RO);

    /**
     *  Initialize the TD management fields
     */
    tdcs_ptr->management_fields.num_vcpus = 0U;
    tdcs_ptr->management_fields.num_assoc_vcpus = 0U;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch = 1ULL;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[0] = 0;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[1] = 0;

    uint64_t native_tsc_frequency = get_global_data()->native_tsc_frequency;
    tdx_sanity_check((native_tsc_frequency <= BIT_MASK_32BITS), FATAL_ERROR_ID_288, 0);
    // safe to cast to 32-bits due to the sanity check above
    tdcs_ptr->executions_ctl_fields.hp_lock_timeout = translate_usec_to_tsc(DEFAULT_HP_LOCK_TIMEOUT_USEC, (uint32_t)native_tsc_frequency);

    /**
     *  Read the TD configuration input and set TDCS fields
     */
    return_val = read_and_set_td_configurations(tdr_ptr, tdcs_ptr, td_params_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("read_and_set_td_configurations failed\n");
        goto EXIT;
    }

    // ---------------------------------------------
    //         Read the Perfmon Event Filters
    // ---------------------------------------------

    if (event_filtering && tdcs_ptr->executions_ctl_fields.attributes.perfmon)
    {
        if (event_filters_info.reserved ||
            event_filters_info.event_filters_num == 0 ||
            event_filters_info.event_filters_num > MAX_EVENT_FILTERS ||
            (TDX_SUCCESS != shared_hpa_check_with_pwr_2_alignment((pa_t)(event_filters_info.raw & ~BITS(11, 0)), _4KB)))
        {
            TDX_ERROR("Illegal event filters info = 0x%lx\n", event_filters_info.raw);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }

        tdcs_ptr->executions_ctl2_fields.event_filters_num = event_filters_info.event_filters_num;

        event_filters_p = (event_filter_t*)map_pa((void*)(event_filters_info.raw & ~BITS(11, 0)), TDX_RANGE_RO);

        for (uint16_t i = 0; i < event_filters_info.event_filters_num; i++)
        {
            event_filter_internal_t event_filter_internal;
            event_filter_t event_filter = event_filters_p[i];

            // Check the provided event filter entry. We currently support only basic filtering and only 8-bit UMASK.
            if (event_filter.reserved_0 ||
                event_filter.umask > 0xFF ||
                event_filter.negative ||
                event_filter.umask_mask != 0xFFFF)
            {
                TDX_ERROR("Illegal event filter [%d] = 0x%lx\n", i, event_filter.raw);
                return_val = api_error_with_operand_id(TDX_EVENT_FILTER_INVALID, i);
                goto EXIT;
            }

            event_filter_internal.event_select = (uint8_t)event_filter.event_select;
            event_filter_internal.umask = (uint8_t)event_filter.umask;

            if ((i != 0) && (tdcs_ptr->event_filters_internal[i - 1].raw >= event_filter_internal.raw))
            {
                TDX_ERROR("Event filters array must be sorted\n");
                return_val = api_error_with_operand_id(TDX_EVENT_FILTER_ORDER_INVALID, i);
                goto EXIT;
            }

            tdcs_ptr->event_filters_internal[i] = event_filter_internal;
        }

        free_la(event_filters_p);
        event_filters_p = NULL;
    }

    /**
     *  Handle CPUID Configuration
     */
    return_val = read_and_set_cpuid_configurations(target_tdr_pa, tdcs_ptr, td_params_ptr, global_data_ptr, local_data_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("read_and_set_cpuid_configurations failed\n");
        goto EXIT;
    }

    // Check and initialize the virtual IA32_ARCH_CAPABILITIES MSR
    if (is_not_gnr_a0_stepping())
    {
        // Check and initialize the virtual IA32_ARCH_CAPABILITIES MSR
        if (!init_virt_ia32_arch_capabilities(tdcs_ptr, td_params_ptr->msr_config_ctls.ia32_arch_cap,
                                              td_params_ptr->ia32_arch_capabilities_config))
        {
            TDX_ERROR("Incorrect IA32_ARCH_CAPABILITIES configuration\n");
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_IA32_ARCH_CAPABILITIES_CONFIG);
            goto EXIT;
        }
    }

    return_val = td_immutable_state_cross_check(tdcs_ptr, false);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("td_immutable_state_cross_check failed\n");
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    /**
     *  Build the MSR bitmaps
     */
    set_msr_bitmaps(tdcs_ptr);

    // Initialize the virtual MSR values
    init_virt_ia32_vmx_msrs(tdcs_ptr);

    /**
     *  Initialize the TD Measurement Fields
     */
    if ((sha_error_code = sha384_init(&(tdcs_ptr->measurement_fields.td_sha_ctx))) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        fatal_error(FATAL_ERROR_ID_58, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    tdcs_ptr->measurement_fields.mrtd_context_version = CRYPTO_LIB_COMPAT_VERSION;
    (void)_lock_xadd_16b(&global_data_ptr->td_build_count, 1);

    // Zero the RTMR hash values
    basic_memset_to_zero(tdcs_ptr->measurement_fields.rtmr, (SIZE_OF_SHA384_HASH_IN_QWORDS<<3)*NUM_RTMRS);

    init_non_blocking_export_variables_in_tdcs(tdcs_ptr);


    tdcs_ptr->management_fields.op_state = OP_STATE_INITIALIZED;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (event_filters_p)
    {
        free_la(event_filters_p);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_ptr);
    }
    if (td_params_ptr != NULL)
    {
        free_la(td_params_ptr);
    }
    return return_val;
}
