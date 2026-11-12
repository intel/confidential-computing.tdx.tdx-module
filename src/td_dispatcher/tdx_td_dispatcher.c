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
 * @file tdx_td_dispatcher.c
 * @brief VM Exit from TD entry point and API dispatcher
 */

#include "tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include "td_transitions/td_exit_stepping.h"
#include "x86_defs/x86_defs.h"
#include "helpers/ipi_helpers.h"
#include "vm_exits_l2/td_l2_vmexit.h"


void tdx_failed_vmentry(void)
{
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    uint64_t error_code = 0;

    ia32_vmread(VMX_VM_INSTRUCTION_ERRORCODE_ENCODE, &error_code);

    TDX_ERROR("VMENTRY failed - error code - %d\n", error_code);

    uint64_t val;
    platform_common_config_t* msrs = &get_global_data()->plt_common_config;
    UNUSED(msrs);

    ia32_vmread(VMX_VM_EXIT_CONTROL_ENCODE, &val);
    TDX_ERROR("VM_EXIT_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_exit_ctls.raw);
    uint64_t vm_exit_ctl = val;

    ia32_vmread(VMX_VM_ENTRY_CONTROL_ENCODE, &val);
    TDX_ERROR("VM_ENTRY_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_entry_ctls.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, &val);
    TDX_ERROR("VM_PIN_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_pinbased_ctls.raw);
    uint64_t vm_ctl_pin_based = val;

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &val);
    TDX_ERROR("VM_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_procbased_ctls.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, &val);
    TDX_ERROR("VM_SEC_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_procbased_ctls2.raw);
    uint64_t vm_proc_based_ctl2 = val;

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE, &val);
    TDX_ERROR("VM_TERT_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_procbased_ctls3);

    // Print and check posted interrupts settings
    ia32_vmread(VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE, &val);
    TDX_ERROR("POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL = 0x%llx\n", val);
    uint64_t vm_posted_int_desc = val;
    ia32_vmread(VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE, &val);
    TDX_ERROR("POSTED_INTERRUPT_NOTIFICATION_VECTOR = 0x%llx\n", val);
    uint64_t vm_posted_int_notif = val;

    ia32_vmx_basic_t ia32_vmx_basic;
    ia32_vmx_basic.raw = ia32_rdmsr(IA32_VMX_BASIC_MSR_ADDR);
    TDX_ERROR("ia32_vmx_basic = 0x%llx\n", ia32_vmx_basic.raw);
    VMX_GUEST_INTERRUPTIBILITY_ENCODE;
    if (vm_ctl_pin_based & 0x80) // poseted interrupts
    {
        if ((vm_proc_based_ctl2 & 0x200) == 0)
        {
            TDX_ERROR("THIS CONDITION IS NOT MET: The \"virtual-interrupt delivery\" VM-execution control is 1.\n");
        }
        if ((vm_exit_ctl & 0x8000) == 0)
        {
            TDX_ERROR("THIS CONDITION IS NOT MET: The \"acknowledge interrupt on exit\" VM-exit control is 1.\n");
        }
        if (vm_posted_int_notif > 255)
        {
            TDX_ERROR("THIS CONDITION IS NOT MET: The posted-interrupt notification vector has a value in the range 0–255 (bits 15:8 are all 0).\n");
        }
        if ((vm_posted_int_desc & 0X3F) != 0)
        {
            TDX_ERROR("THIS CONDITION IS NOT MET: Bits 5:0 of the posted-interrupt descriptor address are all 0.\n");
        }
        if ((ia32_vmx_basic.raw & BIT(48)) && (vm_posted_int_desc > 0xFFFFFFFF))
        {
            TDX_ERROR("THIS CONDITION IS NOT MET: If IA32_VMX_BASIC[48] is read as 1, this address must not set any bits in the range 63:32; see Appendix A.1\n");
        }
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE
    tdx_module_local_t* local_data = get_local_data();

    // L2 vm entry failure should result in resuming L1 and emulating the termination with additional information
    if (local_data->current_td_vm_id == 0)
    {
        extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_td_handle(get_local_data()->vp_ctx.tdr_pa.raw);
        fatal_error(FATAL_ERROR_ID_19, FATAL_INFO_FORMAT_TD_HANDLE_INFO, &extended_fatal_info);
    }
}

void tdx_return_to_td(bool_t launch_state, bool_t called_from_tdenter, gprs_state_t* gpr_state)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    // Restore IA32_SPEC_CTRL
    if (!called_from_tdenter)
    {
        // TDENTER already loads the spec ctrl with safe checks
        wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR,
                  local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl, GET_TDX_MODULE_IA32_SPEC_CTRL());
    }


    restore_xcr0_and_avx_states(true);

    // Check that we have no mapped keyholes left, beside the 2 that we store for TDR/TDVPR PAMT entries
    tdx_sanity_check(local_data_ptr->keyhole_state.total_ref_count - local_data_ptr->fatal_error_mem_mapped == NUM_OF_PRESERVED_KEYHOLES,
                     FATAL_ERROR_ID_250, 30);

    local_data_ptr->current_td_vm_id = local_data_ptr->vp_ctx.tdvps->management.curr_vm;


    // Exit to TD
    tdx_tdentry_to_td(launch_state, gpr_state);
}

void bus_lock_exit(void)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    if (local_data_ptr->vp_ctx.bus_lock_preempted)
    {
        /*
         * If we got here and BUS_LOCK_PREEMPTED is still set, it means that a bus lock preemption
         * has been indicated on VM exit (bit 26 of the exit reason) but the VM exit handler decided
         * not to do a TD exit.
         * In this case, we do an asynchronous TD exit here with a synthetic BUS_LOCK (74) exit reason.
         **/
        vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
        vm_exit_reason.basic_reason = VMEXIT_REASON_BUS_LOCK;

        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, 0, 0);
    }
}

void check_pending_voe_on_debug_td_return(void)
{
    // TDX Local data
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    // If the TD is debuggable, check if a Vector-On-Entry (VOE) is being injected, and if so, if it
    // matches the TD VMCS' exception bitmap and #PF filtering set by the debugger.
    // If so, do a TD Exit with a synthetic EXCEPTION_OR_NMI exit reason.
    if (tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug &&
        is_voe_in_exception_bitmap())
    {
        vmx_exit_inter_info_t vm_exit_inter_info;
        vm_vmexit_exit_reason_t vm_exit_reason;

        ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &vm_exit_inter_info.raw);

        vm_exit_reason.raw = VMEXIT_REASON_EXCEPTION_OR_NMI;

        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, 0, vm_exit_inter_info.raw);
    }
}

static void save_guest_td_gpr_state_on_td_vmexit(void)
{
    tdx_module_local_t* local_data_ptr = get_local_data();
    tdvps_t* tdvps_ptr = local_data_ptr->vp_ctx.tdvps;

    // GPR's saving: move them from local data area (already saved there by assembly prologue) to current TDVPS
    tdvps_ptr->guest_state.gpr_state.rax = local_data_ptr->td_regs.rax;
    tdvps_ptr->guest_state.gpr_state.rcx = local_data_ptr->td_regs.rcx;
    tdvps_ptr->guest_state.gpr_state.rdx = local_data_ptr->td_regs.rdx;
    tdvps_ptr->guest_state.gpr_state.rbx = local_data_ptr->td_regs.rbx;
    tdvps_ptr->guest_state.gpr_state.rbp = local_data_ptr->td_regs.rbp;
    tdvps_ptr->guest_state.gpr_state.rsi = local_data_ptr->td_regs.rsi;
    tdvps_ptr->guest_state.gpr_state.rdi = local_data_ptr->td_regs.rdi;
    tdvps_ptr->guest_state.gpr_state.r8  = local_data_ptr->td_regs.r8;
    tdvps_ptr->guest_state.gpr_state.r9  = local_data_ptr->td_regs.r9;
    tdvps_ptr->guest_state.gpr_state.r10 = local_data_ptr->td_regs.r10;
    tdvps_ptr->guest_state.gpr_state.r11 = local_data_ptr->td_regs.r11;
    tdvps_ptr->guest_state.gpr_state.r12 = local_data_ptr->td_regs.r12;
    tdvps_ptr->guest_state.gpr_state.r13 = local_data_ptr->td_regs.r13;
    tdvps_ptr->guest_state.gpr_state.r14 = local_data_ptr->td_regs.r14;
    tdvps_ptr->guest_state.gpr_state.r15 = local_data_ptr->td_regs.r15;
}


void td_generic_ve_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qualification,
                        ve_category_e category, uint64_t apic_data)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    tdx_inject_ve((uint32_t)vm_exit_reason.raw, exit_qualification, category, tdvps_p, 0, 0, apic_data);
}


void td_call(tdx_module_local_t* tdx_local_data_ptr, bool_t* interrupt_occurred)
{
    api_error_type retval = UNINITIALIZE_ERROR;
    /**
     * Check CPU mode is 64b
     */
    TDX_LOG("TDCALL exit reason\n");

    if (!is_td_guest_in_64b_mode())
    {
        //Not in CPU 64b mode
        TDX_ERROR("Not in CPU mode 64bit. inject GP\n");
        inject_gp(0);
        return;
    }

    tdx_leaf_and_version_t leaf_opcode;
    leaf_opcode.raw = tdx_local_data_ptr->td_regs.rax;



    if ((leaf_opcode.reserved0 != 0) || (leaf_opcode.reserved1 != 0))
    {
        TDX_ERROR("Leaf and version not supported 0x%llx\n", leaf_opcode.raw);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Only a few functions have multiple versions
    if ((leaf_opcode.version > 0) && !((leaf_opcode.leaf == TDG_VM_RD_LEAF) || (leaf_opcode.leaf == TDG_VP_VEINFO_GET_LEAF)))
    {
        TDX_ERROR("Invalid version %d for leaf %d\n", leaf_opcode.version, leaf_opcode.leaf);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    switch (leaf_opcode.leaf)
    {
        case TDG_MEM_PAGE_ACCEPT_LEAF:
        {
            retval = tdg_mem_page_accept(tdx_local_data_ptr->td_regs.rcx, interrupt_occurred);
            break;
        }
        case TDG_MR_RTMR_EXTEND_LEAF:
        {
            retval = tdg_mr_rtmr_extend(tdx_local_data_ptr->td_regs.rcx, tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_VP_VEINFO_GET_LEAF:
        {
            retval = tdg_vp_veinfo_get((uint8_t)leaf_opcode.version);
            break;
        }
        case TDG_VP_INFO_LEAF:
        {
            retval = tdg_vp_info();
            break;
        }
        case TDG_MR_REPORT_LEAF:
        {
            retval = tdg_mr_report(tdx_local_data_ptr->td_regs.rcx,
                               tdx_local_data_ptr->td_regs.rdx,
                               tdx_local_data_ptr->td_regs.r8,
                               interrupt_occurred);
            break;
        }
        case TDG_VP_CPUIDVE_SET_LEAF:
        {
            retval = tdg_vp_cpuidve_set(tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_VP_VMCALL_LEAF:
        {
            //Special case.  will (or may) not return to the TD but to go to VMM.
            retval = tdg_vp_vmcall(tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_VM_RD_LEAF:
        {
            retval = tdg_vm_rd(tdx_local_data_ptr->td_regs.rdx,
                           tdx_local_data_ptr->td_regs.rcx,
                           leaf_opcode.version);
            break;
        }
        case TDG_VM_WR_LEAF:
        {
            retval = tdg_vm_wr(tdx_local_data_ptr->td_regs.rdx,
                           tdx_local_data_ptr->td_regs.rcx,
                           tdx_local_data_ptr->td_regs.r8,
                           tdx_local_data_ptr->td_regs.r9,
                           leaf_opcode.version);
            break;
        }
        case TDG_SYS_RD_LEAF:
        {
            md_field_id_t field_code = {.raw = tdx_local_data_ptr->td_regs.rdx};
            retval = tdg_sys_rd(field_code);
            break;
        }
        case TDG_SYS_RDALL_LEAF:
        {
            md_field_id_t field_code = {.raw = tdx_local_data_ptr->td_regs.r8};
            retval = tdg_sys_rdall(tdx_local_data_ptr->td_regs.rdx, field_code);
            break;
        }
        case TDG_VP_RD_LEAF:
        {
            retval = tdg_vp_rd(tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_VP_WR_LEAF:
        {
            retval = tdg_vp_wr(tdx_local_data_ptr->td_regs.rdx,
                               tdx_local_data_ptr->td_regs.r8,
                               tdx_local_data_ptr->td_regs.r9);
            break;
        }
        case TDG_SERVTD_RD_LEAF:
        {
            retval = tdg_servtd_rd(tdx_local_data_ptr->td_regs.rcx,
                                   tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_SERVTD_WR_LEAF:
        {
            retval = tdg_servtd_wr(tdx_local_data_ptr->td_regs.rcx,
                                   tdx_local_data_ptr->td_regs.rdx,
                                   tdx_local_data_ptr->td_regs.r8,
                                   tdx_local_data_ptr->td_regs.r9);
            break;
        }
        case TDG_MR_VERIFYREPORT_LEAF:
        {
            retval = tdg_mr_verifyreport(tdx_local_data_ptr->td_regs.rcx);

            break;
        }
        case TDG_MEM_PAGE_ATTR_RD_LEAF:
        {
            retval = tdg_mem_page_attr_rd((pa_t)tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_MEM_PAGE_ATTR_WR_LEAF:
        {
            retval = tdg_mem_page_attr_wr(
                (page_info_api_input_t)tdx_local_data_ptr->td_regs.rcx,
                (gpa_attr_t)tdx_local_data_ptr->td_regs.rdx,
                (attr_flags_t)tdx_local_data_ptr->td_regs.r8);
            break;
        }
        case TDG_VP_ENTER_LEAF:
        {
            retval = tdg_vp_enter(tdx_local_data_ptr->td_regs.rcx,
                                  tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_VP_INVEPT_LEAF:
        {
            retval = tdg_vp_invept(tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_VP_INVVPID_LEAF:
        {
            retval = tdg_vp_invvpid(tdx_local_data_ptr->td_regs.rcx,
                                    tdx_local_data_ptr->td_regs.rdx, interrupt_occurred);
            break;
        }
        case TDG_MR_KEY_GET_LEAF:
        {
            retval = tdg_mr_key_get(tdx_local_data_ptr->td_regs.rcx,
                                    tdx_local_data_ptr->td_regs.rdx,
                                    tdx_local_data_ptr->td_regs.r8);
            break;
        }
        default:
        {
            TDX_ERROR("Invalid leaf number for TDCALL\n");
            retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
            break;
        }
    }

EXIT:

    tdx_sanity_check(retval != UNINITIALIZE_ERROR, FATAL_ERROR_ID_251, 1);

    // Handling of stuck host-priority locks
    api_error_code_t error_code = { .raw = retval };
    error_code.details_l2 = 0;

    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t*  tdcs_p  = tdx_local_data_ptr->vp_ctx.tdcs;

    // Make sure the active VMCS is set to the current VM's VMCS.
    set_vm_vmcs_as_active(tdvps_p, tdvps_p->management.curr_vm);

    if (error_code.raw == TDX_OPERAND_BUSY_HOST_PRIORITY)
    {
        // TDCALL leaf function terminated due to host priority.
        // If this keeps happening for more than HP_LOCK_TIMEOUT TSC ticks,
        // TD exit to the host VMM with an error indication.

        // Convert the status to TDX_OPERAND_BUSY in order to be backward-compatible with older TDs
        error_code.raw = TDX_OPERAND_BUSY;
        error_code.details_l2 = ((api_error_code_t)retval).details_l2;
        retval = error_code.raw;

        if (!tdvps_p->management.hp_lock_busy)
        {
            // First time
            tdvps_p->management.hp_lock_busy = true;
            tdvps_p->management.hp_lock_busy_start = ia32_rdtsc();
        }
        else if (ia32_rdtsc() - tdvps_p->management.hp_lock_busy_start >= tdcs_p->executions_ctl_fields.hp_lock_timeout)
        {
            tdvps_p->management.hp_lock_busy = false;

            // Update the retval so that guest TD will know the lock reason failure
            tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rax = retval;
            async_tdexit_empty_reason(TDX_HOST_PRIORITY_BUSY_TIMEOUT);
        }
    }
    else
    {
        tdvps_p->management.hp_lock_busy = false;
    }

    if (*interrupt_occurred == false)
    {
        tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rax = retval;
    }
    else
    {
        // If TDCALL was interrupt we must clear blocking state
        clear_movss_sti_blocking();

        if (!tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.perfmon)
        {
            ia32_wrmsr(IA32_PMC_FX0_CTR_MSR_ADDR, ia32_rdmsr(IA32_PMC_FX0_CTR_MSR_ADDR) + 2);
        }
    }
}

/**
 * @brief Handle VM entry failures per basic exit reason
 **/
static void handle_vm_entry_failures(tdx_module_local_t* tdx_local_data_ptr,
        vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t vm_exit_qualification)
{
    if (vm_exit_reason.vmenter_fail != 0)
    {
        switch (vm_exit_reason.basic_reason)
        {
            case VMEXIT_REASON_FAILED_VMENTER_GS:
                if (tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug)
                {
                    async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
                }
                else
                {
                    async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
                }
                break;
            case VMEXIT_REASON_FAILED_VMENTER_MSR:
            {
                // VM entry failure due to VM_ENTRY_FAILURE_MSR_LOADING is only applicable for MSR load lists.
                // We don't use them so this is unexpected and should be a fatal error.
                TDX_ERROR("VM entry failure due to VM_ENTRY_FAILURE_MSR_LOADING is not expected\n");
                extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                           tdx_local_data_ptr->current_td_vm_id,
                                                                                                           (uint32_t)vm_exit_reason.basic_reason,
                                                                                                           0);
                fatal_error(FATAL_ERROR_ID_92, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
                break;
            }
            case VMEXIT_REASON_FAILED_VMENTER_MC:
                // This VM entry failure was due to a #MC, disable the TD
                    async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
                break;
                // No other exit reasons should happen on VM entry failure
            default:
            {
                TDX_ERROR("Unexpected VMENTRY failure: Exit reason = %d, Exit qualification = %d\n",
                        vm_exit_reason.basic_reason, vm_exit_qualification.raw);

                extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                           tdx_local_data_ptr->current_td_vm_id,
                                                                                                           (uint32_t)vm_exit_reason.basic_reason,
                                                                                                           0);
                fatal_error(FATAL_ERROR_ID_93, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
                break;
            }
        }
        // Flow should never reach here
        tdx_sanity_check(0, FATAL_ERROR_ID_252, 2);
    }
}

static void handle_idt_vectoring(vmx_idt_vectoring_info_t idt_vectoring_info)
{
    vmx_entry_inter_info_t vm_entry_inter_info;

    // if a virtual NMI was re-injected, clear virtual NMI blocking
    if (idt_vectoring_info.interruption_type == VMEXIT_INTER_INFO_TYPE_NMI)
    {
        vmx_guest_inter_state_t guest_inter_state;
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
        guest_inter_state.blocking_by_nmi = 0;
        ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
    }

    // Copy IDT vectoring fields to VM entry exception fields. On the next
    // VM entry, the CPU will inject a VOE.

    vm_entry_inter_info.raw = idt_vectoring_info.raw;
    vm_entry_inter_info.reserved = (uint32_t)0;
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, vm_entry_inter_info.raw);

    if (idt_vectoring_info.error_code_valid)
    {
        uint64_t idt_vectoring_error_code;
        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE, &idt_vectoring_error_code);
        ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, idt_vectoring_error_code);
    }

    uint64_t vm_exit_instruction_length;
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &vm_exit_instruction_length);
    ia32_vmwrite(VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE, vm_exit_instruction_length);
}

stepping_filter_e tdx_td_l1_l2_dispatcher_common_prologue(tdx_module_local_t* local_data, uint16_t vm_id,
        vm_vmexit_exit_reason_t* vm_exit_reason, vmx_exit_qualification_t* vm_exit_qualification,
    vmx_exit_inter_info_t* vm_exit_inter_info)
{
    TDX_LOG("TD Dispatcher Entry from VM %d\n", vm_id);

    // Save current time to verify on next TD entry and for TDEXIT filter checks
    local_data->vp_ctx.tdvps->management.last_exit_tsc = ia32_rdtsc();

    // Save TD GPR state to TDVPS.
    // DR's, XSTATE and XCR's, MSR's will be saved if exit to TD will be required later
    // In case of need of performance improvement - should be done only when actual vmexit to VMM happens
    save_guest_td_gpr_state_on_td_vmexit();

    local_data->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl = ia32_rdmsr(IA32_SPEC_CTRL_MSR_ADDR);
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, GET_TDX_MODULE_IA32_SPEC_CTRL(),
            local_data->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl);

    // Clear NMI unblocking flag;
    // For L1 this is used only for L2 VM entries following L2 VM exits
    // For L2 it will be set later if required, and using on L2 VM entry
    local_data->vp_ctx.tdvps->management.nmi_unblocking_due_to_iret = false;

    // Get exit information
    ia32_vmread(VMX_VM_EXIT_REASON_ENCODE, &vm_exit_reason->raw);

    if (vm_exit_reason->vmenter_fail == 0)
    {
        // If no failed VMENTRY occurred then the VMCS is launched after a VMEXIT
        local_data->vp_ctx.tdvps->management.vm_launched[vm_id] = true;
    }


    ia32_vmread(VMX_VM_EXIT_QUALIFICATION_ENCODE, &vm_exit_qualification->raw);
    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &vm_exit_inter_info->raw);

    if (local_data->vp_ctx.tdr->management_fields.fatal)
    {
        // A #MC VM exit has occurred on another LP, indicating memory integrity error.
        // Do an async TD exit without accessing TD memory.
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE, *vm_exit_reason, vm_exit_qualification->raw, 0, 0, vm_exit_inter_info->raw);
    }

    // If a preempted bus lock has been reported in the exit reason, set the local data bus lock flag.
    // This flag is sticky bit; it gets reset only when reported on TD exit.
    if (vm_exit_reason->bus_lock_preempted)
    {
        local_data->vp_ctx.bus_lock_preempted = true;
    }

    // Sanity check
    if (!local_data->vp_ctx.tdcs->executions_ctl_fields.attributes.debug &&
        ((vm_exit_reason->reserved_0           != 0) ||
        (vm_exit_reason->pending_mtf          != 0) ||
        (vm_exit_reason->parallel             != 0) ||
        (vm_exit_reason->reserved_1           != 0)))
    {
        TDX_ERROR("Fatal error, exit reason corrupted - 0x%llx\n", vm_exit_reason->raw);
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        uint64_t idt_vectoring, activity, interruptibility, entry_int;

        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring);
        ia32_vmread(VMX_GUEST_SLEEP_STATE_ENCODE, &activity);
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &interruptibility);
        ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &entry_int);

        TDX_ERROR("IDT vectoring = 0x%llx, activity state = 0x%llx\n",
                idt_vectoring, activity);
        TDX_ERROR("Interruptibility state = 0x%llx, Entry intr info = 0x%llx\n",
                interruptibility, entry_int);
#endif // DEBUGFEATURE_TDX_DBG_TRACE
        fatal_error(FATAL_ERROR_ID_94, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    uint64_t guest_rip = 0, guest_cs_base = 0;

    ia32_vmread(VMX_GUEST_RIP_ENCODE, &guest_rip);
    ia32_vmread(VMX_GUEST_CS_BASE_ENCODE, &guest_cs_base);
    TDX_LOG("Exit reason = %d, Guest RIP = 0x%llx, CS Base = 0x%llx\n",
            vm_exit_reason->basic_reason, guest_rip, guest_cs_base);
    TDX_LOG("RAX = 0x%llx, RBX = 0x%llx, RCX = 0x%llx, RDX = 0x%llx\nRSP = 0x%llx, RBP = 0x%llx, RSI = 0x%llu, RDI = 0x%llu\n",
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rax,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rbx,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rcx,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rdx,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rsp,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rbp,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rsi,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.rdi);
    TDX_LOG("R8 = 0x%llx, R9 = 0x%llx, R10 = 0x%llu, R11 = 0x%llu\nR12 = 0x%llx, R13 = 0x%llx, R14 = 0x%llu, R15 = 0x%llu\n",
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r8,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r9,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r10,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r11,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r12,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r13,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r14,
            local_data->vp_ctx.tdvps->guest_state.gpr_state.r15);

#endif // DEBUGFEATURE_TDX_DBG_TRACE

    // If the TD is debuggable, the host VMM can request all L2 exits to be converted to TD exits.
    if ((vm_id > 0) && local_data->vp_ctx.tdvps->management.l2_debug_ctls[vm_id].td_exit_on_l2_vm_exit)
    {
        tdx_debug_assert(local_data->vp_ctx.tdcs->executions_ctl_fields.attributes.debug == 1);
        async_tdexit_to_vmm(TDX_TD_EXIT_ON_L2_VM_EXIT, *vm_exit_reason, vm_exit_qualification->raw, 0, 0, vm_exit_inter_info->raw);
    }

    /*------------------------------
       Single/Zero Step Filtering
    ------------------------------*/
    stepping_filter_e vmexit_stepping_result = vmexit_stepping_filter(*vm_exit_reason, *vm_exit_qualification, *vm_exit_inter_info,
                                                                      (bool_t)local_data->vp_ctx.tdcs->executions_ctl_fields.attributes.perfmon);
    if (vmexit_stepping_result == FILTER_FAIL_TDEXIT_RDRAND)
    {
        fatal_error(FATAL_ERROR_ID_178, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    // if stepping cannot be done safely, kill the TD and exit
    if (vmexit_stepping_result == FILTER_FAIL_TDEXIT_WRONG_APIC_MODE)
    {
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE, *vm_exit_reason, vm_exit_qualification->raw, 0, 0, vm_exit_inter_info->raw);
    }

    if (vmexit_stepping_result != FILTER_OK_CONTINUE)
    {
        return vmexit_stepping_result;
    }

    if (vm_id == 0) // Handle IDT vectoring only on L1 VM
    {
        vmx_idt_vectoring_info_t idt_vectoring_info;
        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring_info.raw);

        // VM Exits during Event Delivery via IDT in the Guest TD
        // If the VM exit happened while the CPU attempted to deliver a vectored
        // event via the guest's IDT, collect the information and set up for a
        // Vector-On-Entry (VOE) on the following VM entry.
        // Note that the VOE information may later be changed, e.g., if the flow needs to inject a #PF.

        if (idt_vectoring_info.valid == 1)
        {
            handle_idt_vectoring(idt_vectoring_info);
        }
    }

    bool_t nv_match = false;
    l2_exit_route_t l2_routing = L2_EXIT_ROUTE_TD_EXIT;

    if (vm_exit_reason->basic_reason == VMEXIT_REASON_INTERRUPT)
    {
        if (vm_id == 0)
        {
            if (!nv_match)
            {
                async_tdexit_to_vmm(TDX_SUCCESS, *vm_exit_reason, vm_exit_qualification->raw, 0, 0, vm_exit_inter_info->raw);
            }
        }
        else
        {
            l2_routing = td_l2_interrupt_exit(local_data, *vm_exit_inter_info, *vm_exit_reason,
                                              *vm_exit_qualification, vm_id);
        }
    }

    UNUSED(l2_routing);

    return vmexit_stepping_result;
}

void tdx_td_dispatcher(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    vm_vmexit_exit_reason_t vm_exit_reason;
    vmx_exit_qualification_t vm_exit_qualification;
    vmx_exit_inter_info_t vm_exit_inter_info;

    vmx_guest_inter_state_t guest_inter_state;
    vmx_procbased_ctls_t vm_procbased_ctls;

    td_param_attributes_t attr;

    bool_t interrupt_occurred = false;

    uint16_t vm_id = tdx_local_data_ptr->vp_ctx.tdvps->management.curr_vm;

    tdx_sanity_check((vm_id == tdx_local_data_ptr->current_td_vm_id) && (vm_id == 0), FATAL_ERROR_ID_253, 35);

    bhb_drain_sequence(get_global_data());

    stepping_filter_e vmexit_stepping_result;
    vmexit_stepping_result = tdx_td_l1_l2_dispatcher_common_prologue(tdx_local_data_ptr, 0, &vm_exit_reason,
                                    &vm_exit_qualification, &vm_exit_inter_info);

    if (vmexit_stepping_result != FILTER_OK_CONTINUE)
    {
        goto EXIT;
    }

    handle_vm_entry_failures(tdx_local_data_ptr, vm_exit_reason, vm_exit_qualification);

    attr = tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes;

    switch (vm_exit_reason.basic_reason)
    {
        case VMEXIT_REASON_IO_INSTRUCTION:
        case VMEXIT_REASON_HLT_INSTRUCTION:
        case VMEXIT_REASON_INVD_INSTRUCTION:
        case VMEXIT_REASON_VMCALL_INSTRUCTION:
        case VMEXIT_REASON_WBINVD_INSTRUCTION:
            td_generic_ve_exit(vm_exit_reason, vm_exit_qualification.raw, VE_INFO_NON_CONFIG_PARAVIRT, 0);
            break;
        case VMEXIT_REASON_APIC_WRITE:
        {
            td_generic_ve_exit(vm_exit_reason, vm_exit_qualification.raw, VE_INFO_NON_CONFIG_PARAVIRT, 0);
            break;
        }
        // Unconditional #VE injection, but VM exit itself is conditioned on some configuration
        case VMEXIT_REASON_PCONFIG: // If CPUID(0x7,0x0).EDX[18] is virtualized as 0, PCONFIG is disabled and there's no VM exit
            td_generic_ve_exit(vm_exit_reason, vm_exit_qualification.raw, VE_INFO_CONFIG_PARAVIRT, 0);
            break;

        case VMEXIT_REASON_GETSEC_INSTRUCTION:
        case VMEXIT_REASON_RSM_INSTRUCTION:
        case VMEXIT_REASON_VMCLEAR_INSTRUCTION:
        case VMEXIT_REASON_VMLAUNCH_INSTRUCTION:
        case VMEXIT_REASON_VMPTRLD_INSTRUCTION:
        case VMEXIT_REASON_VMPTRST_INSTRUCTION:
        case VMEXIT_REASON_VMREAD_INSTRUCTION:
        case VMEXIT_REASON_VMRESUME_INSTRUCTION:
        case VMEXIT_REASON_VMWRITE_INSTRUCTION:
        case VMEXIT_REASON_VMXOFF_INSTRUCTION:
        case VMEXIT_REASON_VMXON_INSTRUCTION:
        case VMEXIT_REASON_INVLEPT:
        case VMEXIT_REASON_INVLVPID:
        case VMEXIT_REASON_VMFUNC_INSTRUCTION:
        case VMEXIT_REASON_ENCLS_INSTRUCTION:
        case VMEXIT_REASON_ENCLV_INSTRUCTION:
        case VMEXIT_REASON_ENQCMDS_PASID_TRANSLATION_FAILURE:
        case VMEXIT_REASON_SEAMCALL:
        case VMEXIT_REASON_MWAIT_INSTRUCTION:
        case VMEXIT_REASON_MONITOR_INSTRUCTION:
            inject_ud();
            break;

        // Unconditional #GP injection
        case VMEXIT_REASON_ENQCMD_PASID_TRANSLATION_FAILURE:
        {
            inject_gp(0);
            break;
        }

        case VMEXIT_REASON_TASK_SWITCH:
        case VMEXIT_REASON_BUS_LOCK:
        case VMEXIT_REASON_INIT_EVENT:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_NOTIFICATION:
            if (vm_exit_qualification.notification.nmi_unblocking_due_to_iret)
            {
                ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
                guest_inter_state.blocking_by_nmi = 1;
                ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
            }
            async_tdexit_to_vmm((vm_exit_qualification.notification.vm_context_invalid) ?
                                                  TDX_NON_RECOVERABLE_TD : TDX_SUCCESS,
                                                  vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_TRIPLE_FAULT:
            async_tdexit_to_vmm(TDX_NON_RECOVERABLE_VCPU, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_SMI_OTHER_EVENT:
            // If this exit was due to an MSMI, disable the TD.  Else, do a normal async TD exit.
            async_tdexit_to_vmm((vm_exit_qualification.smi.msmi) ?
                                                  TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE  : TDX_SUCCESS,
                                                  vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_INTERRUPT:
            // Already handled in the prologue
            break;
        case VMEXIT_REASON_C_STATE_SMI:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_RDPMC_INSTRUCTION:
            td_rdpmc_exit(vm_exit_reason, vm_exit_qualification.raw);
            break;
        case VMEXIT_REASON_EPT_MISCONFIGURATION:
            td_ept_misconfiguration_exit(vm_exit_reason);
            break;
        case VMEXIT_REASON_CPUID_INSTRUCTION:
            td_cpuid_exit();
            break;
        case VMEXIT_REASON_EPT_VIOLATION:
            td_ept_violation_exit(vm_exit_qualification, vm_exit_reason);
            break;
        case VMEXIT_REASON_XSETBV_INSTRUCTION:
            td_xsetbv_instruction_exit();
            break;
        case VMEXIT_REASON_CR_ACCESS:
            if (!td_cr_access_exit(vm_exit_qualification))
            {
                // CR access VM exit can only fail for debug TDs, where the host VMM enabled exit on CR3, CR8 etc.
                if (attr.debug)
                {
                    async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
                }
                else
                {
                    async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
                }
            }
            break;
        case VMEXIT_REASON_EXCEPTION_OR_NMI:
            td_exception_or_nmi_exit(vm_exit_reason, vm_exit_qualification, vm_exit_inter_info);
            break;
        case VMEXIT_REASON_MSR_READ:
        case VMEXIT_REASON_MSR_WRITE:
        {
            uint16_t status = (vm_exit_reason.basic_reason == VMEXIT_REASON_MSR_READ) ?
                                            td_rdmsr_exit() : td_wrmsr_exit();
            uint16_t status_category = (status >> 8) & 0xFF;
            status &= 0xFF;
            if (status != TD_MSR_ACCESS_SUCCESS)
            {
                if (status == TD_MSR_ACCESS_GP)
                {
                    inject_gp(0);
                }
                else
                {
                    tdx_sanity_check((status == TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION), FATAL_ERROR_ID_254, 3);
                    td_generic_ve_exit(vm_exit_reason, 0, status_category, 0);
                }
            }
            break;
        }
        case VMEXIT_REASON_TDCALL:
            td_call(tdx_local_data_ptr, &interrupt_occurred);
            break;
        case VMEXIT_REASON_NMI_WINDOW:
            // NMI Window is open.  Inject an NMI if applicable
            td_nmi_exit(tdx_local_data_ptr);
            break;
        case VMEXIT_REASON_EPT_PML_FULL:
        {
            // PML is only allowed for debuggable TDs
            if (attr.debug)
            {
                async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }
            // otherwise, others are not expected
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                       tdx_local_data_ptr->current_td_vm_id,
                                                                                                       (uint32_t)vm_exit_reason.basic_reason,
                                                                                                       0);
            fatal_error(FATAL_ERROR_ID_95, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
            break;
        }
        case VMEXIT_REASON_LOADIWK_INSTRUCTION:
        case VMEXIT_REASON_RDTSC_INSTRUCTION:
        case VMEXIT_REASON_DR_ACCESS:
        case VMEXIT_REASON_PAUSE_INSTRUCTION:
        case VMEXIT_REASON_VIRTUALIZED_EOI:
        case VMEXIT_REASON_GDTR_IDTR_ACCESS:
        case VMEXIT_REASON_LDTR_TR_ACCESS:
        case VMEXIT_REASON_RDTSCP:
        case VMEXIT_REASON_FAILED_VMENTER_GS:
        case VMEXIT_REASON_FAILED_VMENTER_MSR:
        case VMEXIT_REASON_FAILED_VMENTER_MC:
        case VMEXIT_REASON_TPR_BELOW_THRESHOLD:
        case VMEXIT_REASON_SIPI_EVENT:
        case VMEXIT_REASON_SMI_IO_EVENT:
        case VMEXIT_REASON_INTERRUPT_WINDOW:
        case VMEXIT_REASON_INVLPG_INSTRUCTION:
        case VMEXIT_REASON_RDRAND_INSTRUCTION:
        case VMEXIT_REASON_INVPCID_INSTRUCTION:
            // Fatal error
        default:
        {
            // If the TD is debuggable then other exit reasons are expected
            if (tdx_local_data_ptr->vp_ctx.attributes.debug)
            {
                async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }
            else
            {
                async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }

            // Otherwise, other exit reasons are not expected
            TDX_ERROR("Fatal/unknown exit reason %d \n", vm_exit_reason.basic_reason);
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                       tdx_local_data_ptr->current_td_vm_id,
                                                                                                       (uint32_t)vm_exit_reason.basic_reason,
                                                                                                       0);
            fatal_error(FATAL_ERROR_ID_21, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);

            break;
        }
    }

    // Make sure the active VMCS is set to the current VM's VMCS.
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    set_vm_vmcs_as_active(tdvps_p, tdvps_p->management.curr_vm);

    // Check if exception was injected
    // Entry Interrupt Info valid bit is cleared automatically on every VMEXIT
    vmx_entry_inter_info_t entry_intr_info;
    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));

    // Check if we need to advance guest rip or handle pend NMI
    if (!entry_intr_info.valid && !interrupt_occurred)
    {
        // If PEND_NMI was requested, and there's no pending #VE (which should be handled
        // by the guest TD before NMI), set NMI Window Exiting execution control so NMI
        // can be injected at the proper time.
        if (tdvps_p->management.pend_nmi && (tdvps_p->ve_info.valid == 0))
        {
            ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
            vm_procbased_ctls.nmi_window_exiting = 1;
            ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
        }

        increment_fixed_ctr0(tdx_local_data_ptr->vp_ctx.tdcs);
        advance_guest_rip();
    }

    bus_lock_exit();

EXIT:

    check_pending_voe_on_debug_td_return();

    //Return to TD
    tdx_return_to_td(true, false, &tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state);

    //Unreachable code. panic
    tdx_sanity_check(0, FATAL_ERROR_ID_255, 0);
}
