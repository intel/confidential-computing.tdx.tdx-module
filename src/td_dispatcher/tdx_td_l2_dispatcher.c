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
 * @file tdx_td_l2_dispatcher.c
 * @brief L2 VM Exit from TD entry point and API dispatcher
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
#include "td_dispatcher/vm_exits_l2/td_l2_vmexit.h"

static void bus_lock_exit_l2(tdx_module_local_t* local_data_ptr, vmx_exit_inter_info_t vm_exit_inter_info)
{
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

        UNUSED(vm_exit_inter_info);
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, 0, 0);
    }
}

/**
 * @brief Handle L2 VM entry failures per basic exit reason
 **/
static void handle_l2_vm_entry_failures(vm_vmexit_exit_reason_t vm_exit_reason,
                                        vmx_exit_qualification_t vm_exit_qualification,
                                        vmx_exit_inter_info_t vm_exit_inter_info)
{
    if (vm_exit_reason.vmenter_fail != 0)
    {
        switch (vm_exit_reason.basic_reason)
        {
            case VMEXIT_REASON_FAILED_VMENTER_GS:
                // Invalid guest state is (typically) caused by L1 VMM operation
                td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
                break;
            case VMEXIT_REASON_FAILED_VMENTER_MC:
                // This VM entry failure was due to a #MC, disable the TD
                async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE, vm_exit_reason,
                                    vm_exit_qualification.raw, 0, 0, 0);
                break;
                // No other exit reasons should happen on VM entry failure
            default:
            {
                tdx_module_local_t* tdx_local_data_ptr = get_local_data();
                extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                           tdx_local_data_ptr->current_td_vm_id,
                                                                                                           (uint32_t)vm_exit_reason.basic_reason,
                                                                                                           0);
                fatal_error(FATAL_ERROR_ID_96, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
                break;
            }
        }
        // Flow should never reach here
        tdx_sanity_check(0, FATAL_ERROR_ID_256, 102);
    }
}

void tdx_td_l2_dispatcher(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    vm_vmexit_exit_reason_t vm_exit_reason;
    vmx_exit_qualification_t vm_exit_qualification;
    vmx_exit_inter_info_t vm_exit_inter_info;

    TDX_LOG("L2 dispatcher invoked\n");

    uint16_t vm_id = tdx_local_data_ptr->vp_ctx.tdvps->management.curr_vm;

    tdx_sanity_check((vm_id == tdx_local_data_ptr->current_td_vm_id) && (vm_id > 0) && (vm_id < MAX_VMS), FATAL_ERROR_ID_257, 55);

    bhb_drain_sequence(get_global_data());

    stepping_filter_e vmexit_stepping_result;
    vmexit_stepping_result = tdx_td_l1_l2_dispatcher_common_prologue(tdx_local_data_ptr, vm_id, &vm_exit_reason,
                                    &vm_exit_qualification, &vm_exit_inter_info);

    if (vmexit_stepping_result != FILTER_OK_CONTINUE)
    {
        goto EXIT;
    }

    handle_l2_vm_entry_failures(vm_exit_reason, vm_exit_qualification, vm_exit_inter_info);

    vmx_procbased_ctls2_t procbased_exec_ctls2 = { .raw = tdvps_p->management.shadow_procbased_exec_ctls2[0] };

    // Not actually used because interrupts don't occur on TDVMCALL
    bool_t interrupt_occurred = false;

    switch (vm_exit_reason.basic_reason)
    {
        case VMEXIT_REASON_EXCEPTION_OR_NMI:
            td_l2_exception_or_nmi_exit(vm_exit_reason, vm_exit_qualification, vm_exit_inter_info);
            break;
        case VMEXIT_REASON_INTERRUPT:
        {
            // Already handled in the prologue
            // Resume L2 - mark that there's an interrupt to not advance the guest RIP
            interrupt_occurred = true;
            break;
        }
        case VMEXIT_REASON_C_STATE_SMI:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                                vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_INIT_EVENT:
        case VMEXIT_REASON_SMI_IO_EVENT:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_SMI_OTHER_EVENT:
            // If this exit was due to an MSMI, disable the TD.  Else, do a normal async TD exit.
            async_tdexit_to_vmm((vm_exit_qualification.smi.msmi) ?
                    TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE  : TDX_SUCCESS,
                    vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_BUS_LOCK:
            UNUSED(procbased_exec_ctls2);
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_NOTIFICATION:
            // If the context is corrupted, always TD exit.
            // Else, If the host VMM configured a TD exit on notification, do it.
            // Else, exit to the L1 VMM.
            // Note that if both host VMM and L1 VMM didn't configure a VM exit on notification, we wouldn't get here.
            if (vm_exit_qualification.notification.vm_context_invalid)
            {
                async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }
            {
                // EPT violation is one case where NMI may have been unblocked by an IRET instruction
                // before the VM exit happened.  NMI unblocking is only applicable is no IDT vectoring is indicated.
                // Record this so NMI will be re-blocked if L2 will be reentered following a TD exit and TD entry.
                if (vm_exit_qualification.ept_violation.nmi_unblocking_due_to_iret &&
                    !is_idt_vectoring_info_valid())
                {
                    tdvps_p->management.nmi_unblocking_due_to_iret = true;
                }

                async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }

            break;

        // Unconditional L2->L1 exit
        case VMEXIT_REASON_TRIPLE_FAULT:
        case VMEXIT_REASON_TASK_SWITCH:
        case VMEXIT_REASON_VMCALL_INSTRUCTION:
        case VMEXIT_REASON_APIC_WRITE:
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
        case VMEXIT_REASON_SGX_CONFLICT:
        case VMEXIT_REASON_ENQCMD_PASID_TRANSLATION_FAILURE:
        case VMEXIT_REASON_ENQCMDS_PASID_TRANSLATION_FAILURE:
        case VMEXIT_REASON_SEAMCALL:
        case VMEXIT_REASON_MWAIT_INSTRUCTION:
        case VMEXIT_REASON_MONITOR_INSTRUCTION:
        case VMEXIT_REASON_CPUID_INSTRUCTION:
        case VMEXIT_REASON_LOADIWK_INSTRUCTION:
        case VMEXIT_REASON_NMI_WINDOW:
        case VMEXIT_REASON_INTERRUPT_WINDOW:
        case VMEXIT_REASON_INVLPG_INSTRUCTION:
        case VMEXIT_REASON_RDTSC_INSTRUCTION:
        case VMEXIT_REASON_DR_ACCESS:
        case VMEXIT_REASON_PAUSE_INSTRUCTION:
        case VMEXIT_REASON_GDTR_IDTR_ACCESS:
        case VMEXIT_REASON_LDTR_TR_ACCESS:
        case VMEXIT_REASON_RDTSCP:
        case VMEXIT_REASON_PREEMPTION_TIMER_EXPIRED:
        case VMEXIT_REASON_RDRAND_INSTRUCTION:
        case VMEXIT_REASON_RDSEED_INSTRUCTION:
        case VMEXIT_REASON_INVPCID_INSTRUCTION:
        case VMEXIT_REASON_XSAVES_INSTRUCTION:
        case VMEXIT_REASON_XRSTORS_INSTRUCTION:
        case VMEXIT_REASON_UMWAIT:
        case VMEXIT_REASON_TPAUSE:
        case VMEXIT_REASON_RDPMC_INSTRUCTION:
        case VMEXIT_REASON_XSETBV_INSTRUCTION:
        case VMEXIT_REASON_TPR_BELOW_THRESHOLD:
        case VMEXIT_REASON_VIRTUALIZED_EOI:
            td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
            break;

        // L2->L1 exit or #VE injection, depending of TDVPS.ENABLE_EXTENDED_VE
        case VMEXIT_REASON_HLT_INSTRUCTION:
        case VMEXIT_REASON_INVD_INSTRUCTION:
        case VMEXIT_REASON_IO_INSTRUCTION:
        case VMEXIT_REASON_WBINVD_INSTRUCTION:
        case VMEXIT_REASON_PCONFIG:
            {
                td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
            }
            break;

        case VMEXIT_REASON_CR_ACCESS:
        {
            uint16_t status = td_l2_cr_access_exit(vm_exit_qualification, vm_id);
            status &= 0xFF;
            if (status != CR_ACCESS_SUCCESS)
            {
                if (status == CR_ACCESS_GP)
                {
                    inject_gp(0);
                }
                else
                {
                    td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
                }
            }

            break;
        }
        case VMEXIT_REASON_MSR_READ:
        case VMEXIT_REASON_MSR_WRITE:
        {
            td_msr_access_status_t status = (vm_exit_reason.basic_reason == VMEXIT_REASON_MSR_READ) ?
                                            td_rdmsr_exit() : td_wrmsr_exit();
            status &= 0xFF;
            if (status != TD_MSR_ACCESS_SUCCESS)
            {
                if (status == TD_MSR_ACCESS_GP)
                {
                    inject_gp(0);
                }
                else
                {
                    td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
                }
            }
            break;
        }
        case VMEXIT_REASON_EPT_VIOLATION:
            td_l2_ept_violation_exit(vm_exit_reason, vm_exit_qualification);
            break;
        case VMEXIT_REASON_EPT_MISCONFIGURATION:
            td_ept_misconfiguration_exit(vm_exit_reason);
            break;
        case VMEXIT_REASON_TDCALL:
        {
            tdx_leaf_and_version_t leaf_opcode;
            leaf_opcode.raw = tdx_local_data_ptr->td_regs.rax;

            if (tdvps_p->management.l2_ctls[vm_id].enable_tdvmcall && (leaf_opcode.leaf == TDG_VP_VMCALL_LEAF))
            {
                td_call(tdx_local_data_ptr, &interrupt_occurred);
                // interrupt_occurred not actually used because interrupts don't occur on TDVMCALL
                tdx_debug_assert(interrupt_occurred != true);
            }
            else
            {
                td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
            }
            break;
        }
        case VMEXIT_REASON_EPT_PML_FULL:
        {
            // PML is only allowed for debuggable TDs
            if (tdcs_p->executions_ctl_fields.attributes.debug)
            {
                async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }
            // otherwise, others are not expected
            extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(tdx_local_data_ptr->vp_ctx.tdr_pa.raw,
                                                                                                       tdx_local_data_ptr->current_td_vm_id,
                                                                                                       (uint32_t)vm_exit_reason.basic_reason,
                                                                                                       0);
            fatal_error(FATAL_ERROR_ID_97, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
            break;
        }
        default:
        {
            // If the TD is debuggable then other exit reasons are expected
            if (tdcs_p->executions_ctl_fields.attributes.debug)
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
            fatal_error(FATAL_ERROR_ID_98, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO,&extended_fatal_info);

            break;
        }
    }

    // Make sure the active VMCS is set to the current VM's VMCS.
    set_vm_vmcs_as_active(tdvps_p, tdvps_p->management.curr_vm);

    // Check if we need to advance guest rip (only if no exception was injected)
    // Entry Interrupt Info valid bit is cleared automatically on every VMEXIT
    vmx_entry_inter_info_t entry_intr_info;
    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));

    if (!entry_intr_info.valid && !interrupt_occurred)
    {
        increment_fixed_ctr0(tdcs_p);
        advance_guest_rip();
    }

    bus_lock_exit_l2(tdx_local_data_ptr, vm_exit_inter_info);

EXIT:

    // If the L2 was in the middle of IDT vectoring when the VM exit happened, re-inject it as VOE
    (void)reinject_idt_vectoring_event_if_any();

    // Check if a Vector-On-Entry (VOE) is being injected, and if so,
    // if it matches the VMCS' exception bitmap and #PF filtering.
    if (is_voe_in_exception_bitmap())
    {
        // Convert the VOE fields in VMCS to exit information fields and do an L2->L1 exit
        convert_l2_voe_to_l1_exit();
        td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info, false);
    }

    // If NMI unblocking by IRET was indicated during VM exit, re-block NMI
    if (tdvps_p->management.nmi_unblocking_due_to_iret)
    {
        set_guest_inter_blocking_by_nmi();
    }

    set_vmx_preemption_timer(tdvps_p, vm_id);

    //Return to TD
    tdx_return_to_td(true, false, &tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state);

    resume_l1_and_emulate_termination(L2_ENTRY_FAILURE_AFTER_L2_EXIT);
}

