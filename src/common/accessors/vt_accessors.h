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
 * @file vmcs_accessors.h
 * @brief VMCS Accessors Definitions
 */

#ifndef SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_
#define SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "ia32_accessors.h"
#include "helpers/error_reporting.h"
#include "tdx_api_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER

typedef uint64_t vmcs_ptr_t;

/**
 * @brief Read from VMCS entry
 * @param encoding
 *
 * @return value
 */
_STATIC_INLINE_ bool_t ia32_try_vmread(uint64_t encoding, uint64_t *value) {
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmreadq %2,%0\n"
            "pushfq\n"
            "popq %1"
            : "=m"(*value), "=r"(rflags.raw)
            :"r"(encoding)
            :"memory", "cc");

    if (!(rflags.cf == 0 && rflags.zf == 0))
    {
        return false;
    }

    return true;
}

/**
 * @brief Write to VMCS entry
 * @param encoding
 * @param value
 * @return
 */
_STATIC_INLINE_ bool_t ia32_try_vmwrite(uint64_t encoding, uint64_t value)
{
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmwriteq %1,%2\n"
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            :"r"(value), "r"(encoding)
            : "cc");

    if (!(rflags.cf == 0 && rflags.zf == 0))
    {
        return false;
    }

    return true;
}

/**
 * @brief Read from VMCS entry
 * @param encoding
 *
 * @return value
 */
_STATIC_INLINE_ void ia32_vmread(uint64_t encoding, uint64_t *value) {
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmreadq %2,%0\n"
			"pushfq\n"
			"popq %1"
			: "=m"(*value), "=r"(rflags.raw)
			:"r"(encoding)
			:"memory", "cc");

	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), FATAL_ERROR_ID_115, (uint32_t)encoding);
}

/**
 * @brief Write to VMCS entry
 * @param encoding
 * @param value
 * @return
 */
_STATIC_INLINE_ void ia32_vmwrite(uint64_t encoding, uint64_t value)
{
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmwriteq %1,%2\n"
			"pushfq\n"
			"popq %0"
			: "=r"(rflags.raw)
            :"r"(value), "r"(encoding)
            : "cc");

	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), FATAL_ERROR_ID_116, (uint32_t)encoding);
}

/**
 * @brief Launch Virtual Machine
 */
_STATIC_INLINE_ void ia32_vmlaunch(void) {
	_ASM_VOLATILE_ ("vmlaunch":::"memory" , "cc");
}

/**
 * @brief Resume Virtual Machine
 */
_STATIC_INLINE_ void ia32_vmresume(void) {
	_ASM_VOLATILE_ ("vmresume":::"memory" , "cc");
}

/**
 * @brief Clear VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ void ia32_vmclear(vmcs_ptr_t *vmcs_p) {
	_ASM_VOLATILE_ ("vmclear %0"::"m"(vmcs_p):"memory" , "cc");
}

/**
 * @brief Load pointer to VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ void ia32_vmptrld(vmcs_ptr_t *vmcs_p) {
    ia32_rflags_t rflags;
	_ASM_VOLATILE_ ("vmptrld %1\n"
                    "pushfq\n"
                    "popq %0\n"
                    : "=r"(rflags.raw)
	                :"m"(vmcs_p):"memory" , "cc");

	// Runtime assert - VMPTRLD should always succeed
	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), FATAL_ERROR_ID_172, 2);
}

/**
 * @brief Store pointer to VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ uint64_t ia32_vmptrst(void) {
    uint64_t ptr;
    _ASM_VOLATILE_ ("vmptrst %0": "=m"(ptr) ::"memory" , "cc");

    return ptr;
}

/**
 * @brief Invalidate EPT translations
 * @param ept_descriptor
 * @param instruction
 * @return
 */
_STATIC_INLINE_ void ia32_invept(const ept_descriptor_t * ept_descriptor, uint64_t instruction)
{
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ (
            "invept %1,%2\n"
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            : "m"(*ept_descriptor), "r"(instruction)
            :"memory", "cc");

    tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), FATAL_ERROR_ID_173, 3);
}

/**
 * @brief Invalidate translations based on VPID
 *        INVVPID can only fail if the provided GPA is not canonical.
 *        Other failure cases should not happen.
 *
 * @param invvpid_descriptor
 * @param instruction
 *
 * @return Success status of INVVPID instruction
 */
_STATIC_INLINE_ bool_t ia32_invvpid(const invvpid_descriptor_t * invvpid_descriptor, invvpid_type_t instruction)
{
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ (
            "invvpid %1,%2\n"
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            : "m"(*invvpid_descriptor), "r"((uint64_t)instruction)
            :"memory", "cc");

    bool_t is_success = (rflags.cf == 0 && rflags.zf == 0);
    bool_t vmfail_valid = (rflags.cf == 0 && rflags.zf == 1);

    tdx_sanity_check((is_success || vmfail_valid), FATAL_ERROR_ID_174, 3);

    return is_success;
}

/**
 * SEAM ACCESSORS
 */

_STATIC_INLINE_ uint64_t ia32_seamops_capabilities(void)
{
    uint64_t leaf = 0; // for CAPABILITES
    uint64_t capabilities = 0;
    _ASM_VOLATILE_ (
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
            :"=a"(capabilities) : "a"(leaf)
            :"memory", "cc");
    return capabilities;
}

#define SEAMOPS_SUCCESS                     0
#define SEAMOPS_INPUT_ERROR                 1
#define SEAMOPS_ENTROPY_ERROR               2
#define SEAMOPS_DATABASE_ERROR              3
#define SEAMOPS_INVALID_CPUSVN              4
#define SEAMOPS_INVALID_REPORTMACSTRUCT     5

#define SEAMOPS_CAPABILITIES_LEAF           0
#define SEAMOPS_SEAMREPORT_LEAF             1
#define SEAMOPS_SEAMDB_CLEAR_LEAF           2
#define SEAMOPS_SEAMDB_INSERT_LEAF          3
#define SEAMOPS_SEAMDB_GETREF_LEAF          4
#define SEAMOPS_SEAMDB_REPORT_LEAF          5
#define SEAMOPS_SEAMVERIFYREPORT_LEAF       6

#define SEAMOPS_GET_KEY_LEAF               11

#define TD_PRESERVING_CAPABILITIES     BITS(SEAMOPS_SEAMDB_REPORT_LEAF, SEAMOPS_SEAMDB_GETREF_LEAF)

_STATIC_INLINE_ uint64_t ia32_seamops_seamdb_getref(uint64_t* last_entry, uint256_t* last_entry_nonce,
                                                    uint64_t* seamdb_size)
{
    uint64_t leaf = SEAMOPS_SEAMDB_GETREF_LEAF;
    uint64_t result;
    _ASM_VOLATILE_ (
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
            "movq %%r10, %1;"
            "movq %%r11, %2;"
            "movq %%r12, %3;"
            "movq %%r13, %4;"
            "movq %%r14, %5;"
            "movq %%r15, %6;"

            :"=a"(result), "=r"(*last_entry),   "=r"(last_entry_nonce->qwords[0]),
             "=r"(last_entry_nonce->qwords[1]), "=r"(last_entry_nonce->qwords[2]),
             "=r"(last_entry_nonce->qwords[3]), "=r"(*seamdb_size)
            :"a"(leaf)
            :"memory", "cc", "r10", "r11", "r12", "r13", "r14", "r15");
    return result;
}

_STATIC_INLINE_ uint64_t ia32_seamops_seamdb_report(void* report_struct_la,
                                                    void* report_data_la,
                                                    void* tee_info_hash_la,
                                                    uint32_t report_type,
                                                    uint64_t entry_idx,
                                                    uint256_t* entry_nonce)
{
    uint64_t leaf = SEAMOPS_SEAMDB_REPORT_LEAF;
    uint64_t result;
    _ASM_VOLATILE_ (
            "movq %4,  %%r8\n"
            "movq %5,  %%r9\n"
            "movq %6,  %%r10\n"

            "movq (%7),      %%r11\n"
            "movq 0x8(%7),   %%r12\n"
            "movq 0x10(%7),  %%r13\n"
            "movq 0x18(%7),  %%r14\n"
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
            :"=a"(result)
            :"a"(leaf), "c"(report_struct_la), "d"(report_type),
             "r"(report_data_la), "r"(tee_info_hash_la), "r"(entry_idx),
             "r"(entry_nonce)
            :"memory", "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14");
    return result;
}

_STATIC_INLINE_ uint64_t ia32_seamops_seamverify_report(const report_mac_struct_t *report_mac)
{
    uint64_t leaf = SEAMOPS_SEAMVERIFYREPORT_LEAF;
    uint64_t result;
        _ASM_VOLATILE_ (
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
            :"=a"(result)
            :"a"(leaf), "b"(report_mac)
            :"memory", "cc");
    return result;
}

_STATIC_INLINE_ uint64_t ia32_seamops_seam_get_key(seam_key_request_t* seam_key_request, uint256_t* key)
{
    uint64_t leaf = SEAMOPS_GET_KEY_LEAF;
    uint64_t result;


    _ASM_VOLATILE_(
        ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
        :"=a"(result)
        : "a"(leaf), "c"(seam_key_request), "d"(key)
        : "memory", "cc");


    return result;
}

#endif /* SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_ */
