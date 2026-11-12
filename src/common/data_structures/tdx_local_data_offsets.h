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
 * @file tdx_local_data_offsets.h
 * @brief Offset of fields in TDX local data used in assembly code
 */
#ifndef __TDX_LOCAL_DATA_OFFSETS_H_INCLUDED__
#define __TDX_LOCAL_DATA_OFFSETS_H_INCLUDED__


#define TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET      0
#define TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET     128
#define TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET  256
#define TDX_LOCAL_DATA_STACK_CANARY_OFFSET      STACK_PROTECTOR_OFFSET

#if (TDX_LOCAL_DATA_STACK_CANARY_OFFSET != (TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET + 8))
#error "Wrong defines for local data stack canary offsets"
#endif // (TDX_LOCAL_DATA_STACK_CANARY_OFFSET != (TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET + 8))

#endif // __TDX_LOCAL_DATA_OFFSETS_H_INCLUDED__
