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
 * @file sha384.c
 * @brief Crypto implementation of SHA384
 */
#include "crypto/sha384.h"
#include "helpers/helpers.h"
#include "ippcp.h"

static IppsHashMethod* sha384_init_and_get_global_method(void)
{
    int32_t method_buffer_size;
    IppStatus ret_val = ippStsErr;

    hash_method_t* sha384_method = &get_global_data()->sha384_method;
    IppsHashMethod* hash_method_ptr = (IppsHashMethod*)sha384_method->hash_method_buffer;

    if (sha384_method->is_initialized)
    {
        return hash_method_ptr;
    }

    ret_val = ippsHashMethodGetSize(&method_buffer_size);

    if (ret_val != ippStsNoErr || method_buffer_size > (int32_t)HASH_METHOD_BUFFER_SIZE)
    {
        TDX_ERROR("Required method buffer size is %d\n", method_buffer_size);
        return NULL;
    }

    ret_val = ippsHashMethodSet_SHA384(hash_method_ptr);
    if (ret_val != ippStsNoErr)
    {
        TDX_ERROR("SHA384 Method setting failed\n");
        return NULL;
    }

    sha384_method->is_initialized = true;

    return hash_method_ptr;
}

static IppStatus sha384_init_global_method_and_set_in_state(IppsHashState_rmf* ipp_hash_state)
{
    int32_t method_buffer_size;
    IppStatus ret_val = ippStsErr;

    hash_method_t* sha384_method = &get_global_data()->sha384_method;
    IppsHashMethod* hash_method_ptr = (IppsHashMethod*)sha384_method->hash_method_buffer;

    ret_val = ippsHashMethodGetSize(&method_buffer_size);

    if (ret_val != ippStsNoErr || method_buffer_size > (int32_t)HASH_METHOD_BUFFER_SIZE)
    {
        TDX_ERROR("Required method buffer size is %d\n", method_buffer_size);
        return ret_val;
    }

    ret_val = ippsHashStateMethodSet_SHA384(ipp_hash_state, hash_method_ptr);

    sha384_method->is_initialized = true;

    return ret_val;
}

crypto_api_error sha384_init(sha384_ctx_t* ctx)
{
    prepare_state_for_avx_usage(true, false);
    
    sha384_ctx_t local_ctx;
    int32_t ctx_size = 0;
    IppStatus ret_val = ippStsErr;

    IppsHashMethod* hash_method = sha384_init_and_get_global_method();
    if (hash_method == NULL)
    {
        goto EXIT_NO_COPY;
    }

    // Zero initial local context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    ret_val = ippsHashGetSize_rmf(&ctx_size);

    if ((ret_val != ippStsNoErr) || (ctx_size <= 0) || ((uint32_t)ctx_size > SIZE_OF_SHA384_CTX_BUFFER))
    {
        goto EXIT_NO_COPY;
    }

    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    // Init the sha context
    ret_val = ippsHashInit_rmf(ipp_hash_state, hash_method);

    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    ctx->last_init_seamdb_index = get_global_data()->seamdb_index;

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

EXIT_NO_COPY:

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_update_128B(sha384_ctx_t* ctx, const sha384_128B_block_t* blocks, uint32_t num_of_blocks)
{
    prepare_state_for_avx_usage(true, false);
    
    sha384_ctx_t local_ctx;
    IppStatus ret_val = ippStsErr;

    // Copy context to stack
    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    ret_val = ippsHashUnpack_rmf(ctx->buffer, ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    uint64_t seamdb_index = get_global_data()->seamdb_index;

    if (seamdb_index != ctx->last_init_seamdb_index)
    {
        ret_val = sha384_init_global_method_and_set_in_state(ipp_hash_state);

        if (ret_val != ippStsNoErr)
        {
            TDX_ERROR("SHA384 Method update failed\n");
            goto EXIT;
        }

        ctx->last_init_seamdb_index = seamdb_index;
    }

    ret_val = ippsHashUpdate_rmf((const Ipp8u*)blocks,
        (int)SIZE_OF_SHA384_BLOCK_IN_BYTES * (int)num_of_blocks,
        ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_finalize(sha384_ctx_t* ctx, uint64_t* hash)
{
    prepare_state_for_avx_usage(true, false);

    sha384_ctx_t local_ctx;
    IppStatus ret_val = ippStsErr;

    // Copy context to stack
    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    ret_val = ippsHashUnpack_rmf(ctx->buffer, ipp_hash_state);

    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    uint64_t seamdb_index = get_global_data()->seamdb_index;

    if (seamdb_index != ctx->last_init_seamdb_index)
    {
        ret_val = sha384_init_global_method_and_set_in_state(ipp_hash_state);

        if (ret_val != ippStsNoErr)
        {
            TDX_ERROR("SHA384 Method update failed\n");
            goto EXIT;
        }

        ctx->last_init_seamdb_index = seamdb_index;
    }

    ret_val = ippsHashFinal_rmf((Ipp8u*)hash, ipp_hash_state);

    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_generate_hash(const uint8_t* block, uint32_t block_size, uint64_t* hash, bool_t is_guest)
{
    prepare_state_for_avx_usage(true, is_guest);
    
    IppsHashMethod* hash_method = sha384_init_and_get_global_method();

    if (hash_method == NULL)
    {
        return ippStsErr;
    }

    return ippsHashMessage_rmf(block, (int)block_size, (Ipp8u*)hash, hash_method);
}

