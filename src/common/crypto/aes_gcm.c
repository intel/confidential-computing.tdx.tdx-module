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
 * @file aes_gcm.c
 * @brief Crypto implementation for AES GCM library
 */

#include "crypto/aes_gcm.h"
#include "ippcp.h"
#include "debug/tdx_debug.h"
#include "helpers/error_reporting.h"
#include "helpers/helpers.h"

#define KEY256_LEN  32
tdx_static_assert(KEY256_LEN == sizeof(key256_t), key256_t);

static void clean_ctx(aes_gcm_ctx_t *ctx)
{
    basic_memset_to_zero(&ctx->state, GCM_STATE_BUFFER_SIZE);
}

aes_gcm_api_error aes_gcm_init(const key256_t *key, aes_gcm_ctx_t *ctx, const migs_iv_t *iv)
{
    tdx_debug_assert(ctx);
    
    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMGetSize(&ctx->size);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        goto EXIT;
    }

    tdx_debug_assert(ctx->size <= (int)GCM_STATE_BUFFER_SIZE);

    if (ctx->size > (int)GCM_STATE_BUFFER_SIZE)
    {
        status = ippStsSizeErr;
        TDX_ERROR("aes_gcm_ctx size (%d) is bigger than allocated memory size (%d)\n", ctx->size, (int32_t)GCM_STATE_BUFFER_SIZE);
        goto EXIT;
    }

    status = ippsAES_GCMInit((const Ipp8u*)key->bytes, KEY256_LEN, pState, ctx->size);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        goto EXIT;
    }

    status = ippsAES_GCMProcessIV((const Ipp8u*)iv->raw, sizeof(iv->raw), pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        goto EXIT;
    }

    tdx_debug_assert(ippStsNoErr == AES_GCM_NO_ERROR);

EXIT:
    if (ippStsNoErr != status)
    {
        clean_ctx(ctx);
    }
    return (aes_gcm_api_error) status;
}

aes_gcm_api_error aes_gcm_refresh_context(aes_gcm_ctx_t *ctx)
{
    tdx_debug_assert(ctx);

    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMReinit(pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        goto EXIT;
    }

    tdx_debug_assert(ippStsNoErr == AES_GCM_NO_ERROR);

EXIT:
    if (ippStsNoErr != status)
    {
        clean_ctx(ctx);
    }

    return (aes_gcm_api_error) status;
}

aes_gcm_api_error aes_gcm_reset(aes_gcm_ctx_t *ctx, const migs_iv_t *iv)
{
    tdx_debug_assert(ctx);

    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMReset(pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        goto EXIT;
    }

    status = ippsAES_GCMProcessIV((const Ipp8u*)iv->raw, sizeof(iv->raw), pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
    }

EXIT:
    if (ippStsNoErr != status)
    {
        clean_ctx(ctx);
    }
    return (aes_gcm_api_error) status;
}

aes_gcm_api_error aes_gcm_process_aad(aes_gcm_ctx_t *ctx, const uint8_t *p_aad, int32_t size_aad)
{
    tdx_debug_assert(ctx);
    
    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMProcessAAD((const Ipp8u*)p_aad, size_aad, pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
    }

    return (aes_gcm_api_error) status;
}

aes_gcm_api_error aes_gcm_encrypt(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size)
{
    tdx_debug_assert(ctx);

    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMEncrypt((const Ipp8u*)src, (Ipp8u*)dst, size, pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
    }

    return (aes_gcm_api_error) status;
}

aes_gcm_api_error aes_gcm_decrypt(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size)
{
    tdx_debug_assert(ctx);

    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMDecrypt((const Ipp8u*)src, (Ipp8u*)dst, size, pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
    }

    return (aes_gcm_api_error) status;
}

/* Decrypt the input 4KB page into a the TD page.
   Note the need to use MOVDIR64B either as part of the decryption algorithm
   or to initialize the page before decryption.
*/
aes_gcm_api_error aes_gcm_decrypt_direct(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size)
{
    tdx_debug_assert(ctx);

    zero_area_cacheline(dst, (uint64_t)size);

    return aes_gcm_decrypt(ctx, src, dst, size);
}

#define MAC256_LEN 16

aes_gcm_api_error aes_gcm_finalize(aes_gcm_ctx_t *ctx, uint8_t *mac)
{
    tdx_debug_assert(ctx);

    prepare_state_for_avx_usage(false, false);

    IppsAES_GCMState *pState = (IppsAES_GCMState*) &ctx->state;

    IppStatus status = ippsAES_GCMGetTag((Ipp8u*)mac, MAC256_LEN, pState);
    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
    }

    return (aes_gcm_api_error) status;
}

