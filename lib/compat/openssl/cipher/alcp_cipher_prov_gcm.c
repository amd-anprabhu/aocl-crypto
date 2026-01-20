
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

#include "alcp_cipher_prov_aead.h"
#include "alcp_cipher_prov_aead_gcm.h"

// Helper to get combined allocation size
static inline size_t
gcm_ctx_alloc_size(void)
{
    return sizeof(ALCP_PROV_AES_CTX) + alcp_cipher_aead_context_size();
}

// Helper to get ch_context pointer from combined allocation
static inline void*
gcm_ctx_get_ch_context(ALCP_PROV_AES_CTX* ctx)
{
    return (void*)((Uint8*)ctx + sizeof(ALCP_PROV_AES_CTX));
}

static void*
ALCP_prov_alg_gcm_newctx(void* provctx, size_t keybits)
{
    ALCP_PROV_AES_CTX* ctx;
    ENTER();

    // Single combined allocation for ctx + ch_context
    ctx = OPENSSL_zalloc(gcm_ctx_alloc_size());
    if (ctx == NULL)
        return NULL;

    // ch_context points to memory immediately after the struct
    ctx->base.handle.ch_context = gcm_ctx_get_ch_context(ctx);

    // Request handle for the cipher
    alc_error_t err = alcp_cipher_aead_request_with_extState(
        ALC_AES_MODE_GCM,
        keybits,
        NULL,
        &(ctx->base.handle));

    if (err == ALC_ERROR_NONE) {
        ALCP_prov_gcm_initctx(provctx, &(ctx->base), keybits);
    } else {
        OPENSSL_clear_free(ctx, gcm_ctx_alloc_size());
        return NULL;
    }

    return ctx;
}

static void*
ALCP_prov_alg_gcm_dupctx(void* provctx)
{
    ENTER();
    ALCP_PROV_AES_CTX*      ctx  = provctx;
    ALCP_PROV_AES_CTX*      dctx = NULL;
    alc_prov_cipher_data_t* src_cipherctx;
    alc_prov_cipher_data_t* dst_cipherctx;

    if (ctx == NULL)
        return NULL;

    // Single combined allocation for new context
    dctx = OPENSSL_zalloc(gcm_ctx_alloc_size());
    if (dctx == NULL)
        return NULL;

    // Copy the struct data (not ch_context data)
    memcpy(dctx, ctx, sizeof(*ctx));

    // Fix pKey pointer to point to new context's ks
    if (dctx->base.prov_cipher_data.pKey != NULL)
        dctx->base.prov_cipher_data.pKey = (const Uint8*)&dctx->ks;

    // ch_context points to embedded memory after struct
    dctx->base.handle.ch_context = gcm_ctx_get_ch_context(dctx);

    src_cipherctx = &(ctx->base.prov_cipher_data);
    dst_cipherctx = &(dctx->base.prov_cipher_data);

    // Re-request cipher handle for the new context
    alc_error_t err = alcp_cipher_aead_request_with_extState(
        ALC_AES_MODE_GCM,
        dst_cipherctx->keyLen_in_bytes * 8,
        NULL,
        &(dctx->base.handle));

    if (err != ALC_ERROR_NONE) {
        OPENSSL_clear_free(dctx, gcm_ctx_alloc_size());
        return NULL;
    }

    // Re-initialize with key and/or IV if they were set in the source context
    if (src_cipherctx->isKeySet) {
        const Uint8* key_ptr = (const Uint8*)&dctx->ks;
        const Uint8* iv_ptr  = NULL;
        size_t       iv_len  = 0;

        // Include IV if it was set (state is COPIED or BUFFERED)
        if (src_cipherctx->ivState == IV_STATE_COPIED
            || src_cipherctx->ivState == IV_STATE_BUFFERED) {
            iv_ptr = dst_cipherctx->iv_buff;
            iv_len = dst_cipherctx->ivLen;
        }

        err = alcp_cipher_aead_init(&(dctx->base.handle),
                                    key_ptr,
                                    dst_cipherctx->keyLen_in_bytes * 8,
                                    iv_ptr,
                                    iv_len);
        if (alcp_is_error(err)) {
            alcp_cipher_aead_finish(&(dctx->base.handle));
            OPENSSL_clear_free(dctx, gcm_ctx_alloc_size());
            return NULL;
        }

        // Update IV state if it was buffered (now it's initialized)
        if (src_cipherctx->ivState == IV_STATE_BUFFERED && iv_ptr != NULL) {
            dst_cipherctx->ivState = IV_STATE_COPIED;
        }
    }

    return dctx;
}

static OSSL_FUNC_cipher_freectx_fn ALCP_prov_alg_gcm_freectx;

static void
ALCP_prov_alg_gcm_freectx(void* vctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx = (ALCP_PROV_AES_CTX*)vctx;

    if (ctx == NULL)
        return;

    // Finish the cipher (ch_context is part of combined allocation, don't free
    // separately)
    if (ctx->base.handle.ch_context != NULL) {
        alcp_cipher_aead_finish(&(ctx->base.handle));
        ctx->base.handle.ch_context = NULL;
    }

    // Single free for combined allocation
    OPENSSL_clear_free(ctx, gcm_ctx_alloc_size());
}

#if 1 // to be removed. kept for understanding.
static OSSL_FUNC_cipher_get_params_fn aes_128_gcm_get_params;
static int
aes_128_gcm_get_params(OSSL_PARAM params[])
{
    ENTER();
    return ALCP_prov_cipher_generic_get_params(
        params, 0x6, (0x0001 | 0x0002), 128, 8, 96);
}
static OSSL_FUNC_cipher_newctx_fn aes128gcm_newctx;
static void*
aes128gcm_newctx(void* provctx)
{
    // printf("\n aes128gcm_newctx");
    return ALCP_prov_alg_gcm_newctx(provctx, 128);
}
static void*
aes128gcm_dupctx(void* src)
{
    return ALCP_prov_alg_gcm_dupctx(src);
}
const OSSL_DISPATCH ALCP_prov_aes128gcm_functions[] = {
    { 1, (void (*)(void))aes128gcm_newctx },
    { 7, (void (*)(void))ALCP_prov_alg_gcm_freectx },
    { 8, (void (*)(void))aes128gcm_dupctx },
    { 2, (void (*)(void))ALCP_prov_gcm_einit },
    { 3, (void (*)(void))ALCP_prov_gcm_dinit },
    { 4, (void (*)(void))ALCP_prov_gcm_stream_update },
    { 5, (void (*)(void))ALCP_prov_gcm_stream_final },
    { 6, (void (*)(void))ALCP_prov_gcm_cipher },
    { 9, (void (*)(void))aes_128_gcm_get_params },
    { 10, (void (*)(void))ALCP_prov_gcm_get_ctx_params },
    { 11, (void (*)(void))ALCP_prov_gcm_set_ctx_params },
    { 0, ((void*)0) }
};

#else

/* ossl_aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);

#endif

/* ossl_aes192gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96);

/* ossl_aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);
