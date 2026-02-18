/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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

#include "digest/alcp_digest_prov.h"
#include "provider/alcp_names.h"

void
alcp_prov_digest_freectx(void* vctx)
{
    alc_prov_digest_ctx_p pdctx = vctx;
    ENTER();
    alcp_digest_finish(&pdctx->handle);
    OPENSSL_clear_free(vctx, sizeof(*pdctx) + alcp_digest_context_size());
    EXIT();
}

void*
alcp_prov_digest_newctx(void* vprovctx, alc_digest_mode_t mode)
{
    alc_prov_digest_ctx_p dig_ctx;
    Uint64                ctx_size = alcp_digest_context_size();

    ENTER();

    dig_ctx = OPENSSL_zalloc(sizeof(*dig_ctx) + ctx_size);
    if (dig_ctx != NULL) {
        dig_ctx->handle.context = (Uint8*)dig_ctx + sizeof(*dig_ctx);
        alc_error_t err         = alcp_digest_request(mode, &(dig_ctx->handle));
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Request failed %llu\n", (unsigned long long)err);
            OPENSSL_clear_free(dig_ctx, sizeof(*dig_ctx) + ctx_size);
            return 0;
        }
        if (mode == ALC_SHAKE_128 || mode == ALC_SHAKE_256) {
#if OPENSSL_API_LEVEL >= 30400
            dig_ctx->shake_digest_size = SIZE_MAX;
#else
            dig_ctx->shake_digest_size = (mode == ALC_SHAKE_128)
                                             ? (ALC_DIGEST_LEN_128 / 8)
                                             : (ALC_DIGEST_LEN_256 / 8);
#endif
        }
    }
    EXIT();

    return dig_ctx;
}

void*
alcp_prov_digest_dupctx(void* vctx)
{
    ENTER();
    alc_prov_digest_ctx_p src_ctx    = vctx;
    Uint64                ctx_size   = alcp_digest_context_size();
    Uint64                total_size = sizeof(*src_ctx) + ctx_size;

    alc_prov_digest_ctx_p dest_ctx = OPENSSL_memdup(src_ctx, total_size);
    if (dest_ctx == NULL) {
        return NULL;
    }

    dest_ctx->handle.context = (Uint8*)dest_ctx + sizeof(*dest_ctx);

    alc_error_t err =
        alcp_digest_context_copy(&src_ctx->handle, &dest_ctx->handle);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: copy failed in dupctx\n");
        OPENSSL_clear_free(dest_ctx, total_size);
        return NULL;
    }

    EXIT();
    return dest_ctx;
}

/*-
 * Generic digest functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM digest_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
alcp_prov_digest_gettable_params(void* provctx)
{
    ENTER();
    EXIT();
    return digest_known_gettable_params;
}

int
alcp_prov_digest_get_params(OSSL_PARAM    params[],
                            size_t        blockSize,
                            size_t        digestSize,
                            unsigned long flags)
{
    ENTER();
    OSSL_PARAM* param = NULL;
    OSSL_PARAM_LOCATE_SET_SIZE(
        params, OSSL_DIGEST_PARAM_BLOCK_SIZE, param, blockSize);
#if OPENSSL_API_LEVEL >= 30400
    if (flags & ALCP_FLAG_XOF) {
        OSSL_PARAM_LOCATE_SET_SIZE(params, OSSL_DIGEST_PARAM_SIZE, param, 0);
    } else {
        OSSL_PARAM_LOCATE_SET_SIZE(
            params, OSSL_DIGEST_PARAM_SIZE, param, digestSize);
    }
#else
    OSSL_PARAM_LOCATE_SET_SIZE(
        params, OSSL_DIGEST_PARAM_SIZE, param, digestSize);
#endif
    OSSL_PARAM_LOCATE_SET_INT(
        params, OSSL_DIGEST_PARAM_XOF, param, ((flags & ALCP_FLAG_XOF) != 0));
    OSSL_PARAM_LOCATE_SET_INT(params,
                              OSSL_DIGEST_PARAM_ALGID_ABSENT,
                              param,
                              ((flags & ALCP_FLAG_ALGID_ABSENT) != 0));
    EXIT();
    return 1;
}

int
alcp_prov_digest_update(void* vctx, const unsigned char* in, size_t inl)
{
    ENTER();
    alc_error_t           err;
    alc_prov_digest_ctx_p cctx = vctx;

    err = alcp_digest_update(&(cctx->handle), in, inl);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Unable to Update Digest\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
alcp_prov_digest_final(void* vctx, unsigned char* out, size_t outsize)
{
    ENTER();
    alc_error_t           err  = ALC_ERROR_NONE;
    alc_prov_digest_ctx_p dctx = vctx;

    err = alcp_digest_finalize(&(dctx->handle), out, outsize);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Failed to finalize and copy digest\n");
        return 0;
    }
    EXIT();
    return 1;
}

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST
static const char DIGEST_DEF_PROP[] = "provider=alcp,fips=no";
#endif

const OSSL_ALGORITHM ALC_prov_digests[] = {
#ifdef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2
    { ALCP_PROV_NAMES_SHA2_224, DIGEST_DEF_PROP, sha224_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_256, DIGEST_DEF_PROP, sha256_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_384, DIGEST_DEF_PROP, sha384_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512, DIGEST_DEF_PROP, sha512_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512_224,
      DIGEST_DEF_PROP,
      sha512_224_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512_256,
      DIGEST_DEF_PROP,
      sha512_256_sha2_functions },
#endif

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3
    { ALCP_PROV_NAMES_SHA3_512, DIGEST_DEF_PROP, sha512_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_384, DIGEST_DEF_PROP, sha384_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_256, DIGEST_DEF_PROP, sha256_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_224, DIGEST_DEF_PROP, sha224_sha3_functions },
#endif

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE
    { ALCP_PROV_NAMES_SHAKE_128, DIGEST_DEF_PROP, shake128_sha3_functions },
    { ALCP_PROV_NAMES_SHAKE_256, DIGEST_DEF_PROP, shake256_sha3_functions },
#endif

    { NULL, NULL, NULL },
};
