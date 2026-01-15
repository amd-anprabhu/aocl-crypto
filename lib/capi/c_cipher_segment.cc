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

#include "alcp/alcp.hh"
#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/cipher_segment.h"

#include "alcp/capi/cipher/ctx.hh"
#include "alcp/capi/defs.hh"

using namespace alcp::cipher;

EXTERN_C_BEGIN

static CipherKeyLen
getKeyLen(const Uint64 keyLen)
{
    // xts supports only 128 and 256 keysize
    CipherKeyLen key_size = CipherKeyLen::eKey128Bit;
    if (keyLen == 256) {
        key_size = CipherKeyLen::eKey256Bit;
    }
    return key_size;
}

static CipherMode
getCipherMode(const alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_XTS:
            return CipherMode::eAesXTS;
        default:
            return CipherMode::eCipherModeNone;
    }
}

alc_error_t
alcp_cipher_segment_request(const alc_cipher_mode_t mode,
                            const Uint64            keyLen,
                            alc_cipher_handle_p     pCipherHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "Mode %d, KeyLen %6ld", mode, keyLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    new (ctx) Context;

    ALCP_ZERO_LEN_ERR_RET(keyLen);

    // Store mode and keyLen for later use
    ctx->m_cipherMode = getCipherMode(mode);
    ctx->m_keyLen     = getKeyLen(keyLen);

    // Direct cipher creation (no factory)
    auto cipher = createCipherSeg(ctx->m_cipherMode, ctx->m_keyLen);

    if (cipher == nullptr) {
        printf("\n cipher algo create failed");
        return ALC_ERROR_GENERIC;
    }
    ctx->m_cipher     = cipher;  // iCipherSegment inherits from iCipher
    ctx->m_cipherType = CipherType::eCipherSegment;

    return err;
}

alc_error_t
alcp_cipher_segment_init(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pKey,
                         Uint64                    keyLen,
                         const Uint8*              pIv,
                         Uint64                    ivLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeyLen %6ld,IVLen %6ld", keyLen, ivLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);
    ALCP_CHECK_CIPHER_TYPE(ctx, CipherType::eCipherSegment);

    // init can be called to setKey or setIv or both
    if ((pKey != NULL && keyLen != 0) || (pIv != NULL && ivLen != 0)) {
        err = static_cast<iCipherSegment*>(ctx->m_cipher)->init(pKey, keyLen, pIv, ivLen);
    } else {
        err = ALC_ERROR_INVALID_ARG;
    }
    return err;
}

alc_error_t
alcp_cipher_segment_encrypt_xts(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pPlainText,
                                Uint8*                    pCipherText,
                                Uint64                    currPlainTextLen,
                                Uint64                    startBlockNum)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG,
                   "CurrentPTLen %6ld,BlkNo %6ld",
                   currPlainTextLen,
                   startBlockNum);
#endif
    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(pPlainText);
    ALCP_BAD_PTR_ERR_RET(pCipherText);

    ALCP_ZERO_LEN_ERR_RET(currPlainTextLen);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);

    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);
    ALCP_CHECK_CIPHER_TYPE(ctx, CipherType::eCipherSegment);

    return static_cast<iCipherSegment*>(ctx->m_cipher)->encryptSegment(
        pPlainText, pCipherText, currPlainTextLen, startBlockNum);
}

alc_error_t
alcp_cipher_segment_decrypt_xts(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pCipherText,
                                Uint8*                    pPlainText,
                                Uint64                    currCipherTextLen,
                                Uint64                    startBlockNum)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG,
                   "CurrentPTLen %6ld,BlkNo %6ld",
                   currCipherTextLen,
                   startBlockNum);
#endif
    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(pPlainText);
    ALCP_BAD_PTR_ERR_RET(pCipherText);

    ALCP_ZERO_LEN_ERR_RET(currCipherTextLen);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);

    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);
    ALCP_CHECK_CIPHER_TYPE(ctx, CipherType::eCipherSegment);

    return static_cast<iCipherSegment*>(ctx->m_cipher)->decryptSegment(
        pCipherText, pPlainText, currCipherTextLen, startBlockNum);
}

void
alcp_cipher_segment_finish(const alc_cipher_handle_p pCipherHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    if (pCipherHandle == nullptr || pCipherHandle->ch_context == nullptr)
        return;

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);

    // Validate type before deleting
    if (ctx->m_cipherType != CipherType::eCipherSegment) {
        return; // Wrong type, don't delete
    }

    // Delete cipher object directly (no factory to delete)
    auto cipher = static_cast<iCipherSegment*>(ctx->m_cipher);
    if (cipher != nullptr) {
        delete cipher;
        ctx->m_cipher     = nullptr;
        ctx->m_cipherType = CipherType::eNone;
    }
}
EXTERN_C_END
