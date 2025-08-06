/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher_aead.h"

#include "alcp/capi/cipher/ctx.hh"
#include "alcp/capi/defs.hh"

using namespace alcp::cipher;

EXTERN_C_BEGIN

Uint64
alcp_cipher_aead_context_size()
{
    Uint64 size = sizeof(Context);
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CtxSize %6ld", size);
#endif
    return size;
}

static CipherKeyLen
getKeyLen(const Uint64 keyLen)
{
    CipherKeyLen key_size = CipherKeyLen::eKey128Bit;
    if (keyLen == 192) {
        key_size = CipherKeyLen::eKey192Bit;
    } else if (keyLen == 256) {
        key_size = CipherKeyLen::eKey256Bit;
    }
    return key_size;
}

static CipherMode
getCipherAeadMode(const alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_GCM:
            return CipherMode::eAesGCM;
        case ALC_AES_MODE_CCM:
            return CipherMode::eAesCCM;
        case ALC_AES_MODE_SIV:
            return CipherMode::eAesSIV;
        case ALC_CHACHA20_POLY1305:
            return CipherMode::eCHACHA20_POLY1305;
        default:
            return CipherMode::eCipherModeNone;
    }
}

alc_error_t
alcp_cipher_aead_request(const alc_cipher_mode_t mode,
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

    auto alcpCipher = new CipherFactory<iCipherAead>;

    ctx->m_cipher_factory = static_cast<void*>(alcpCipher);

    auto aead = alcpCipher->create(getCipherAeadMode(mode), getKeyLen(keyLen));
    if (aead == nullptr) {
        printf("\n cipher algo create failed");
        return ALC_ERROR_GENERIC;
    }
    ctx->m_cipher = static_cast<void*>(aead);

    return err;
}

alc_error_t
alcp_cipher_aead_request_with_extState(const alc_cipher_mode_t mode,
                                       const Uint64            keyLen,
                                       alc_cipher_state_t*     pCipherState,
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

    auto alcpCipher       = new CipherFactory<iCipherAead>;
    ctx->m_cipher_factory = static_cast<void*>(alcpCipher);
    // printf("\n aead request cipherstate %p ", (void*)pCipherState);

    auto aead = alcpCipher->create(
        getCipherAeadMode(mode), getKeyLen(keyLen), pCipherState);
    if (aead == nullptr) {
        printf("\n cipher algo create failed");
        return ALC_ERROR_GENERIC;
    }
    ctx->m_cipher = static_cast<void*>(aead);

    return err;
}

alc_error_t
alcp_cipher_aead_encrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "EncLen %6ld", len);
#endif

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(pInput);
    ALCP_BAD_PTR_ERR_RET(pOutput);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    return i->encrypt(pInput, pOutput, len);
}

alc_error_t
alcp_cipher_aead_decrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "DecLen %6ld", len);
#endif

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(pInput);
    ALCP_BAD_PTR_ERR_RET(pOutput);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);
    // ALCP_BAD_PTR_ERR_RET(i->decrypt, err);
    return i->decrypt(pInput, pOutput, len);
}

alc_error_t
alcp_cipher_aead_init(const alc_cipher_handle_p pCipherHandle,
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
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    /* FIXME: instead of this, should we call ALCP_BAD_PTR_ERR_RET checks ? */
    if ((pKey != NULL && keyLen != 0) || (pIv != NULL && ivLen != 0)) {
        err = i->init(pKey, keyLen, pIv, ivLen);
    }

    return err;
}

alc_error_t
alcp_cipher_aead_set_aad(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint64                    aadLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "ADLen %6ld", aadLen);
#endif
    ALCP_ZERO_LEN_ERR_RET(aadLen);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(pInput);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    return i->setAad(pInput, aadLen);
}

alc_error_t
alcp_cipher_aead_get_tag(const alc_cipher_handle_p pCipherHandle,
                         Uint8*                    pOutput,
                         Uint64                    tagLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TagLen %6ld", tagLen);
#endif

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);

    ALCP_BAD_PTR_ERR_RET(pOutput);

    ALCP_ZERO_LEN_ERR_RET(tagLen);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    return i->getTag(pOutput, tagLen);
}

alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    tagLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TagLen %ld", tagLen);
#endif
    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);

    ALCP_ZERO_LEN_ERR_RET(tagLen);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);
    // ALCP_BAD_PTR_ERR_RET(i->setTagLength, err);
    return i->setTagLength(tagLen);
}

alc_error_t
alcp_cipher_aead_set_ccm_plaintext_length(
    const alc_cipher_handle_p pCipherHandle, Uint64 plaintextLength)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "PTLen %6ld", plaintextLength);
#endif

    ALCP_BAD_PTR_ERR_RET(pCipherHandle);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context);

    auto ctx = static_cast<alcp::cipher::Context*>(pCipherHandle->ch_context);

    /* check if ctx->m_cipher is not nullptr */
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);
    return i->setPlainTextLength(plaintextLength);
}

void
alcp_cipher_aead_finish(const alc_cipher_handle_p pCipherHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    if (nullptr == pCipherHandle)
        return;
    if (pCipherHandle->ch_context == nullptr) {
        return;
    }

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return;
    }
    auto alcpCipher =
        static_cast<CipherFactory<iCipherAead>*>(ctx->m_cipher_factory);

    if (alcpCipher != nullptr) {
        delete alcpCipher;
    }

    ctx->~Context();
}

EXTERN_C_END
