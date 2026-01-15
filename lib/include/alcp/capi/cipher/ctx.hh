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
#pragma once

#include "alcp/cipher.h"
#include "alcp/cipher.hh"

namespace alcp::cipher {

/**
 * @brief Type discriminator for cipher context
 *
 * Used to track which interface type is stored in the context,
 * enabling runtime type safety checks at API boundaries.
 */
enum class CipherType : Uint8
{
    eNone = 0,       ///< Uninitialized or invalid
    eCipher,         ///< iCipher* (non-AEAD modes: CBC, CTR, OFB, CFB, XTS, ChaCha20)
    eCipherAead,     ///< iCipherAead* (AEAD modes: GCM, CCM, SIV, ChaCha20-Poly1305)
    eCipherSegment   ///< iCipherSegment* (segmented modes: XTS block)
};

/**
 * @brief Cipher context structure
 *
 * Stores the cipher object pointer along with function pointers for direct calls.
 * Function pointers take cipher object as first parameter to avoid vtable dispatch.
 */
typedef struct Context
{
    iCipher*      m_cipher      = nullptr; ///< Cipher pointer
    iMultibuffer* m_multibuffer = nullptr; ///< Cached multibuffer interface (may be null)

    // Function pointers for direct calls (cipher object passed as first arg)
    alc_error_t (*encrypt)(void* cipher, const Uint8* pSrc, Uint8* pDst, Uint64 len, Uint64* outLen);
    alc_error_t (*decrypt)(void* cipher, const Uint8* pSrc, Uint8* pDst, Uint64 len, Uint64* outLen);
    alc_error_t (*init)(void* cipher, const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen);
    alc_error_t (*encryptSegment)(void* cipher, const Uint8* pSrc, Uint8* pDst, Uint64 len, Uint64 startBlockNum);
    alc_error_t (*decryptSegment)(void* cipher, const Uint8* pSrc, Uint8* pDst, Uint64 len, Uint64 startBlockNum);
    alc_error_t (*setAad)(void* cipher, const Uint8* pAad, Uint64 aadLen);
    alc_error_t (*getTag)(void* cipher, Uint8* pTag, Uint64 tagLen);
    alc_error_t (*setTagLength)(void* cipher, Uint64 tagLen);
    alc_error_t (*setPlainTextLength)(void* cipher, Uint64 plainTextLength);

    CipherType   m_cipherType = CipherType::eNone;
    CipherMode   m_cipherMode = CipherMode::eCipherModeNone;
    CipherKeyLen m_keyLen     = CipherKeyLen::eKey128Bit;
    Uint8        destructed   = 0;

    Context()
        : m_cipher{ nullptr }
        , m_multibuffer{ nullptr }
        , encrypt{ nullptr }
        , decrypt{ nullptr }
        , init{ nullptr }
        , encryptSegment{ nullptr }
        , decryptSegment{ nullptr }
        , setAad{ nullptr }
        , getTag{ nullptr }
        , setTagLength{ nullptr }
        , setPlainTextLength{ nullptr }
        , destructed{ 0 }
    {}
    ~Context() { destructed = 1; }
} alcp_cipher_ctx_t;

/**
 * @brief Type validation macro for cipher context
 *
 * Returns ALC_ERROR_INVALID_ARG if the context type doesn't match expected type.
 */
#define ALCP_CHECK_CIPHER_TYPE(ctx, expected_type)                             \
    do {                                                                       \
        if ((ctx)->m_cipherType != (expected_type)) {                          \
            return ALC_ERROR_INVALID_ARG;                                      \
        }                                                                      \
    } while (0)

} // namespace alcp::cipher
