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

#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_zen4.hh"
#include "chacha20_inplace.cc.inc"

namespace alcp::cipher {

alc_error_t
ChaCha20::init(const Uint8* pKey,
               const Uint64 keyLen,
               const Uint8* pIv,
               const Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pKey != NULL && keyLen != 0) {
        err = setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    if (pIv != NULL && ivLen != 0) {
        err = setIv(pIv, ivLen);
    }

    return err;
}

alc_error_t
ChaCha20::validateKey(const Uint8* key, Uint64 keylen)
{
    return ValidateKey(key, keylen);
}

alc_error_t
ChaCha20::validateIv(const Uint8 iv[], Uint64 iVlen)
{
    return ValidateIv(iv, iVlen);
}

alc_error_t
ChaCha20::setKey(const Uint8 key[], Uint64 keylen)
{
    alc_error_t err = validateKey(key, keylen);
    if (alcp_is_error(err)) {
        return err;
    }
    
    // Store key via KeyManager
    err = m_keyManager.setKey(key, keylen);
    if (err == ALC_ERROR_NONE) {
        m_stateManager.onKeySet();
    }
    return err;
}

alc_error_t
ChaCha20::setIv(const Uint8 iv[], Uint64 ivlen)
{
    alc_error_t err = validateIv(iv, ivlen);
    if (alcp_is_error(err)) {
        return err;
    }
    
    // Store IV via IvManager
    err = m_ivManager.setIv(iv, ivlen);
    if (err == ALC_ERROR_NONE) {
        m_stateManager.onIvSet();
    }
    return err;
}

// Template specializations for ChaCha256T encrypt/decrypt

template<>
alc_error_t
ChaCha256T<CpuArchLevel::eZen4>::encrypt(const Uint8* pInput,
                                                  Uint8*       pOutput,
                                                  Uint64       len,
                                                  Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    Uint64 blocks   = len / cMBlockSize;
    int    remBytes = len - (blocks * cMBlockSize);
    err             = zen4::ProcessInput(getKey(),
                             cMKeylen,
                             getIv(),
                             cMIvlen,
                             pInput,
                             pOutput,
                             blocks,
                             remBytes);

    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
}

template<>
alc_error_t
ChaCha256T<CpuArchLevel::eZen4>::decrypt(const Uint8* pInput,
                                                  Uint8*       pOutput,
                                                  Uint64       len,
                                                  Uint64*      outlen)
{
    // ChaCha20 encryption and decryption are identical operations
    return encrypt(pInput, pOutput, len, outlen);
}

template<>
alc_error_t
ChaCha256T<CpuArchLevel::eReference>::encrypt(const Uint8* pInput,
                                                    Uint8*       pOutput,
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    Uint64 blocks   = len / cMBlockSize;
    int    remBytes = len - (blocks * cMBlockSize);
    err             = ProcessInput(getKey(),
                       cMKeylen,
                       getIv(),
                       cMIvlen,
                       pInput,
                       pOutput,
                       blocks,
                       remBytes);

    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
}

template<>
alc_error_t
ChaCha256T<CpuArchLevel::eReference>::decrypt(const Uint8* pInput,
                                                    Uint8*       pOutput,
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    // ChaCha20 encryption and decryption are identical operations
    return encrypt(pInput, pOutput, len, outlen);
}

} // namespace alcp::cipher
