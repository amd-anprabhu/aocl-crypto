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

#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/base.hh"

namespace alcp::cipher {

using mac::poly1305::Poly1305;

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setIvInternal(const Uint8* iv, Uint64 ivLen)
{
    if (ivLen != 12) {
        return ALC_ERROR_INVALID_SIZE;
    }
    
    // ChaCha20-Poly1305 uses 12-byte nonce with 4-byte counter prefix
    // Store in IvManager via parent class (16 bytes total: 4 counter + 12 nonce)
    Uint8 fullIv[16] = {};
    memset(fullIv, 0, 4);          // Counter = 0
    memcpy(fullIv + 4, iv, ivLen); // Nonce
    
    alc_error_t err = ChaCha256T<arch>::m_ivManager.setIv(fullIv, 16);
    if (err == ALC_ERROR_NONE) {
        ChaCha256T<arch>::m_stateManager.onIvSet();
    }
    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setKeyInternal(const Uint8* key, Uint64 keylen)
{
    alc_error_t err = ChaCha256T<arch>::setKey(key, keylen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    std::fill(m_poly1305_key, m_poly1305_key + 32, 0);
    Uint64 outlen = 0;
    err = ChaCha256T<arch>::encrypt(m_poly1305_key, m_poly1305_key, 32, &outlen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    m_len_input_processed.u64 = 0;
    m_len_aad_processed.u64   = 0;
    err = Poly1305<utils::CpuArchLevel::eDynamic>::init(m_poly1305_key, 32);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    return ALC_ERROR_NONE;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::init(const Uint8* pKey,
                       Uint64       keyLen,
                       const Uint8* pIv,
                       Uint64       ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    err = setIvInternal(pIv, ivLen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = setKeyInternal(pKey, keyLen);
    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::encrypt(const Uint8* inputBuffer,
                          Uint8*       outputBuffer,
                          Uint64       bufferLength,
                          Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    
    // Set Counter to 1 - access IV via IvManager
    Uint8* pIv = ChaCha256T<arch>::getIv();
    (*(reinterpret_cast<Uint32*>(pIv))) += 1;
    
    Uint64 chacha_outlen = 0;
    err = ChaCha256T<arch>::encrypt(
        inputBuffer, outputBuffer, bufferLength, &chacha_outlen);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // ChaCha20-Poly1305 is an AEAD: output length equals input length on
    // success
    if (outlen != nullptr) {
        *outlen = bufferLength;
    }

    m_len_input_processed.u64 += bufferLength;

    Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                ? 0
                                : (16 - (m_len_aad_processed.u64 % 16));
    if (padding_length != 0) {
        err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_zero_padding, padding_length);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(outputBuffer, bufferLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    padding_length = ((m_len_input_processed.u64 % 16) == 0)
                         ? 0
                         : (16 - (m_len_input_processed.u64 % 16));
    if (padding_length != 0) {
        err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_zero_padding, padding_length);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    constexpr Uint64 cSizeLength = sizeof(Uint64);
    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_len_aad_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_len_input_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::decrypt(const Uint8* inputBuffer,
                          Uint8*       outputBuffer,
                          Uint64       bufferLength,
                          Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    
    // Set Counter to 1 - access IV via IvManager
    Uint8* pIv = ChaCha256T<arch>::getIv();
    (*(reinterpret_cast<Uint32*>(pIv))) += 1;
    
    Uint64 chacha_outlen = 0;
    err = ChaCha256T<arch>::encrypt(
        inputBuffer, outputBuffer, bufferLength, &chacha_outlen);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // ChaCha20-Poly1305 is an AEAD: output length equals input length on
    // success
    if (outlen != nullptr) {
        *outlen = bufferLength;
    }

    m_len_input_processed.u64 += bufferLength;

    Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                ? 0
                                : (16 - (m_len_aad_processed.u64 % 16));
    if (padding_length != 0) {
        err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_zero_padding, padding_length);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    // In case of decryption one should change the order of updation i.e
    // input (which is the ciphertext) should be updated
    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(inputBuffer, bufferLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    padding_length = ((m_len_input_processed.u64 % 16) == 0)
                         ? 0
                         : (16 - (m_len_input_processed.u64 % 16));
    if (padding_length != 0) {
        err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_zero_padding, padding_length);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    constexpr Uint64 cSizeLength = sizeof(Uint64);
    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_len_aad_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = Poly1305<utils::CpuArchLevel::eDynamic>::update(m_len_input_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setAad(const Uint8* pInput, Uint64 len)
{
    alc_error_t err = Poly1305<utils::CpuArchLevel::eDynamic>::update(pInput, len);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    m_len_aad_processed.u64 += len;
    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::getTag(Uint8* pOutput, Uint64 len)
{
    alc_error_t err = Poly1305<utils::CpuArchLevel::eDynamic>::finalize(pOutput, len);
    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setTagLength(Uint64 tagLength)
{
    if (tagLength != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    return ALC_ERROR_NONE;
}

// Explicit template instantiations
template class ChaChPolyT<CpuArchLevel::eZen4>;
template class ChaChPolyT<CpuArchLevel::eReference>;

} // namespace alcp::cipher
