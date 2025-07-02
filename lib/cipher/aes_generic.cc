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

#include "alcp/cipher/aes.hh"
//
#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"
#include <stdexcept>

using alcp::utils::CpuId;

namespace alcp::cipher {

// WIP

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::multibufferInit(const Uint8* pKey,
                                                            Uint64       keyLen,
                                                            const Uint8** pIv,
                                                            Uint64        ivLen,
                                                            Uint64 numBuffers)
{
    // Store buffer count for destructor
    m_numBuffers = numBuffers;

    m_pIvs_aes = new Uint8*[numBuffers];
    if (m_pIvs_aes == nullptr) {
        return ALC_ERROR_NO_MEMORY;
    }

    for (Uint64 i = 0; i < numBuffers; ++i) {
        Aes::init(pKey, keyLen, pIv[i], ivLen);
        // allocate memory for each Iv
        m_pIvs_aes[i] = new Uint8[ivLen];
        if (m_pIvs_aes[i] == nullptr) {
            // Clean up on failure
            for (Uint64 j = 0; j < i; ++j) {
                delete[] m_pIvs_aes[j];
            }
            delete[] m_pIvs_aes;
            m_pIvs_aes = nullptr;
            return ALC_ERROR_NO_MEMORY;
        }
        memcpy(m_pIvs_aes[i], m_pIv_aes, ivLen); // copy each IV
    }
    // REMOVED: delete[] m_pIv_aes; // INVALID: m_pIv_aes points to
    // stack-allocated m_iv_aes
    return ALC_ERROR_NONE;
}
// flush function to store the multibuffer data to the memory

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::flush(const Uint8** pPlainText,
                                                  Uint64        numBuffers,
                                                  Uint64        len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (pPlainText == nullptr) {
        printf("\nError: Invalid input pointer\n");
        return ALC_ERROR_INVALID_ARG;
    }
    m_pData_aes = pPlainText;
    return err;
}
// Dequence the data
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::dequeue(Uint8** pCipherText,
                                                    Uint64  numBuffers,
                                                    Uint64  len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;
    if (__builtin_expect(!(m_isKeySet_aes), 0)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (__builtin_expect(m_ivLen_aes != 16, 0)) {
        m_ivLen_aes = 16;
    }

    if (__builtin_expect(arch < CpuCipherFeatures::eVaes512, 0)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (mode == CipherMode::eAesCBC) {
        // Split up the number of buffers into power of 2
        if (__builtin_expect(numBuffers >= 128, 0)) {
            return ALC_ERROR_INVALID_ARG;
        }
        int processedBuffers = 0;
        // Only bits 0 to 6 are needed since 2^7 = 128 which is the
        // max currently supported
        for (int i = 7; i >= 0; i--) {
            if (numBuffers & (1ULL << i)) {
                if (i == 0) {
                    err = aesni::EncryptCbc(m_pData_aes[processedBuffers],
                                            pCipherText[processedBuffers],
                                            len,
                                            m_cipher_key_data.m_enc_key,
                                            getRounds(),
                                            m_pIvs_aes[processedBuffers]);
                    processedBuffers++;
                } else {
                    err = vaes512::EncryptCbc(&m_pData_aes[processedBuffers],
                                              &pCipherText[processedBuffers],
                                              len,
                                              m_cipher_key_data.m_enc_key,
                                              getRounds(),
                                              (1ULL << i),
                                              &m_pIvs_aes[processedBuffers]);
                    processedBuffers += (1ULL << i);
                }
                if (err != ALC_ERROR_NONE) {
                    return err;
                }
            }
        }
    }
    return ALC_ERROR_NONE;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::encrypt(const Uint8* pinput,
                                                    Uint8*       pOutput,
                                                    Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    /*
        eAesCBC,
        eAesOFB,
        eAesCTR,
        eAesCFB,*/

    if constexpr (arch < CpuCipherFeatures::eAesni) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (mode == CipherMode::eAesCBC) {
        err = aesni::EncryptCbc(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_pIv_aes);
    } else if constexpr (mode == CipherMode::eAesOFB) {
        err = aesni::EncryptOfb(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_pIv_aes);
    } else if constexpr (mode == CipherMode::eAesCTR) {
        if constexpr (arch == CpuCipherFeatures::eVaes512) {
            err = CryptCtr<keyLenBits, arch>(pinput,
                                             pOutput,
                                             len,
                                             m_cipher_key_data.m_enc_key,
                                             getRounds(),
                                             m_pIv_aes);
        } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
            err = vaes::CryptCtr(pinput,
                                 pOutput,
                                 len,
                                 m_cipher_key_data.m_enc_key,
                                 getRounds(),
                                 m_pIv_aes);
        } else if constexpr (arch == CpuCipherFeatures::eAesni) {
            err = aesni::CryptCtr(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_enc_key,
                                  getRounds(),
                                  m_pIv_aes);
        }
    } else if constexpr (mode == CipherMode::eAesCFB) {
        err = aesni::EncryptCfb(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_pIv_aes);
    }
    // WIP, other generic modes to be added.
    return err;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::decrypt(const Uint8* pinput,
                                                    Uint8*       pOutput,
                                                    Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_DEC;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    if constexpr (arch < CpuCipherFeatures::eAesni) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (mode == CipherMode::eAesCBC) {
        err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
            pinput, pOutput, len, m_cipher_key_data.m_dec_key, m_pIv_aes);
    } else if constexpr (mode == CipherMode::eAesOFB) {
        err = aesni::DecryptOfb(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_pIv_aes);
    } else if constexpr (mode == CipherMode::eAesCTR) {
        if constexpr (arch == CpuCipherFeatures::eVaes512) {
            err = CryptCtr<keyLenBits, arch>(pinput,
                                             pOutput,
                                             len,
                                             m_cipher_key_data.m_enc_key,
                                             getRounds(),
                                             m_pIv_aes);
        } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
            err = vaes::CryptCtr(pinput,
                                 pOutput,
                                 len,
                                 m_cipher_key_data.m_enc_key,
                                 getRounds(),
                                 m_pIv_aes);
        } else if constexpr (arch == CpuCipherFeatures::eAesni) {
            err = aesni::CryptCtr(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_enc_key,
                                  getRounds(),
                                  m_pIv_aes);
        }
    } else if constexpr (mode == CipherMode::eAesCFB) {
        err = DecryptCfb<keyLenBits, arch>(pinput,
                                           pOutput,
                                           len,
                                           m_cipher_key_data.m_enc_key,
                                           getRounds(),
                                           m_pIv_aes);
    }
    return err;
}

/*
 * @brief        CopyCtx
 * @param[in]    pSrc
 * @param[in]    pDst
 * @return       ALC_ERROR_NONE
 */
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::CopyCtx(const iCipher* pSrc,
                                                    iCipher*       pDst)
{
    if (pSrc == nullptr || pDst == nullptr) {
        return ALC_ERROR_BAD_STATE;
    }

    // Cast to the correct derived class type
    const auto* src =
        dynamic_cast<const AesGenericCiphersT<mode, keyLenBits, arch>*>(pSrc);
    auto* dst = dynamic_cast<AesGenericCiphersT<mode, keyLenBits, arch>*>(pDst);

    if (src == nullptr || dst == nullptr) {
        return ALC_ERROR_INVALID_ARG; // Types don't match
    }

    // Copy cipher key data (includes both encryption and decryption keys)
    // Copy IV if it exists
    if (src->m_pIv_aes != nullptr && src->m_ivLen_aes > 0) {
        if (dst->m_pIv_aes != nullptr) {
            memcpy(dst->m_pIv_aes, src->m_pIv_aes, src->m_ivLen_aes);
        } else {
            return ALC_ERROR_BAD_STATE; // Destination IV buffer not allocated
        }
    }

    dst->m_cipher_key_data.m_enc_key = dst->Rijndael::getEncryptKeysRound();
    dst->m_cipher_key_data.m_dec_key = dst->Rijndael::getDecryptKeysRound();

    memcpy((void*)dst->m_cipher_key_data.m_enc_key,
           src->m_cipher_key_data.m_enc_key,
           alcp::cipher::Rijndael::cRoundKeySize);
    memcpy((void*)dst->m_cipher_key_data.m_dec_key,
           src->m_cipher_key_data.m_dec_key,
           alcp::cipher::Rijndael::cRoundKeySize);

    // Copy state variables
    dst->m_isKeySet_aes = src->m_isKeySet_aes;
    dst->m_isEnc_aes    = src->m_isEnc_aes;
    dst->Rijndael::setRounds(src->getRounds());

    dst->m_keyLen_in_bytes_aes = src->m_keyLen_in_bytes_aes;
    dst->m_dataLen             = src->m_dataLen;

    return ALC_ERROR_NONE;
}

#if 1

/*
    eAesCBC,
    eAesOFB,
    eAesCTR,
    eAesCFB,*/
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesOFB */
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesCTR */
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesCFB */
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

// other generic modes to be added.
#endif

} // namespace alcp::cipher
