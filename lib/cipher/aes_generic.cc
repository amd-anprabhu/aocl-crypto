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

    if (numBuffers == 0 || ivLen == 0) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (m_pIvs_aes == nullptr) {
        return ALC_ERROR_BAD_STATE;
    }
    if (ivLen > MAX_CIPHER_IV_SIZE || numBuffers > MAX_CIPHER_BUFFER_SIZE) {
        return ALC_ERROR_INVALID_ARG;
    }
    for (Uint64 i = 0; i < numBuffers; ++i) {
        if (pIv[i] == nullptr) {
            return ALC_ERROR_INVALID_ARG;
        }
        // Initialize per-buffer IV into internal single-IV storage
        Aes::init(pKey, keyLen, pIv[i], ivLen);

        // Copy initialized IV into the statically allocated slot
        memcpy(m_Ivs_aes[i], m_pIv_aes, ivLen);
    }
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
        return ALC_ERROR_NO_FALLBACK;
    }
    // Direct dispatch, no lambdas or std::function
    if constexpr (!(mode == CipherMode::eAesCBC || mode == CipherMode::eAesCFB)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    // Split up the number of buffers into power of 2
    if (__builtin_expect(numBuffers >= 128, 0)) {
        return ALC_ERROR_INVALID_ARG;
    }
    // Power-of-two fast path
    if (__builtin_expect(numBuffers && ((numBuffers & (numBuffers - 1)) == 0), 1)) {
        int i = __builtin_ctzll(numBuffers);
        size_t bufferCount = static_cast<size_t>(1ULL << i);
        if constexpr (mode == CipherMode::eAesCBC) {
            if (i == 0) {
                err = aesni::EncryptCbc(m_pData_aes[0],
                                        pCipherText[0],
                                        len,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[0]);
            } else if (i == 1) {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[j];
                }
                err = vaes::EncryptCbc(&m_pData_aes[0],
                                       &pCipherText[0],
                                       len,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       bufferCount,
                                       ivPtrs);
            } else {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[j];
                }
                err = vaes512::EncryptCbc(&m_pData_aes[0],
                                          &pCipherText[0],
                                          len,
                                          m_cipher_key_data.m_enc_key,
                                          getRounds(),
                                          bufferCount,
                                          ivPtrs);
            }
        } else {
            if (i == 0) {
                err = aesni::EncryptCfb(m_pData_aes[0],
                                        pCipherText[0],
                                        len,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[0]);
            } else if (i == 1) {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[j];
                }
                err = vaes::EncryptCfb(&m_pData_aes[0],
                                       &pCipherText[0],
                                       len,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       bufferCount,
                                       ivPtrs);
            } else {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[j];
                }
                err = vaes512::EncryptCfb(&m_pData_aes[0],
                                          &pCipherText[0],
                                          len,
                                          m_cipher_key_data.m_enc_key,
                                          getRounds(),
                                          bufferCount,
                                          ivPtrs);
            }
        }
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    // General path: iterate over set bits from MSB to LSB
    size_t processedBuffers = 0;
    Uint64 remaining = numBuffers;
    while (remaining) {
        int i = 63 - __builtin_clzll(remaining);
        size_t bufferCount = static_cast<size_t>(1ULL << i);
        if constexpr (mode == CipherMode::eAesCBC) {
            if (i == 0) {
                err = aesni::EncryptCbc(m_pData_aes[processedBuffers],
                                        pCipherText[processedBuffers],
                                        len,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[processedBuffers]);
            } else if (i == 1) {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[processedBuffers + j];
                }
                err = vaes::EncryptCbc(&m_pData_aes[processedBuffers],
                                       &pCipherText[processedBuffers],
                                       len,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       bufferCount,
                                       ivPtrs);
            } else {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[processedBuffers + j];
                }
                err = vaes512::EncryptCbc(&m_pData_aes[processedBuffers],
                                          &pCipherText[processedBuffers],
                                          len,
                                          m_cipher_key_data.m_enc_key,
                                          getRounds(),
                                          bufferCount,
                                          ivPtrs);
            }
        } else {
            if (i == 0) {
                err = aesni::EncryptCfb(m_pData_aes[processedBuffers],
                                        pCipherText[processedBuffers],
                                        len,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[processedBuffers]);
            } else if (i == 1) {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[processedBuffers + j];
                }
                err = vaes::EncryptCfb(&m_pData_aes[processedBuffers],
                                       &pCipherText[processedBuffers],
                                       len,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       bufferCount,
                                       ivPtrs);
            } else {
                Uint8* ivPtrs[MAX_CIPHER_BUFFER_SIZE];
                for (size_t j = 0; j < bufferCount; ++j) {
                    ivPtrs[j] = m_Ivs_aes[processedBuffers + j];
                }
                err = vaes512::EncryptCfb(&m_pData_aes[processedBuffers],
                                          &pCipherText[processedBuffers],
                                          len,
                                          m_cipher_key_data.m_enc_key,
                                          getRounds(),
                                          bufferCount,
                                          ivPtrs);
            }
        }
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        processedBuffers += bufferCount;
        remaining &= ~(1ULL << i);
    }
    return ALC_ERROR_NONE;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::encrypt(const Uint8* pinput,
                                                    Uint8*       pOutput,
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen     = 0;
    m_isEnc_aes = ALCP_ENC;
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
#ifdef AES_MULTI_UPDATE
        // Complete partial block if available
        if (m_partial_len > 0 && len > 0) {
            Uint32 need = 16U - m_partial_len;
            Uint32 take = static_cast<Uint32>(len < static_cast<Uint64>(need)
                                                  ? len
                                                  : static_cast<Uint64>(need));
            memcpy(m_partial_block + m_partial_len, pinput, take);
            m_partial_len += take;
            pinput += take;
            len -= take;
            if (m_partial_len == 16U) {
                err = aesni::EncryptCbc(m_partial_block,
                                        pOutput,
                                        16,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_pIv_aes);
                if (err != ALC_ERROR_NONE) {
                    return err;
                }
                pOutput += 16;
                *outlen += 16;
                m_partial_len = 0;
            }
        }

        // Process full blocks from remaining input
        Uint64 fullBytes = (len / 16ULL) * 16ULL;
        if (fullBytes > 0) {
            err = aesni::EncryptCbc(pinput,
                                    pOutput,
                                    fullBytes,
                                    m_cipher_key_data.m_enc_key,
                                    getRounds(),
                                    m_pIv_aes);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
            pinput += fullBytes;
            pOutput += fullBytes;
            len -= fullBytes;
            *outlen += fullBytes;
        }

        // Buffer trailing bytes (<16)
        if (len > 0) {
            memcpy(m_partial_block, pinput, static_cast<size_t>(len));
            m_partial_len = static_cast<Uint32>(len);
        }

#else
        err = aesni::EncryptCbc(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_pIv_aes);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        *outlen = len; // Set output length for CBC mode
#endif // AES_MULTI_UPDATE
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

    // Set output length for stream modes
    if constexpr (mode != CipherMode::eAesCBC) {
        *outlen = len;
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
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen     = 0;
    m_isEnc_aes = ALCP_DEC;
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
#ifdef AES_MULTI_UPDATE
        // 1) Complete partial block if available
        if (m_partial_len > 0 && len > 0) {
            Uint32 need = 16U - m_partial_len;
            Uint32 take = static_cast<Uint32>(len < static_cast<Uint64>(need)
                                                  ? len
                                                  : static_cast<Uint64>(need));
            memcpy(m_partial_block + m_partial_len, pinput, take);
            m_partial_len += take;
            pinput += take;
            len -= take;
            if (m_partial_len == 16U) {
                err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
                    m_partial_block,
                    pOutput,
                    16,
                    m_cipher_key_data.m_dec_key,
                    m_pIv_aes);
                if (err != ALC_ERROR_NONE) {
                    return err;
                }
                pOutput += 16;
                *outlen += 16;
                m_partial_len = 0;
            }
        }

        // 2) Process full blocks from remaining input
        Uint64 fullBytes = (len / 16ULL) * 16ULL;
        if (fullBytes > 0) {
            err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
                pinput,
                pOutput,
                fullBytes,
                m_cipher_key_data.m_dec_key,
                m_pIv_aes);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
            pinput += fullBytes;
            pOutput += fullBytes;
            len -= fullBytes;
            *outlen += fullBytes;
        }

        // 3) Buffer trailing bytes (<16)
        if (len > 0) {
            memcpy(m_partial_block, pinput, static_cast<size_t>(len));
            m_partial_len = static_cast<Uint32>(len);
        }

#else
        err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
            pinput, pOutput, len, m_cipher_key_data.m_dec_key, m_pIv_aes);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        *outlen = len; // Set output length for CBC mode
#endif // AES_MULTI_UPDATE
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

    // Set output length for stream modes
    if constexpr (mode != CipherMode::eAesCBC) {
        *outlen = len;
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
            return ALC_ERROR_BAD_STATE; // Destination IV buffer not
                                        // allocated
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
