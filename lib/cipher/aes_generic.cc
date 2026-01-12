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


// flush function to store the multibuffer data to the memory (variable-length version)
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::flush(const Uint8**  pPlainText,
                                                  const Uint64*  pLengths,
                                                  Uint64         numBuffers)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (pPlainText == nullptr || pLengths == nullptr) {
        printf("\nError: Invalid input pointer\n");
        return ALC_ERROR_INVALID_ARG;
    }
    if (numBuffers > MAX_CIPHER_BUFFER_SIZE) {
        return ALC_ERROR_INVALID_ARG;
    }
    m_pData_aes = pPlainText;
    // Copy lengths to member array
    for (Uint64 i = 0; i < numBuffers; i++) {
        m_bufferLengths_aes[i] = pLengths[i];
    }
    return err;
}

/**
 * @brief Dequeue processed ciphertext buffers with variable lengths (multi-buffer API)
 *
 * This function implements the **Iterative MinLen Algorithm** for processing multiple
 * buffers with varying lengths while maximizing SIMD parallelism.
 *
 * ## Algorithm Overview
 *
 * The naive approach of processing each buffer individually wastes SIMD lanes. Instead,
 * we use an iterative strategy that keeps all SIMD lanes utilized as long as possible:
 *
 * ```
 * Example with 4 buffers of lengths: [64, 128, 128, 256] bytes
 *
 * Iteration 1: minLen = 64
 *   Process all 4 buffers for 64 bytes (VAES512 - 4 lanes active)
 *   Buffer 0 completes, removed from active list
 *   Remaining: [-, 64, 64, 192]
 *
 * Iteration 2: minLen = 64
 *   Process 3 buffers for 64 bytes (VAES512 + AESNI decomposition)
 *   Buffers 1,2 complete
 *   Remaining: [-, -, -, 128]
 *
 * Iteration 3: Single buffer remains
 *   Process buffer 3 for 128 bytes (AESNI single-buffer path)
 * ```
 *
 * ## Processing Steps
 *
 * 1. **Initialize**: Track active buffer indices and current offsets (all start at 0)
 * 2. **Iterate**: While 2+ buffers active:
 *    - Find minimum remaining length among active buffers
 *    - Process all active buffers for that length using SIMD
 *    - Remove completed buffers from active list
 * 3. **Single Buffer**: If one buffer remains, process with AESNI
 * 4. **Tails**: Process any remaining unaligned bytes individually
 *
 * @param[out] pCipherText  Array of pointers to ciphertext output buffers
 * @param[in]  numBuffers   Number of buffers to process (max 127)
 * @param[in]  pLengths     Array of per-buffer lengths in bytes (or nullptr to use
 *                          lengths from prior flush() call)
 * @return ALC_ERROR_NONE on success, error code otherwise
 *
 * @note This function requires AVX512 VAES support. Falls back with ALC_ERROR_NO_FALLBACK
 *       on systems without this capability.
 * @note Only CBC and CFB modes are currently supported for variable-length multi-buffer.
 */
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::dequeue(Uint8**       pCipherText,
                                                    Uint64        numBuffers,
                                                    const Uint64* pLengths)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;

    // Validate cipher state
    if (__builtin_expect(!(m_isKeySet_aes), 0)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (__builtin_expect(m_ivLen_aes != 16, 0)) {
        m_ivLen_aes = 16;
    }

    // Require AVX512 VAES for multi-buffer operations
    if (__builtin_expect(arch < CpuCipherFeatures::eVaes512, 0)) {
        return ALC_ERROR_NO_FALLBACK;
    }

    // Only CBC and CFB modes support variable-length multi-buffer
    if constexpr (!(mode == CipherMode::eAesCBC || mode == CipherMode::eAesCFB)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    // Validate buffer count (must fit in stack-allocated arrays)
    if (__builtin_expect(numBuffers > MAX_CIPHER_BUFFER_SIZE, 0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    // Use provided lengths or fall back to lengths from flush() call
    const Uint64* actualLengths = pLengths ? pLengths : m_bufferLengths_aes;

    // Step 1: Initialize active buffer tracking
    // activeIndices: Maps position in processing arrays to original buffer index
    // This allows us to remove completed buffers without reordering original data
    Uint64 activeIndices[MAX_CIPHER_BUFFER_SIZE];
    Uint64 activeCount = numBuffers;
    for (Uint64 i = 0; i < numBuffers; i++) {
        activeIndices[i] = i;
    }

    // Track how many bytes we've processed for each buffer
    Uint64 currentOffsets[MAX_CIPHER_BUFFER_SIZE];
    for (Uint64 i = 0; i < numBuffers; i++) {
        currentOffsets[i] = 0;
    }

    // Step 2: Iterative MinLen processing loop
    // Continue while we have 2+ buffers (can use SIMD parallelism)
    while (activeCount > 2) {
        // Find minimum remaining length among all active buffers
        // This is the amount we can safely process for ALL buffers in parallel
        Uint64 minLen = UINT64_MAX;
        for (Uint64 i = 0; i < activeCount; i++) {
            Uint64 bufIdx = activeIndices[i];
            Uint64 remaining = actualLengths[bufIdx] - currentOffsets[bufIdx];
            if (remaining < minLen) {
                minLen = remaining;
            }
        }

        // Align to AES block boundary (16 bytes)
        // Any remaining bytes < 16 will be handled in Step 4
        minLen = (minLen / 16) * 16;

        // If no aligned data remains, exit loop to process unaligned tails
        if (minLen == 0) {
            break;
        }

        // Power-of-2 decomposition: Process buffers in optimal SIMD batches
        // Example: 5 buffers → batch of 4 (VAES512) + batch of 1 (AESNI)
        // This ensures we always use the widest SIMD path available
        Uint64 processed = 0;
        Uint64 toProcess = activeCount;

        while (toProcess > 0) {
            // Find highest set bit to get largest power-of-2 batch size
            // __builtin_clzll counts leading zeros, so 63 - clz gives bit position
            int i = 63 - __builtin_clzll(toProcess);
            size_t batchCount = static_cast<size_t>(1ULL << i);

            // Prepare contiguous arrays for SIMD processing
            // Map from active buffer positions to original buffer data
            const Uint8* batchInputs[MAX_CIPHER_BUFFER_SIZE];
            Uint8* batchOutputs[MAX_CIPHER_BUFFER_SIZE];
            Uint8* batchIvs[MAX_CIPHER_BUFFER_SIZE];

            for (size_t j = 0; j < batchCount; j++) {
                Uint64 bufIdx = activeIndices[processed + j];
                batchInputs[j] = m_pData_aes[bufIdx] + currentOffsets[bufIdx];
                batchOutputs[j] = pCipherText[bufIdx] + currentOffsets[bufIdx];
                batchIvs[j] = m_Ivs_aes[bufIdx];
            }

            // Dispatch to optimal SIMD implementation based on batch size:
            //   i=0 (1 buffer):  AESNI single-buffer
            //   i=1 (2 buffers): VAES256 (2 lanes)
            //   i≥2 (4+ buffers): VAES512 (4 lanes per ZMM register)
            if constexpr (mode == CipherMode::eAesCBC) {
                if (i == 0) {
                    // Single buffer - use aesni
                    err = aesni::EncryptCbc(batchInputs[0],
                                            batchOutputs[0],
                                            minLen,
                                            m_cipher_key_data.m_enc_key,
                                            getRounds(),
                                            batchIvs[0]);
                } else if (i == 1) {
                    // 2 buffers - use VAES256
                    err = vaes::EncryptCbc(batchInputs,
                                           batchOutputs,
                                           minLen,
                                           m_cipher_key_data.m_enc_key,
                                           getRounds(),
                                           batchCount,
                                           batchIvs);
                } else {
                    // 4+ buffers - use VAES512
                    err = vaes512::EncryptCbc(batchInputs,
                                              batchOutputs,
                                              minLen,
                                              m_cipher_key_data.m_enc_key,
                                              getRounds(),
                                              batchCount,
                                              batchIvs);
                }
            } else {  // CipherMode::eAesCFB
                if (i == 0) {
                    // Single buffer - use aesni
                    err = aesni::EncryptCfb(batchInputs[0],
                                            batchOutputs[0],
                                            minLen,
                                            m_cipher_key_data.m_enc_key,
                                            getRounds(),
                                            batchIvs[0]);
                } else if (i == 1) {
                    // 2 buffers - use VAES256
                    err = vaes::EncryptCfb(batchInputs,
                                           batchOutputs,
                                           minLen,
                                           m_cipher_key_data.m_enc_key,
                                           getRounds(),
                                           batchCount,
                                           batchIvs);
                } else {
                    // 4+ buffers - use VAES512
                    err = vaes512::EncryptCfb(batchInputs,
                                              batchOutputs,
                                              minLen,
                                              m_cipher_key_data.m_enc_key,
                                              getRounds(),
                                              batchCount,
                                              batchIvs);
                }
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            // Update offsets for processed buffers
            for (size_t j = 0; j < batchCount; j++) {
                Uint64 bufIdx = activeIndices[processed + j];
                currentOffsets[bufIdx] += minLen;
            }

            processed += batchCount;
            toProcess &= ~(1ULL << i);  // Clear the bit we just processed
        }

        // Compact active buffer list by removing completed buffers
        // A buffer is complete when its offset equals its total length
        Uint64 newActiveCount = 0;
        for (Uint64 i = 0; i < activeCount; i++) {
            Uint64 bufIdx = activeIndices[i];
            if (currentOffsets[bufIdx] < actualLengths[bufIdx]) {
                activeIndices[newActiveCount++] = bufIdx;
            }
        }
        activeCount = newActiveCount;
    }

    // Step 3: Handle single/two remaining buffer
    // When only two buffers remains use VAES Path
    if (activeCount == 2) {
        Uint64 bufIdx0 = activeIndices[0];
        Uint64 bufIdx1 = activeIndices[1];

        Uint64 remaining0 = actualLengths[bufIdx0] - currentOffsets[bufIdx0];
        Uint64 remaining1 = actualLengths[bufIdx1] - currentOffsets[bufIdx1];
        Uint64 minLen = (remaining0 < remaining1 ? remaining0 : remaining1);
        Uint64 alignedLen = (minLen / 16) * 16;

        if (alignedLen > 0) {
            const Uint8* batchInputs[2] = {
                m_pData_aes[bufIdx0] + currentOffsets[bufIdx0],
                m_pData_aes[bufIdx1] + currentOffsets[bufIdx1]
            };
            Uint8* batchOutputs[2] = {
                pCipherText[bufIdx0] + currentOffsets[bufIdx0],
                pCipherText[bufIdx1] + currentOffsets[bufIdx1]
            };
            Uint8* batchIvs[2] = {
                m_Ivs_aes[bufIdx0],
                m_Ivs_aes[bufIdx1]
            };

            if constexpr (mode == CipherMode::eAesCBC) {
                err = vaes::EncryptCbc(batchInputs,
                                       batchOutputs,
                                       alignedLen,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       2,
                                       batchIvs);
            } else { // eAesCFB
                err = vaes::EncryptCfb(batchInputs,
                                       batchOutputs,
                                       alignedLen,
                                       m_cipher_key_data.m_enc_key,
                                       getRounds(),
                                       2,
                                       batchIvs);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            currentOffsets[bufIdx0] += alignedLen;
            currentOffsets[bufIdx1] += alignedLen;
        }
    }

    // When only one buffer remains, SIMD parallelism isn't beneficial
    // Use single-buffer AESNI path for remaining aligned data
    if (activeCount == 1) {
        Uint64 bufIdx = activeIndices[0];
        Uint64 remaining = actualLengths[bufIdx] - currentOffsets[bufIdx];
        Uint64 alignedLen = (remaining / 16) * 16;

        if (alignedLen > 0) {
            const Uint8* input = m_pData_aes[bufIdx] + currentOffsets[bufIdx];
            Uint8* output = pCipherText[bufIdx] + currentOffsets[bufIdx];

            if constexpr (mode == CipherMode::eAesCBC) {
                err = aesni::EncryptCbc(input,
                                        output,
                                        alignedLen,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[bufIdx]);
            } else {  // CipherMode::eAesCFB
                err = aesni::EncryptCfb(input,
                                        output,
                                        alignedLen,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[bufIdx]);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            currentOffsets[bufIdx] += alignedLen;
        }
    }

    // =========================================================================
    // Step 4: Process unaligned tail bytes
    // =========================================================================
    // Any buffer with length not divisible by 16 has remaining bytes
    // These must be processed individually (cannot parallelize partial blocks)
    for (Uint64 i = 0; i < numBuffers; i++) {
        Uint64 remaining = actualLengths[i] - currentOffsets[i];

        if (remaining > 0) {
            const Uint8* tailInput = m_pData_aes[i] + currentOffsets[i];
            Uint8* tailOutput = pCipherText[i] + currentOffsets[i];

            if constexpr (mode == CipherMode::eAesCBC) {
                err = aesni::EncryptCbc(tailInput,
                                        tailOutput,
                                        remaining,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[i]);
            } else {  // CipherMode::eAesCFB
                err = aesni::EncryptCfb(tailInput,
                                        tailOutput,
                                        remaining,
                                        m_cipher_key_data.m_enc_key,
                                        getRounds(),
                                        m_Ivs_aes[i]);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
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