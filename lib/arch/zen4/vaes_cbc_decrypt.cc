/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"

#include <cstdint>
#include <immintrin.h>


#include "alcp/cipher/aesni.hh"
#include "avx512.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

namespace alcp::cipher::vaes512 {

#ifdef AES_CBC_INPLACE_BUFFER
// Helper: Check if more data remains to process
static inline bool
hasMoreData(Uint64 blocks, Uint64 res)
{
    return (blocks > 0) || (res != 0);
}
#endif

template<void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
         void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
         void AesEncNoLoad_4x512(
             __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
alc_error_t inline DecryptCbc(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
{
    if (len == 0) {
        return ALC_ERROR_NONE;
    }

    Uint64 blocks = len / Rijndael::cBlockSize;
    Uint64 res    = len % Rijndael::cBlockSize;

    auto pIn  = reinterpret_cast<const __m128i*>(pCipherText);
    auto pOut = reinterpret_cast<__m512i*>(pPlainText);

    __m512i a1, a2, a3, a4;
    __m512i b1, b2, b3, b4;

    sKeys keys;
    alcp_load_key_zmm(reinterpret_cast<const __m128i*>(pKey), keys);

    // Initialize b1 with IV
    b1 = alcp_loadu_128((const __m512i*)pIv);

    // Process first 4+ blocks with special IV packing: b1 = [IV, c0, c1, c2]
    if (blocks >= 4) {
        // Pack IV with first 3 ciphertext blocks
        __m512i tmp = _mm512_loadu_si512(pIn);
        tmp = _mm512_permutexvar_epi64(_mm512_set_epi64(5, 4, 3, 2, 1, 0, 0, 0), tmp);
        b1  = _mm512_mask_blend_epi64(0xFC, b1, tmp);

        // Process first 16-block batch
        if (blocks >= 16) {
            a1 = _mm512_loadu_si512(pIn);
            a2 = _mm512_loadu_si512(pIn + 4);
            a3 = _mm512_loadu_si512(pIn + 8);
            a4 = _mm512_loadu_si512(pIn + 12);

            b2 = _mm512_loadu_si512(pIn + 3);
            b3 = _mm512_loadu_si512(pIn + 7);
            b4 = _mm512_loadu_si512(pIn + 11);

            AesEncNoLoad_4x512(a1, a2, a3, a4, keys);
            a1 = alcp_xor(a1, b1);
            a2 = alcp_xor(a2, b2);
            a3 = alcp_xor(a3, b3);
            a4 = alcp_xor(a4, b4);

            blocks -= 16;
            b1 = alcp_loadu_128((__m512i*)(pIn + 15));
#ifdef AES_CBC_INPLACE_BUFFER
            if (hasMoreData(blocks, res)) {
                b1 = (blocks >= 4) ? _mm512_loadu_si512(pIn + 15)
                                   : alcp_loadu_128((__m512i*)(pIn + 15));
            }
#endif
            alcp_storeu(pOut, a1);
            alcp_storeu(pOut + 1, a2);
            alcp_storeu(pOut + 2, a3);
            alcp_storeu(pOut + 3, a4);

            pIn += 16;
            pOut += 4;

            // Continue with remaining 16-block batches
            for (; blocks >= 16; blocks -= 16) {
#ifndef AES_CBC_INPLACE_BUFFER
                b1 = _mm512_loadu_si512(pIn - 1);
#endif
                a1 = _mm512_loadu_si512(pIn);
                a2 = _mm512_loadu_si512(pIn + 4);
                a3 = _mm512_loadu_si512(pIn + 8);
                a4 = _mm512_loadu_si512(pIn + 12);

                b2 = _mm512_loadu_si512(pIn + 3);
                b3 = _mm512_loadu_si512(pIn + 7);
                b4 = _mm512_loadu_si512(pIn + 11);

                AesEncNoLoad_4x512(a1, a2, a3, a4, keys);
                a1 = alcp_xor(a1, b1);
                a2 = alcp_xor(a2, b2);
                a3 = alcp_xor(a3, b3);
                a4 = alcp_xor(a4, b4);

                b1 = alcp_loadu_128((__m512i*)(pIn + 15));
#ifdef AES_CBC_INPLACE_BUFFER
                if (hasMoreData(blocks - 16, res)) {
                    b1 = (blocks - 16 >= 4) ? _mm512_loadu_si512(pIn + 15)
                                            : alcp_loadu_128((__m512i*)(pIn + 15));
                }
#endif
                alcp_storeu(pOut, a1);
                alcp_storeu(pOut + 1, a2);
                alcp_storeu(pOut + 2, a3);
                alcp_storeu(pOut + 3, a4);

                pIn += 16;
                pOut += 4;
            }
        }

        // Process 8 blocks
        if (blocks >= 8) {
            // Only reload b1 if we've already processed a previous kernel
            // (pIn has advanced from start). Otherwise, use the packed b1.
#ifndef AES_CBC_INPLACE_BUFFER
            if (pIn != reinterpret_cast<const __m128i*>(pCipherText)) {
                b1 = _mm512_loadu_si512(pIn - 1);
            }
#endif
            a1 = _mm512_loadu_si512(pIn);
            a2 = _mm512_loadu_si512(pIn + 4);
            b2 = _mm512_loadu_si512(pIn + 3);

            AesEncNoLoad_2x512(a1, a2, keys);
            a1 = alcp_xor(a1, b1);
            a2 = alcp_xor(a2, b2);

            blocks -= 8;
            b1 = alcp_loadu_128((__m512i*)(pIn + 7));
#ifdef AES_CBC_INPLACE_BUFFER
            if (hasMoreData(blocks, res)) {
                b1 = (blocks >= 4) ? _mm512_loadu_si512(pIn + 7)
                                   : alcp_loadu_128((__m512i*)(pIn + 7));
            }
#endif
            alcp_storeu(pOut, a1);
            alcp_storeu(pOut + 1, a2);

            pIn += 8;
            pOut += 2;
        }

        // Process 4 blocks
        if (blocks >= 4) {
            // Only reload b1 if we've already processed a previous kernel
#ifndef AES_CBC_INPLACE_BUFFER
            if (pIn != reinterpret_cast<const __m128i*>(pCipherText)) {
                b1 = _mm512_loadu_si512(pIn - 1);
            }
#endif
            a1 = _mm512_loadu_si512(pIn);

            AesEncNoLoad_1x512(a1, keys);
            a1 = alcp_xor(a1, b1);

            blocks -= 4;
            b1 = alcp_loadu_128((__m512i*)(pIn + 3));
#ifdef AES_CBC_INPLACE_BUFFER
            if (hasMoreData(blocks, res)) {
                b1 = alcp_loadu_128((__m512i*)(pIn + 3));
            }
#endif
            alcp_storeu(pOut, a1);

            pIn += 4;
            pOut += 1;
        }
    }

    // Process remaining blocks one at a time (< 4 blocks or residual bytes)
    // b1 is already set: either IV (if no 4+ block path) or last ciphertext
    auto pOut_128 = reinterpret_cast<__m128i*>(pOut);
#ifndef AES_CBC_INPLACE_BUFFER
    const __m128i* pStart = reinterpret_cast<const __m128i*>(pCipherText);
#endif
    len = (blocks * Rijndael::cBlockSize) + res;

    while (len) {
        Uint64 chunk = (len > 16) ? 16 : len;
        Uint64 mask  = (1ULL << chunk) - 1;

        // Load current ciphertext block
        a1 = _mm512_setzero_si512();
        a1 = _mm512_mask_loadu_epi8(a1, mask, pIn);

        // Save current ciphertext for next IV (before potential overwrite)
        __m512i currCt = alcp_loadu_128((__m512i*)pIn);

        // For non-first block in non-inplace mode, load IV from previous ciphertext
#ifndef AES_CBC_INPLACE_BUFFER
        if (pIn != pStart) {
            b1 = alcp_loadu_128((__m512i*)(pIn - 1));
        }
#endif

        // Decrypt and XOR with IV
        AesEncNoLoad_1x512(a1, keys);
        a1 = alcp_xor(a1, b1);
        _mm512_mask_storeu_epi8((__m512i*)pOut_128, mask, a1);

        // Update b1 for next iteration
        b1 = currCt;

        pIn++;
        pOut_128++;
        len -= chunk;
    }

#ifdef AES_MULTI_UPDATE
    // Save last ciphertext as new IV for subsequent calls
    alcp_storeu_128(reinterpret_cast<__m512i*>(pIv), b1);
#endif

    alcp_clear_keys_zmm(keys);
    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes512

namespace alcp::cipher {

template<alcp::cipher::CipherKeyLen T, alcp::utils::CpuArchLevel arch>
alc_error_t
tDecryptCbc(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds10,
                      AesDecryptNoLoad_2x512Rounds10,
                      AesDecryptNoLoad_4x512Rounds10,
                      alcp_load_key_zmm_10rounds,
                      alcp_clear_keys_zmm_10rounds>(
        pSrc, pDest, len, pKey, 10, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey128Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds10,
                      AesDecryptNoLoad_2x512Rounds10,
                      AesDecryptNoLoad_4x512Rounds10,
                      alcp_load_key_zmm_10rounds,
                      alcp_clear_keys_zmm_10rounds>(
        pSrc, pDest, len, pKey, 10, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey192Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds12,
                      AesDecryptNoLoad_2x512Rounds12,
                      AesDecryptNoLoad_4x512Rounds12,
                      alcp_load_key_zmm_12rounds,
                      alcp_clear_keys_zmm_12rounds>(
        pSrc, pDest, len, pKey, 12, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey256Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds14,
                      AesDecryptNoLoad_2x512Rounds14,
                      AesDecryptNoLoad_4x512Rounds14,
                      alcp_load_key_zmm_14rounds,
                      alcp_clear_keys_zmm_14rounds>(
        pSrc, pDest, len, pKey, 14, pIv);
}

} // namespace alcp::cipher
