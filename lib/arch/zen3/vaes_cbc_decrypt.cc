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

#include "vaes.hh"

#include "alcp/cipher/aesni.hh"
#include "alcp/types.hh"
#include "avx256.hh"

#include <immintrin.h>

namespace alcp::cipher::vaes {

template<void AesDec_1x128(__m256i* pBlk0, const __m128i* pKey, int nRounds),
         void AesDec_2x128(
             __m256i* pBlk0, __m256i* pBlk1, const __m128i* pKey, int nRounds),
         void AesDec_4x128(__m256i*       pBlk0,
                           __m256i*       pBlk1,
                           __m256i*       pBlk2,
                           __m256i*       pBlk3,
                           const __m128i* pKey,
                           int            nRounds)>
alc_error_t
DecryptCbc(const Uint8* pCipherText,
           Uint8*       pPlainText,
           Uint64       len,
           const Uint8* pKey,
           int          nRounds,
           Uint8*       pIv)
{
    if (len == 0) {
        return ALC_ERROR_NONE;
    }

    auto pkey128 = reinterpret_cast<const __m128i*>(pKey);

    // Fast path: AES-NI for single block (< 32 bytes)
    if (len < 32) {
        auto    p_in  = reinterpret_cast<const __m128i*>(pCipherText);
        auto    p_out = reinterpret_cast<__m128i*>(pPlainText);
        __m128i iv =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv));

        while (len >= 16) {
            __m128i ct    = _mm_loadu_si128(p_in);
            __m128i block = ct;
            aesni::AesDecrypt(&block, pkey128, nRounds);
            block = _mm_xor_si128(block, iv);
            _mm_storeu_si128(p_out, block);
            iv = ct;
            p_in++;
            p_out++;
            len -= 16;
        }

#ifdef AES_MULTI_UPDATE
        _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv), iv);
#endif
        return ALC_ERROR_NONE;
    }

    // VAES-256 path for 2+ blocks (32+ bytes)
    auto p_in_128  = reinterpret_cast<const __m128i*>(pCipherText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pPlainText);

    __m256i cblock1, cblock2, cblock3, cblock4;
    __m256i iv1, iv2, iv3, iv4;

    // Pack IV: iv1 = [IV, c0] (analogous to Zen4's permute+blend)
    iv1 = _mm256_inserti128_si256(
        _mm256_castsi128_si256(
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv))),
        _mm_loadu_si128(p_in_128),
        1);

    // Hot inner loop: 8 blocks (128 bytes) per iteration.
    // len >= 256 guarantees another batch follows, so 256-bit
    // iv1 reload is unconditionally safe.
    for (; len >= 256; len -= 128) {
        cblock1 = _mm256_loadu_si256((__m256i*)(p_in_128));
        cblock2 = _mm256_loadu_si256((__m256i*)(p_in_128 + 2));
        cblock3 = _mm256_loadu_si256((__m256i*)(p_in_128 + 4));
        cblock4 = _mm256_loadu_si256((__m256i*)(p_in_128 + 6));

        iv2 = _mm256_loadu_si256((__m256i*)(p_in_128 + 1));
        iv3 = _mm256_loadu_si256((__m256i*)(p_in_128 + 3));
        iv4 = _mm256_loadu_si256((__m256i*)(p_in_128 + 5));

        AesDec_4x128(&cblock1, &cblock2, &cblock3, &cblock4, pkey128,
                      nRounds);

        cblock1 = _mm256_xor_si256(cblock1, iv1);
        cblock2 = _mm256_xor_si256(cblock2, iv2);
        cblock3 = _mm256_xor_si256(cblock3, iv3);
        cblock4 = _mm256_xor_si256(cblock4, iv4);

        iv1 = _mm256_loadu_si256((__m256i*)(p_in_128 + 7));

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), cblock1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 2),
                            cblock2);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 4),
                            cblock3);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 6),
                            cblock4);

        p_in_128 += 8;
        p_out_128 += 8;
    }

    // Last 8-block batch (128 <= len < 256): conditional iv1 reload
    if (len >= 128) {
        cblock1 = _mm256_loadu_si256((__m256i*)(p_in_128));
        cblock2 = _mm256_loadu_si256((__m256i*)(p_in_128 + 2));
        cblock3 = _mm256_loadu_si256((__m256i*)(p_in_128 + 4));
        cblock4 = _mm256_loadu_si256((__m256i*)(p_in_128 + 6));

        iv2 = _mm256_loadu_si256((__m256i*)(p_in_128 + 1));
        iv3 = _mm256_loadu_si256((__m256i*)(p_in_128 + 3));
        iv4 = _mm256_loadu_si256((__m256i*)(p_in_128 + 5));

        AesDec_4x128(&cblock1, &cblock2, &cblock3, &cblock4, pkey128,
                      nRounds);

        cblock1 = _mm256_xor_si256(cblock1, iv1);
        cblock2 = _mm256_xor_si256(cblock2, iv2);
        cblock3 = _mm256_xor_si256(cblock3, iv3);
        cblock4 = _mm256_xor_si256(cblock4, iv4);

        len -= 128;
        if (len >= 32) {
            iv1 = _mm256_loadu_si256((__m256i*)(p_in_128 + 7));
        } else {
            iv1 = _mm256_castsi128_si256(_mm_loadu_si128(p_in_128 + 7));
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), cblock1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 2),
                            cblock2);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 4),
                            cblock3);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 6),
                            cblock4);

        p_in_128 += 8;
        p_out_128 += 8;
    }

    // 4-block batch (64 bytes)
    if (len >= 64) {
        cblock1 = _mm256_loadu_si256((__m256i*)(p_in_128));
        cblock2 = _mm256_loadu_si256((__m256i*)(p_in_128 + 2));
        iv2     = _mm256_loadu_si256((__m256i*)(p_in_128 + 1));

        AesDec_2x128(&cblock1, &cblock2, pkey128, nRounds);

        cblock1 = _mm256_xor_si256(cblock1, iv1);
        cblock2 = _mm256_xor_si256(cblock2, iv2);

        len -= 64;
        if (len >= 32) {
            iv1 = _mm256_loadu_si256((__m256i*)(p_in_128 + 3));
        } else {
            iv1 = _mm256_castsi128_si256(_mm_loadu_si128(p_in_128 + 3));
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), cblock1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128 + 2),
                            cblock2);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    // 2-block batch (32 bytes)
    if (len >= 32) {
        cblock1 = _mm256_loadu_si256((__m256i*)p_in_128);

        AesDec_1x128(&cblock1, pkey128, nRounds);
        cblock1 = _mm256_xor_si256(cblock1, iv1);

        len -= 32;
        iv1 = _mm256_castsi128_si256(_mm_loadu_si128(p_in_128 + 1));

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), cblock1);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    // 1-block tail: AES-NI (same approach as Zen4 tail)
    if (len >= 16) {
        __m128i ct    = _mm_loadu_si128(p_in_128);
        __m128i block = ct;
        aesni::AesDecrypt(&block, pkey128, nRounds);
        block = _mm_xor_si128(block, _mm256_castsi256_si128(iv1));
        _mm_storeu_si128(p_out_128, block);
        iv1 = _mm256_castsi128_si256(ct);
    }

#ifdef AES_MULTI_UPDATE
    _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv),
                     _mm256_castsi256_si128(iv1));
#endif

    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes

namespace alcp::cipher {

// primary template
template<alcp::cipher::CipherKeyLen T, alcp::utils::CpuArchLevel arch>
alc_error_t
tDecryptCbc(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    constexpr int nRounds = static_cast<int>(T) / 32 + 6;
    return alcp::cipher::vaes::DecryptCbc<alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey128Bit,
            alcp::utils::CpuArchLevel::eZen3>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    return alcp::cipher::vaes::DecryptCbc<alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, 10, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey192Bit,
            alcp::utils::CpuArchLevel::eZen3>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    return alcp::cipher::vaes::DecryptCbc<alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, 12, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey256Bit,
            alcp::utils::CpuArchLevel::eZen3>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    return alcp::cipher::vaes::DecryptCbc<alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt,
                                          alcp::cipher::vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, 14, pIv);
}
} // namespace alcp::cipher