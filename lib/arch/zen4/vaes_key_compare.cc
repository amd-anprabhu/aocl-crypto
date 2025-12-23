/*
 * Copyright (C) 2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/vaes_key_compare.hh"
#include <immintrin.h>

namespace alcp::cipher::vaes512 {

template<CipherKeyLen keyLen>
inline int
CompareAndStoreT(const Uint8* new_key, Uint8* old_key);

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey128Bit>(const Uint8* new_key, Uint8* old_key)
{
    __m128i old_xmm = _mm_lddqu_si128((const __m128i*)old_key);
    __m128i new_xmm = _mm_lddqu_si128((const __m128i*)new_key);

    if (_mm_cmp_epu64_mask(old_xmm, new_xmm, _MM_CMPINT_EQ) == 0x03) {
        return 1; // Keys same
    }
    _mm_storeu_si128((__m128i*)old_key, new_xmm);
    return 0; // Keys different, stored
}

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey192Bit>(const Uint8* new_key, Uint8* old_key)
{
    // Load 24 bytes using masked load (3 x 64-bit elements)
    const __mmask8 cMask   = 0b0111; // Load 3 elements
    __m256i        old_ymm = _mm256_maskz_loadu_epi64(cMask, old_key);
    __m256i        new_ymm = _mm256_maskz_loadu_epi64(cMask, new_key);

    if (_mm256_cmp_epu64_mask(old_ymm, new_ymm, _MM_CMPINT_EQ) == 0x0F) {
        return 1; // Keys same
    }
    _mm256_mask_storeu_epi64(old_key, cMask, new_ymm);
    return 0; // Keys different, stored
}

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey256Bit>(const Uint8* new_key, Uint8* old_key)
{
    __m256i old_ymm = _mm256_lddqu_si256((const __m256i*)old_key);
    __m256i new_ymm = _mm256_lddqu_si256((const __m256i*)new_key);

    if (_mm256_cmp_epu64_mask(old_ymm, new_ymm, _MM_CMPINT_EQ) == 0x0F) {
        return 1; // Keys same
    }
    _mm256_storeu_si256((__m256i*)old_key, new_ymm);
    return 0; // Keys different, stored
}

int
CompareAndStoreKey(const Uint8* new_key, Uint8* old_key, Uint32 keyLenBytes)
{
    switch (keyLenBytes) {
        case 16:
            return CompareAndStoreT<CipherKeyLen::eKey128Bit>(new_key, old_key);
        case 24:
            return CompareAndStoreT<CipherKeyLen::eKey192Bit>(new_key, old_key);
        case 32:
            return CompareAndStoreT<CipherKeyLen::eKey256Bit>(new_key, old_key);
        default:
            return 0; // Should not reach here
    }
}

} // namespace alcp::cipher::vaes512
