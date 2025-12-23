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

#include "alcp/cipher/aesni_key_compare.hh"
#include <cstring>
#include <immintrin.h>

namespace alcp::cipher::aesni {

template<CipherKeyLen keyLen>
inline int
CompareAndStoreT(const Uint8* new_key, Uint8* old_key);

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey128Bit>(const Uint8* new_key, Uint8* old_key)
{
    __m128i old_key_xmm = _mm_lddqu_si128((const __m128i*)old_key);
    __m128i new_key_xmm = _mm_lddqu_si128((const __m128i*)new_key);

    if (_mm_test_all_ones(_mm_cmpeq_epi64(old_key_xmm, new_key_xmm))) {
        return 1; // Keys same
    }
    _mm_storeu_si128((__m128i*)old_key, new_key_xmm);
    return 0; // Keys different, stored
}

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey192Bit>(const Uint8* new_key, Uint8* old_key)
{
    __m128i old_key_lo = _mm_lddqu_si128((const __m128i*)old_key);
    __m128i new_key_lo = _mm_lddqu_si128((const __m128i*)new_key);

    if (!_mm_test_all_ones(_mm_cmpeq_epi64(old_key_lo, new_key_lo))) {
        memcpy(old_key, new_key, sizeof(__m128i));
        return 0; // Keys different, stored
    }

    // Compare the remaining 8 bytes (192-bit key = 16 bytes + 8 bytes)
    Uint64 old_key_hi = *(const Uint64*)(old_key + sizeof(__m128i));
    Uint64 new_key_hi = *(const Uint64*)(new_key + sizeof(__m128i));

    if (old_key_hi == new_key_hi) {
        return 1; // Keys same
    } else {
        memcpy(old_key, new_key, 16);
        return 0; // Keys different, stored
    }
}

template<>
inline int
CompareAndStoreT<CipherKeyLen::eKey256Bit>(const Uint8* new_key, Uint8* old_key)
{
    __m128i old_key_lo = _mm_lddqu_si128((const __m128i*)old_key);
    __m128i new_key_lo = _mm_lddqu_si128((const __m128i*)new_key);

    if (!_mm_test_all_ones(_mm_cmpeq_epi64(old_key_lo, new_key_lo))) {
        memcpy(old_key, new_key, 32);
        return 0; // Keys different, stored
    }

    __m128i old_key_hi =
        _mm_lddqu_si128((const __m128i*)(old_key + sizeof(__m128i)));
    __m128i new_key_hi =
        _mm_lddqu_si128((const __m128i*)(new_key + sizeof(__m128i)));

    if (_mm_test_all_ones(_mm_cmpeq_epi64(old_key_hi, new_key_hi))) {
        return 1; // Keys same
    } else {
        _mm_storeu_si128((__m128i*)old_key, new_key_lo);
        _mm_storeu_si128((__m128i*)(old_key + sizeof(__m128i)), new_key_hi);
        return 0; // Keys different, stored
    }
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

} // namespace alcp::cipher::aesni
