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

#include "alcp/cipher/aes.hh"
#include "alcp/types.hh"
#include "vaes.hh"
#include "vaes_avx256_core.hh"
#include <complex.h>
#include <cstdint>
#include <cstdio>
#include <immintrin.h>
#include <vector>

#include "alcp/base.hh"
#include "alcp/base/error.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/types.hh"

#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher::vaes {

void
EncryptCbc(Uint64          blocks,
           const __m128i** p_in_128,
           __m128i*        current_ivs,
           int             nRounds,
           sKeys&          keys_ymm,
           __m128i**       p_out_128)
{
    __m256i ymm0;
    for (Uint64 i = 0; i < blocks; i++) {
        __m128i data0 =
            _mm_xor_si128(_mm_loadu_si128(p_in_128[0]), current_ivs[0]);
        __m128i data1 =
            _mm_xor_si128(_mm_loadu_si128(p_in_128[1]), current_ivs[1]);
        ymm0 = _mm256_castsi128_si256(data0);
        ymm0 = _mm256_insertf128_si256(ymm0, data1, 1);
        switch (nRounds) {
            case 10:
                AesEncryptNoLoad_1x256Rounds10(ymm0, keys_ymm);
                break;
            case 12:
                AesEncryptNoLoad_1x256Rounds12(ymm0, keys_ymm);
                break;
            case 14:
                AesEncryptNoLoad_1x256Rounds14(ymm0, keys_ymm);
        }
        // Unpack the result back to 2 lanes of __m128i
        const __m128i ctext_lane0 = _mm256_extractf128_si256(ymm0, 0);
        const __m128i ctext_lane1 = _mm256_extractf128_si256(ymm0, 1);
        _mm_storeu_si128(p_out_128[0], ctext_lane0);
        _mm_storeu_si128(p_out_128[1], ctext_lane1);
        _mm_storeu_si128(&current_ivs[0],
                         ctext_lane0); // Explicit store for IV
        _mm_storeu_si128(&current_ivs[1],
                         ctext_lane1); // Explicit store for IV

        p_in_128[0]++;
        p_out_128[0]++;
        p_in_128[1]++;
        p_out_128[1]++;
    }
}
} // namespace alcp::cipher::vaes
