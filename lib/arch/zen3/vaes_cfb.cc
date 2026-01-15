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

#include "vaes_cfb.hh"

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

#include "alcp/cipher/aesni.hh"
#include "alcp/types.hh"

#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher::vaes {

alc_error_t
EncryptCfb(const Uint8** pPlainText,
           Uint8**       pCipherText,
           Uint64        len,
           const Uint8*  pKey,
           int           nRounds,
           int           num_buffers,
           Uint8**       pIv)
{
    Uint64      blocks = len / Rijndael::cBlockSize;
    alc_error_t err    = ALC_ERROR_NONE;

    if (__builtin_expect(num_buffers == 0 || blocks == 0, 0)) {
        return ALC_ERROR_NONE;
    }

    if (__builtin_expect(nRounds != 10 && nRounds != 12 && nRounds != 14, 0)) {
        return ALC_ERROR_INVALID_ARG; // Invalid number of rounds
    }

    // Use dynamic allocation to avoid template attribute warnings
    auto p_in_128_storage    = std::make_unique<const __m128i*[]>(num_buffers);
    auto p_out_128_storage   = std::make_unique<__m128i*[]>(num_buffers);
    auto current_ivs_storage = std::make_unique<__m128i[]>(num_buffers);
    const __m128i**         p_in_128    = p_in_128_storage.get();
    __m128i**               p_out_128   = p_out_128_storage.get();
    __m128i*                current_ivs = current_ivs_storage.get();
    auto                    pkey128 = reinterpret_cast<const __m128i*>(pKey);
    alignas(64) vaes::sKeys keys_ymm{};

    for (int i = 0; i < num_buffers; i++) {
        p_in_128[i]  = reinterpret_cast<const __m128i*>(pPlainText[i]);
        p_out_128[i] = reinterpret_cast<__m128i*>(pCipherText[i]);
        //clang-format off
        current_ivs[i] =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv[i]));
        // clang-format on
    }
    switch (nRounds) {
        case 10:
            vaes::alcp_load_key_ymm_10rounds(pkey128, keys_ymm);
            break;
        case 12:
            vaes::alcp_load_key_ymm_12rounds(pkey128, keys_ymm);
            break;
        case 14:
            vaes::alcp_load_key_ymm_14rounds(pkey128, keys_ymm);
            break;
    }
    __m256i ymm0;
    for (Uint64 i = 0; i < blocks; i++) {
        // Pack current IVs into YMM register using AVX2 intrinsics
        ymm0 = _mm256_castsi128_si256(current_ivs[0]);
        ymm0 = _mm256_inserti128_si256(ymm0, current_ivs[1], 1);

        // Encrypt the IVs
        switch (nRounds) {
            case 10:
                vaes::AesEncryptNoLoad_1x256Rounds10(ymm0, keys_ymm);
                break;
            case 12:
                vaes::AesEncryptNoLoad_1x256Rounds12(ymm0, keys_ymm);
                break;
            case 14:
                vaes::AesEncryptNoLoad_1x256Rounds14(ymm0, keys_ymm);
                break;
        }

        // Unpack the encrypted IVs and XOR with plaintext using AVX2 intrinsics
        const __m128i encrypted_iv0 = _mm256_castsi256_si128(ymm0);
        const __m128i encrypted_iv1 = _mm256_extracti128_si256(ymm0, 1);

        const __m128i ctext0 =
            _mm_xor_si128(encrypted_iv0, _mm_loadu_si128(p_in_128[0]));
        const __m128i ctext1 =
            _mm_xor_si128(encrypted_iv1, _mm_loadu_si128(p_in_128[1]));

        _mm_storeu_si128(p_out_128[0], ctext0);
        _mm_storeu_si128(p_out_128[1], ctext1);

        // Update IVs with ciphertext blocks for CFB mode
        _mm_storeu_si128(&current_ivs[0], ctext0);
        _mm_storeu_si128(&current_ivs[1], ctext1);

        p_in_128[0]++;
        p_out_128[0]++;
        p_in_128[1]++;
        p_out_128[1]++;
    }
    // Update final IVs in the caller's pIv array if AES_MULTI_UPDATE is
    // defined
#ifdef AES_MULTI_UPDATE
    for (int i = 0; i < num_buffers; i++) {
        // Store the last ciphertext block (now in current_ivs[i]) back
        // to pIv[i]
        _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv[i]), current_ivs[i]);
    }
#endif
    return err;
}
} // namespace alcp::cipher::vaes
