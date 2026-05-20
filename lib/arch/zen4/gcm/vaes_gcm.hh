/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#pragma once

#include <cstdint>
#include <immintrin.h>

#include "alcp/cipher/aes_gcm.hh"
#include "alcp/types.hh"

#define NUM_PARALLEL_ZMMS 4

/*_mm_prefetch accepts const void*` arguments for GCC / ICC
whereas MSVC still expects `const char* ` */
#ifdef _WIN32
#define cast_to(ptr) ((const char*)ptr)
#else
#define cast_to(ptr) ((void*)ptr)
#endif

namespace alcp::cipher::vaes512 {

// dynamic Unrolling
int inline dynamicUnroll(Uint64 blocks)
{

    // int num_512_blks = (blocks << 2);
    // num_512_blks     = (num_512_blks >= 8) ? 8 : num_512_blks;

    int num_512_blks = 0; // 4 blocks in 512 bit
    if (blocks >= 32) {
        num_512_blks = 8; // 8x4 = 32 blks = 32x128/8 = 512 bytes
    } else if (blocks >= 16) {
        num_512_blks = 4; // 4x4 blks = 256 bytes
    } else if (blocks >= 8) {
        num_512_blks = 2;
    } else if (blocks >= 4) {
        num_512_blks = 1;
    }
    return num_512_blks;
}

void inline computeHashSubKeys(int           num_512_blks,
                               __m128i       Hsubkey_128,
                               __m512i*      pHashSubkeyTableLocal,
                               const __m128i const_factor_128)
{
    __m128i h_128_2 = carryless_multiply(Hsubkey_128, Hsubkey_128);
    __m128i h_128_3 = carryless_multiply(Hsubkey_128, h_128_2);
    __m128i h_128_4 = carryless_multiply(h_128_2, h_128_2);

    __m512i hkey{};
    hkey                     = _mm512_inserti64x2(hkey, Hsubkey_128, 3);
    hkey                     = _mm512_inserti64x2(hkey, h_128_2, 2);
    hkey                     = _mm512_inserti64x2(hkey, h_128_3, 1);
    hkey                     = _mm512_inserti64x2(hkey, h_128_4, 0);
    pHashSubkeyTableLocal[0] = hkey;

    if (num_512_blks >= 2) {
        __m512i Hsubkey_4 = _mm512_broadcast_i64x2(h_128_4);
        __m512i Hsubkey_8 = carryless_multiply(Hsubkey_4, Hsubkey_4);

        pHashSubkeyTableLocal[1] =
            carryless_multiply(pHashSubkeyTableLocal[0], Hsubkey_4);

        for (int i = 2; i < num_512_blks; i += 2) {
            pHashSubkeyTableLocal[i] =
                carryless_multiply(pHashSubkeyTableLocal[i - 2], Hsubkey_8);
            if (i + 1 < num_512_blks) {
                pHashSubkeyTableLocal[i + 1] =
                    carryless_multiply(pHashSubkeyTableLocal[i], Hsubkey_4);
            }
        }
    }
}

void inline computeHashSubKeys_withStore(int      num_512_blks,
                                         __m128i  Hsubkey_128,
                                         __m512i* p512GcmCtxHashSubkeyTable,
                                         __m512i* pHashSubkeyTableLocal,
                                         const __m128i const_factor_128)
{
    __m128i*      pHashSubkeyTableLocal_128 = (__m128i*)pHashSubkeyTableLocal;
    const __m512i const_factor_512 = _mm512_set_epi64(0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1);

    __m128i h_128_0, h_128_1, h_128_2;
    aesni::gMul(Hsubkey_128, Hsubkey_128, h_128_2, const_factor_128); // 2
    aesni::gMul(h_128_2, Hsubkey_128, h_128_1, const_factor_128);     // 1
    aesni::gMul(h_128_1, Hsubkey_128, h_128_0, const_factor_128);     // 0

    pHashSubkeyTableLocal_128[3] = Hsubkey_128;
    pHashSubkeyTableLocal_128[2] = h_128_2;
    pHashSubkeyTableLocal_128[1] = h_128_1;
    pHashSubkeyTableLocal_128[0] = h_128_0;
    // store to gcm ctx
    _mm512_store_si512(p512GcmCtxHashSubkeyTable, pHashSubkeyTableLocal[0]);
    p512GcmCtxHashSubkeyTable++;

    const Uint64* H4_64     = (const Uint64*)pHashSubkeyTableLocal_128;
    __m512i       Hsubkey_4 = _mm512_set_epi64(H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0]);

    for (int i = 1; i < num_512_blks; i++) {
        gMulParallel4(pHashSubkeyTableLocal[i],
                      pHashSubkeyTableLocal[i - 1],
                      Hsubkey_4,
                      const_factor_512);
        // store to gcm ctx
        _mm512_store_si512(p512GcmCtxHashSubkeyTable, pHashSubkeyTableLocal[i]);
        p512GcmCtxHashSubkeyTable++;
    }
}

void inline getPrecomputedTable(Uint64         updateCounter,
                                __m512i*       p512GcmCtxHashSubkeyTable,
                                __m512i*       pHashSubkeyTableLocal,
                                int            num_512_blks,
                                alc_gcm_ctx_t* gcmCtx,
                                __m128i        const_factor_128)
{
    _mm_prefetch(cast_to(p512GcmCtxHashSubkeyTable), _MM_HINT_T0);

#if ALWAYS_COMPUTE
    if (num_512_blks) {
        computeHashSubKeys(num_512_blks,
                           gcmCtx->m_hash_subKey_128,
                           pHashSubkeyTableLocal,
                           const_factor_128);
        return;
    }
#else  // ALWAYS_COMPUTE
    if ((updateCounter == 1)
        || (num_512_blks > gcmCtx->m_num_512blks_precomputed)) {
        // updateCounter is 1, compute subkeys and store in table
        computeHashSubKeys_withStore(num_512_blks,
                                     gcmCtx->m_hash_subKey_128,
                                     p512GcmCtxHashSubkeyTable,
                                     pHashSubkeyTableLocal,
                                     const_factor_128);

        gcmCtx->m_num_512blks_precomputed = num_512_blks;
    } else {
        // load from table
        int i = 0;
        for (; i < num_512_blks - 4; i += 4) {
            pHashSubkeyTableLocal[0] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable);
            pHashSubkeyTableLocal[1] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 1);
            pHashSubkeyTableLocal[2] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 2);
            pHashSubkeyTableLocal[3] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 3);

            pHashSubkeyTableLocal += 4;
            p512GcmCtxHashSubkeyTable += 4;
        }
        for (; i < num_512_blks; i++) {
            pHashSubkeyTableLocal[0] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable);
            pHashSubkeyTableLocal++;
            p512GcmCtxHashSubkeyTable++;
        }
    }
    return;
#endif // ALWAYS_COMPUTE
}

template<void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys)>
__attribute__((always_inline)) static inline void
process_residue(const __m512i* p_in_512,
                __m512i*       p_out_512,
                Uint64         blocks,
                int            remBytes,
                const sKeys&   keys,
                alc_gcm_ctx_t* gcmCtx,
                const __m512i& cSwapCtr,
                const __m512i& cReverseMask,
                bool           is_encrypt)
{
    const Uint64 c_lanes = blocks + (remBytes ? 1 : 0);
    if (!c_lanes)
        return;

    __m128i h1 = gcmCtx->m_hash_subKey_128;
    __m128i c00, c01, c10, c11;

    __m512i X{}, H{};

    __m512i c1 = _mm512_broadcast_i64x2(gcmCtx->m_counter_128);
    c1         = _mm512_add_epi32(
        c1, _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3));

    const Uint64 c_bytes = (blocks * 16) + remBytes;
    const Uint64 c_mask  = _bzhi_u64(0xFFFFFFFFFFFFFFFF, c_bytes);
    __m512i      a1      = _mm512_maskz_loadu_epi8(c_mask, p_in_512);

    __m512i b1 = _mm512_shuffle_epi8(c1, cSwapCtr);
    AesEncNoLoad_1x512(b1, keys);

    switch (c_lanes) {
        case 4: {
            cmul128(h1, h1, c00, c01, c10, c11);
            __m128i h2 = combine_cmul128(c00, c01, c10, c11);
            cmul128(h1, h2, c00, c01, c10, c11);
            __m128i h3 = combine_cmul128(c00, c01, c10, c11);
            cmul128(h2, h2, c00, c01, c10, c11);
            __m128i h4 = combine_cmul128(c00, c01, c10, c11);
            H          = _mm512_inserti64x2(H, h4, 0);
            H          = _mm512_inserti64x2(H, h3, 1);
            H          = _mm512_inserti64x2(H, h2, 2);
            H          = _mm512_inserti64x2(H, h1, 3);
            break;
        }
        case 3: {
            cmul128(h1, h1, c00, c01, c10, c11);
            __m128i h2 = combine_cmul128(c00, c01, c10, c11);
            cmul128(h1, h2, c00, c01, c10, c11);
            __m128i h3 = combine_cmul128(c00, c01, c10, c11);
            H          = _mm512_inserti64x2(H, h3, 0);
            H          = _mm512_inserti64x2(H, h2, 1);
            H          = _mm512_inserti64x2(H, h1, 2);
            H          = _mm512_inserti64x2(H, h3, 3);
            break;
        }
        case 2: {
            cmul128(h1, h1, c00, c01, c10, c11);
            __m128i h2 = combine_cmul128(c00, c01, c10, c11);
            H          = _mm512_inserti64x2(H, h2, 0);
            H          = _mm512_inserti64x2(H, h1, 1);
            H          = _mm512_inserti64x2(H, h2, 2);
            break;
        }
    }

    if (is_encrypt) {
        // Encrypt: XOR then store, GHASH on output (ciphertext)
        a1 = _mm512_xor_si512(b1, a1);
        _mm512_mask_storeu_epi8(p_out_512, c_mask, a1);
        X = _mm512_mask_mov_epi8(X, c_mask, a1);
        X = _mm512_shuffle_epi8(X, cReverseMask);
    } else {
        // Decrypt: GHASH on input (ciphertext), then XOR and store
        X  = _mm512_mask_mov_epi8(X, c_mask, a1);
        X  = _mm512_shuffle_epi8(X, cReverseMask);
        a1 = _mm512_xor_si512(b1, a1);
        _mm512_mask_storeu_epi8(p_out_512, c_mask, a1);
    }

    // Update counter
    __m128i c1_128 = _mm512_castsi512_si128(c1);
    gcmCtx->m_counter_128 =
        _mm_add_epi32(c1_128, _mm_set_epi32(c_lanes, 0, 0, 0));

    // GHASH computation
    __m512i g = _mm512_zextsi128_si512(gcmCtx->m_gHash_128);
    switch (c_lanes) {
        case 4:
            X = _mm512_xor_si512(X, g);
            break;
        case 3:
            X = _mm512_inserti64x2(X, gcmCtx->m_gHash_128, 3);
            break;
        case 2:
            X = _mm512_inserti64x2(X, gcmCtx->m_gHash_128, 2);
            break;
        case 1: {
            __m128i g_128 =
                _mm_xor_si128(_mm512_castsi512_si128(X), gcmCtx->m_gHash_128);
            __m128i c00_128, c01_128, c10_128, c11_128;
            cmul128(h1, g_128, c00_128, c01_128, c10_128, c11_128);
            gcmCtx->m_gHash_128 =
                combine_cmul128(c00_128, c01_128, c10_128, c11_128);
            return;
        }
    }

    __m512i c00_512, c01_512, c10_512, c11_512;
    cmul512(H, X, c00_512, c01_512, c10_512, c11_512);
    __m512i result      = combine_cmul512(c00_512, c01_512, c10_512, c11_512);
    gcmCtx->m_gHash_128 = amd512_horizontal_sum128(result);
}

} // namespace alcp::cipher::vaes512
