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
#pragma once

#include <immintrin.h>

#include "config.h"

#ifdef COMPILER_IS_GCC
#define UNROLL_4  _Pragma("GCC unroll 4")
#define UNROLL_8  _Pragma("GCC unroll 8")
#define UNROLL_14 _Pragma("GCC unroll 14")
#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_48 _Pragma("GCC unroll 48")
#else
#define UNROLL_4
#define UNROLL_8
#define UNROLL_14
#define UNROLL_16
#define UNROLL_48
#endif

#define I_TO_F(zmm) _mm512_castsi512_ps(zmm)
#define F_TO_I(zmm) _mm512_castps_si512(zmm)

#define BITS_PER_BYTE           8
#define XMM_SIZE_BYTES          sizeof(__m128i)
#define SHA256_WORD_SIZE_BYTES  sizeof(Uint32)
#define SHA256_BLOCK_SIZE_BYTES 64
#define SHA256_BLOCK_SIZE_WORDS SHA256_BLOCK_SIZE_BYTES / SHA256_WORD_SIZE_BYTES
#define BUFFERS_16              16
#define MAX_BUFFERS             128
#define ROUNDS                  64
#define ROUNDS_48               48
#define ROUNDS_16               16
#define NUM_WORKING_VARIABLES   8
#define SHA256_HASH_SIZE_BYTES  32
#define SHA256_HASH_SIZE_WORDS  SHA256_HASH_SIZE_BYTES / SHA256_WORD_SIZE_BYTES
#define NUM_XMM_PER_BLOCK       SHA256_BLOCK_SIZE_BYTES / XMM_SIZE_BYTES

namespace alcp::digest { namespace zen4 {

    alignas(64) static constexpr Uint32 cRoundConstants_SHA256[ROUNDS] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

#ifdef ALCP_CONFIG_LITTLE_ENDIAN
    alignas(64) static constexpr Uint64 c_mask[8] = {
        0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL,
        0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL,
        0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL
    };
#endif

    static inline __attribute__((always_inline)) __m512i ternary_xor(__m512i a,
                                                                     __m512i b,
                                                                     __m512i c)
    {
#ifdef COMPILER_IS_GCC
        // Memory fence to prevent reordering
        asm volatile("" ::: "memory");
#endif
        // NOTE: We deliberately avoid _mm512_ternarylogic_epi32(a, b, c,
        // 0x96) because this implementation provides better performance.
        return _mm512_xor_si512(a, _mm512_xor_si512(b, c));
    }

    static inline __attribute__((always_inline)) __m512i sigma_0(__m512i line)
    {
        /* sigma0(x) = ROTR(x,7) ^ ROTR(x,8) ^ SHR(x,3) */
        return ternary_xor(_mm512_ror_epi32(line, 7),
                           _mm512_ror_epi32(line, 18),
                           _mm512_srli_epi32(line, 3));
    }

    static inline __attribute__((always_inline)) __m512i sigma_1(__m512i line)
    {
        /* sigma0(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10) */
        return ternary_xor(_mm512_ror_epi32(line, 17),
                           _mm512_ror_epi32(line, 19),
                           _mm512_srli_epi32(line, 10));
    }

    static inline __attribute__((always_inline)) __m512i Sigma_0(__m512i line)
    {
        /* Sigma0(x) = ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) */
        return ternary_xor(_mm512_ror_epi32(line, 2),
                           _mm512_ror_epi32(line, 13),
                           _mm512_ror_epi32(line, 22));
    }

    static inline __attribute__((always_inline)) __m512i Sigma_1(__m512i line)
    {
        /* Sigma1(x) = ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) */
        return ternary_xor(_mm512_ror_epi32(line, 6),
                           _mm512_ror_epi32(line, 11),
                           _mm512_ror_epi32(line, 25));
    }

    static inline __attribute__((always_inline)) void broadcast_state(
        Uint32   hash[SHA256_HASH_SIZE_WORDS],
        __m512i& zmm0,
        __m512i& zmm1,
        __m512i& zmm2,
        __m512i& zmm3,
        __m512i& zmm4,
        __m512i& zmm5,
        __m512i& zmm6,
        __m512i& zmm7)
    {
        /* Broadcast the state set in init to all instances */
        zmm0 = _mm512_set1_epi32(hash[0]);
        zmm1 = _mm512_set1_epi32(hash[1]);
        zmm2 = _mm512_set1_epi32(hash[2]);
        zmm3 = _mm512_set1_epi32(hash[3]);
        zmm4 = _mm512_set1_epi32(hash[4]);
        zmm5 = _mm512_set1_epi32(hash[5]);
        zmm6 = _mm512_set1_epi32(hash[6]);
        zmm7 = _mm512_set1_epi32(hash[7]);
    }

    static inline __attribute__((always_inline)) void shuffle_line(
        __m512i& line)
    {
#ifdef ALCP_CONFIG_LITTLE_ENDIAN
        /* SHA-2 expects data in big-endian format.
         * Because x86 architectures use little-endian memory representation,
         * data loaded from memory must be rotated byte-wise to big-endian
         * format before use.
         */
        line =
            _mm512_shuffle_epi8(line, _mm512_load_si512((void const*)c_mask));
#endif
    }

    static inline __attribute__((always_inline)) void pack(const __m128i* p0,
                                                           const __m128i* p1,
                                                           const __m128i* p2,
                                                           const __m128i* p3,
                                                           __m512i&       zmm,
                                                           Uint16 mask = 0xFFFF)
    {
        /* Load data from four instances into one ZMM. */
        __m128i xmm0 = _mm_maskz_loadu_epi8(mask, p0);
        __m128i xmm1 = _mm_maskz_loadu_epi8(mask, p1);
        __m128i xmm2 = _mm_maskz_loadu_epi8(mask, p2);
        __m128i xmm3 = _mm_maskz_loadu_epi8(mask, p3);

        zmm = _mm512_inserti32x4(zmm, xmm0, 0);
        zmm = _mm512_inserti32x4(zmm, xmm1, 1);
        zmm = _mm512_inserti32x4(zmm, xmm2, 2);
        zmm = _mm512_inserti32x4(zmm, xmm3, 3);
        shuffle_line(zmm);
    }

    static inline __attribute__((always_inline)) void transpose_4x16_u32(
        __m512i& zmm0, __m512i& zmm1, __m512i& zmm2, __m512i& zmm3)
    {
        /*
         * Input:
         * zmm0 = a0 a1 a2 a3     e0 e1 e2 e3     i0 i1 i2 i3     m0 m1 m2 m3
         * zmm1 = b0 b1 b2 b3     f0 f1 f2 f3     j0 j1 j2 j3     n0 n1 n2 n3
         * zmm2 = c0 c1 c2 c3     g0 g1 g2 g3     k0 k1 k2 k3     o0 o1 o2 o3
         * zmm3 = d0 d1 d2 d3     h0 h1 h2 h3     l0 l1 l2 l3     p0 p1 p2 p3
         *
         * Output:
         * zmm0 = a0 b0 c0 d0     e0 f0 g0 h0     i0 j0 k0 l0     m0 n0 o0 p0
         * zmm1 = a1 b1 c1 d1     e1 f1 g1 h1     i1 j1 k1 l1     m1 n1 o1 p1
         * zmm2 = a2 b2 c2 d2     e2 f2 g2 h2     i2 j2 k2 l2     m2 n2 o2 p2
         * zmm3 = a3 b3 c3 d3     e3 f3 g3 h3     i3 j3 k3 l3     m3 n3 o3 p3
         *
         * `a` through `p` indicate data from different instances/buffers.
         */
        __m512 t0 = _mm512_shuffle_ps(I_TO_F(zmm0), I_TO_F(zmm1), 0b01000100);
        __m512 t1 = _mm512_shuffle_ps(I_TO_F(zmm2), I_TO_F(zmm3), 0b01000100);
        __m512 t2 = _mm512_shuffle_ps(I_TO_F(zmm0), I_TO_F(zmm1), 0b11101110);
        __m512 t3 = _mm512_shuffle_ps(I_TO_F(zmm2), I_TO_F(zmm3), 0b11101110);

        zmm0 = F_TO_I(_mm512_shuffle_ps(t0, t1, 0b10001000));
        zmm1 = F_TO_I(_mm512_shuffle_ps(t0, t1, 0b11011101));
        zmm2 = F_TO_I(_mm512_shuffle_ps(t2, t3, 0b10001000));
        zmm3 = F_TO_I(_mm512_shuffle_ps(t2, t3, 0b11011101));
    }

    static inline void load_words_4x16_u32(const __m128i** pp_para_src,
                                           Uint64          offset,
                                           __m512i&        zmm0,
                                           __m512i&        zmm1,
                                           __m512i&        zmm2,
                                           __m512i&        zmm3,
                                           Uint16          mask = 0xFFFF)
    {
        /* Load 4 words from 16 buffers */
        pack(pp_para_src[0] + offset,
             pp_para_src[4] + offset,
             pp_para_src[8] + offset,
             pp_para_src[12] + offset,
             zmm0,
             mask);
        pack(pp_para_src[1] + offset,
             pp_para_src[5] + offset,
             pp_para_src[9] + offset,
             pp_para_src[13] + offset,
             zmm1,
             mask);
        pack(pp_para_src[2] + offset,
             pp_para_src[6] + offset,
             pp_para_src[10] + offset,
             pp_para_src[14] + offset,
             zmm2,
             mask);
        pack(pp_para_src[3] + offset,
             pp_para_src[7] + offset,
             pp_para_src[11] + offset,
             pp_para_src[15] + offset,
             zmm3,
             mask);
    }

    static inline void zero_rows(__m512i block[SHA256_BLOCK_SIZE_WORDS],
                                 Uint64  p_index)
    {
        switch (p_index) {
            case 0:
                block[0] = _mm512_setzero_si512();
                block[1] = _mm512_setzero_si512();
                block[2] = _mm512_setzero_si512();
                block[3] = _mm512_setzero_si512();
                [[fallthrough]];
            case 1:
                block[4] = _mm512_setzero_si512();
                block[5] = _mm512_setzero_si512();
                block[6] = _mm512_setzero_si512();
                block[7] = _mm512_setzero_si512();
                [[fallthrough]];
            case 2:
                block[8]  = _mm512_setzero_si512();
                block[9]  = _mm512_setzero_si512();
                block[10] = _mm512_setzero_si512();
                block[11] = _mm512_setzero_si512();
                [[fallthrough]];
            case 3:
                block[12] = _mm512_setzero_si512();
                block[13] = _mm512_setzero_si512();
                /* block[14] and block[15] need not be set to zero as padding
                 * will be placed in them in the finalize function */
                break;
            default:
                break;
        }
    }

    static inline void partial_load_block(
        const __m128i** pp_para_src,
        Uint64          res,
        Uint64          offset,
        __m512i         block[SHA256_BLOCK_SIZE_WORDS])
    {
        /*
         * +------------+---------+-----------+-------------+-----------+
         * | res(bytes) | p_index | full rows | partial row | zero rows |
         * +------------+---------+-----------+-------------+-----------+
         * | 0          | 0       | -         | -           | 0,1,2,3   |
         * | 1 - 15     | 1       | -         | 0           | 1,2,3     |
         * | 16 - 31    | 2       | 0         | 1           | 2,3       |
         * | 32 - 47    | 3       | 0,1       | 2           | 3         |
         * | 48 - 63    | 4       | 0,1,2     | 3           | -         |
         * +------------+---------+-----------+-------------+-----------+
         */
        Uint64         p_index = res ? (res >> 4) + 1 : 0;
        const __m128i* p[BUFFERS_16];

        UNROLL_16
        for (size_t i = 0; i < BUFFERS_16; ++i) {
            p[i] = pp_para_src[i] + offset;
        }

        /* Load full rows */
        switch (p_index) {
            case 4:
                load_words_4x16_u32(
                    p, 2, block[8], block[9], block[10], block[11]);
                transpose_4x16_u32(block[8], block[9], block[10], block[11]);
                [[fallthrough]];
            case 3:
                load_words_4x16_u32(
                    p, 1, block[4], block[5], block[6], block[7]);
                transpose_4x16_u32(block[4], block[5], block[6], block[7]);
                [[fallthrough]];
            case 2:
                load_words_4x16_u32(
                    p, 0, block[0], block[1], block[2], block[3]);
                transpose_4x16_u32(block[0], block[1], block[2], block[3]);
                break;
            default:
                break;
        }

        /* Load one partial row */
        if (p_index) {
            Uint16 mask = 0xFFFF >> (BUFFERS_16 - (res & (BUFFERS_16 - 1)));
            Uint64 pos  = (p_index - 1) * 4;
            load_words_4x16_u32(p,
                                p_index - 1,
                                block[pos],
                                block[pos + 1],
                                block[pos + 2],
                                block[pos + 3],
                                mask);
            transpose_4x16_u32(
                block[pos], block[pos + 1], block[pos + 2], block[pos + 3]);
        }

        /* Zero out remaining rows to avoid stale data in later rounds */
        zero_rows(block, p_index);
    }

    static inline void store(__m128i** pp_dst,
                             __m512i   state[8],
                             Uint64    digest_len)
    {
        UNROLL_8
        for (Uint64 i = 0; i < NUM_WORKING_VARIABLES; ++i) {
            shuffle_line(state[i]);
        }

        /* Transpose words in hash, so that words in same instance/buffer are
         * grouped together
         */
        transpose_4x16_u32(state[0], state[1], state[2], state[3]);
        transpose_4x16_u32(state[4], state[5], state[6], state[7]);

        __m128i xmm[BUFFERS_16];
        xmm[0] = _mm512_extracti32x4_epi32(state[0], 0);
        xmm[1] = _mm512_extracti32x4_epi32(state[1], 0);
        xmm[2] = _mm512_extracti32x4_epi32(state[2], 0);
        xmm[3] = _mm512_extracti32x4_epi32(state[3], 0);

        xmm[4] = _mm512_extracti32x4_epi32(state[0], 1);
        xmm[5] = _mm512_extracti32x4_epi32(state[1], 1);
        xmm[6] = _mm512_extracti32x4_epi32(state[2], 1);
        xmm[7] = _mm512_extracti32x4_epi32(state[3], 1);

        xmm[8]  = _mm512_extracti32x4_epi32(state[0], 2);
        xmm[9]  = _mm512_extracti32x4_epi32(state[1], 2);
        xmm[10] = _mm512_extracti32x4_epi32(state[2], 2);
        xmm[11] = _mm512_extracti32x4_epi32(state[3], 2);

        xmm[12] = _mm512_extracti32x4_epi32(state[0], 3);
        xmm[13] = _mm512_extracti32x4_epi32(state[1], 3);
        xmm[14] = _mm512_extracti32x4_epi32(state[2], 3);
        xmm[15] = _mm512_extracti32x4_epi32(state[3], 3);

        UNROLL_16
        for (Uint64 i = 0; i < BUFFERS_16; i++) {
            _mm_storeu_si128(pp_dst[i], xmm[i]);
        }

        xmm[0] = _mm512_extracti32x4_epi32(state[4], 0);
        xmm[1] = _mm512_extracti32x4_epi32(state[5], 0);
        xmm[2] = _mm512_extracti32x4_epi32(state[6], 0);
        xmm[3] = _mm512_extracti32x4_epi32(state[7], 0);

        xmm[4] = _mm512_extracti32x4_epi32(state[4], 1);
        xmm[5] = _mm512_extracti32x4_epi32(state[5], 1);
        xmm[6] = _mm512_extracti32x4_epi32(state[6], 1);
        xmm[7] = _mm512_extracti32x4_epi32(state[7], 1);

        xmm[8]  = _mm512_extracti32x4_epi32(state[4], 2);
        xmm[9]  = _mm512_extracti32x4_epi32(state[5], 2);
        xmm[10] = _mm512_extracti32x4_epi32(state[6], 2);
        xmm[11] = _mm512_extracti32x4_epi32(state[7], 2);

        xmm[12] = _mm512_extracti32x4_epi32(state[4], 3);
        xmm[13] = _mm512_extracti32x4_epi32(state[5], 3);
        xmm[14] = _mm512_extracti32x4_epi32(state[6], 3);
        xmm[15] = _mm512_extracti32x4_epi32(state[7], 3);

        if (digest_len == SHA256_HASH_SIZE_BYTES) {
            UNROLL_16
            for (Uint64 i = 0; i < BUFFERS_16; i++) {
                _mm_storeu_si128(pp_dst[i] + 1, xmm[i]);
            }
        } else {
            /* Digest truncation for SHA2_224 variant,
             * Store only last 3 words from state[4...6]
             */
            UNROLL_16
            for (Uint64 i = 0; i < BUFFERS_16; i++) {
                _mm_mask_storeu_epi32(pp_dst[i] + 1, 0b0111, xmm[i]);
            }
        }
    }
}} // namespace alcp::digest::zen4
