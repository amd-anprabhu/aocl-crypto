/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_avx2.hh"

#include <cstring>
#include <immintrin.h>

namespace alcp::cipher::avx2 {

// Shuffle mask for byte-level 8-bit rotation (AVX2 lacks _mm256_rol_epi32)
static const __m256i cRot8Mask256 =
    _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
                    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

// Shuffle control masks for ChaCha20 diagonal/column round transitions
// Row→Diagonal: rotate rows 1,2,3 by 1,2,3 positions respectively
static constexpr int cShuffleRotate1 = 0x39; // _MM_SHUFFLE(0,3,2,1)
static constexpr int cShuffleRotate2 = 0x4E; // _MM_SHUFFLE(1,0,3,2)
static constexpr int cShuffleRotate3 = 0x93; // _MM_SHUFFLE(2,1,0,3)

inline void
RoundFunction(__m256i& regA, __m256i& regB, __m256i& regC, __m256i& regD)
{
    regA = _mm256_add_epi32(regA, regB);
    // d ^= a;
    regD = _mm256_xor_si256(regD, regA);
    // d <<<= 16;
    regD = _mm256_or_si256(_mm256_slli_epi32(regD, 16),
                           _mm256_srli_epi32(regD, 16));

    // c += d;
    regC = _mm256_add_epi32(regC, regD);
    // b ^= c;
    regB = _mm256_xor_si256(regB, regC);
    // b <<<= 12;
    regB = _mm256_or_si256(_mm256_slli_epi32(regB, 12),
                           _mm256_srli_epi32(regB, 20));

    // a += b;
    regA = _mm256_add_epi32(regA, regB);
    // d ^= a;
    regD = _mm256_xor_si256(regD, regA);
    // d <<<= 8;
    regD = _mm256_shuffle_epi8(regD, cRot8Mask256);

    // c += d;
    regC = _mm256_add_epi32(regC, regD);
    // b ^= c;
    regB = _mm256_xor_si256(regB, regC);
    // b <<<= 7;
    regB = _mm256_or_si256(_mm256_slli_epi32(regB, 7),
                           _mm256_srli_epi32(regB, 25));
}

template<int index>
inline void
XorMessageKeyStreamStore(__m256i         stateRegister,
                         const __m128i*& pPlaintext128,
                         __m128i*&       pCiphertext128)
{
    __m128i reg128State = _mm256_extracti128_si256(stateRegister, index);
    __m128i reg128Msg   = _mm_loadu_si128(pPlaintext128);
    reg128Msg           = _mm_xor_si128(reg128Msg, reg128State);
    _mm_storeu_si128(pCiphertext128, reg128Msg);
    pPlaintext128++;
    pCiphertext128++;
}

inline void
Chacha20Avx2ParallelBlocks2(__m256i  s[4],
                            const __m256i s_prev[4])
{
    for (int i = 0; i < 10; i++) {

        // -- Row Round
        RoundFunction(s[0], s[1], s[2], s[3]);

        // -- Setting up for Column Round
        s[1] = _mm256_shuffle_epi32(s[1], cShuffleRotate1);
        s[2] = _mm256_shuffle_epi32(s[2], cShuffleRotate2);
        s[3] = _mm256_shuffle_epi32(s[3], cShuffleRotate3);

        // Column Round
        RoundFunction(s[0], s[1], s[2], s[3]);

        // Reshuffle back for next Row operation
        s[1] = _mm256_shuffle_epi32(s[1], cShuffleRotate3);
        s[2] = _mm256_shuffle_epi32(s[2], cShuffleRotate2);
        s[3] = _mm256_shuffle_epi32(s[3], cShuffleRotate1);
    }

    for (int i = 0; i < 4; i++) {
        s[i] = _mm256_add_epi32(s[i], s_prev[i]);
    }
}

inline void
ProcessChacha20ParallelBlocks8(Uint64&       blocks,
                               const Uint8   key[],
                               Uint8         iv[],
                               const Uint8*& pInputText,
                               Uint8*&       pOutputText)
{
    const Uint32* pKey32 = reinterpret_cast<const Uint32*>(key);
    Uint32*       pIv    = reinterpret_cast<Uint32*>(iv);

    // Broadcast constants and key into 256-bit registers
    // Each 256-bit register holds 2 copies of the 128-bit value
    __m256i constVec = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(Chacha20Constants)));
    __m256i keyLo = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(pKey32)));
    __m256i keyHi = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(pKey32 + 4)));

    Uint32 counter = pIv[0];

    while (blocks >= 8) {
        // Build IV vectors with consecutive counters for 8 blocks
        // Group A: blocks 0,1   Group B: blocks 2,3
        // Group C: blocks 4,5   Group D: blocks 6,7
        __m256i ivA = _mm256_set_m128i(
            _mm_setr_epi32(counter + 1, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter,     pIv[1], pIv[2], pIv[3]));
        __m256i ivB = _mm256_set_m128i(
            _mm_setr_epi32(counter + 3, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter + 2, pIv[1], pIv[2], pIv[3]));
        __m256i ivC = _mm256_set_m128i(
            _mm_setr_epi32(counter + 5, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter + 4, pIv[1], pIv[2], pIv[3]));
        __m256i ivD = _mm256_set_m128i(
            _mm_setr_epi32(counter + 7, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter + 6, pIv[1], pIv[2], pIv[3]));

        // a=constants, b=keyLo, c=keyHi, d=iv (per group)
        __m256i sA[4]      = { constVec, keyLo, keyHi, ivA };
        __m256i sB[4]      = { constVec, keyLo, keyHi, ivB };
        __m256i sC[4]      = { constVec, keyLo, keyHi, ivC };
        __m256i sD[4]      = { constVec, keyLo, keyHi, ivD };
        const __m256i sA_prev[4] = { sA[0], sA[1], sA[2], sA[3] };
        const __m256i sB_prev[4] = { sB[0], sB[1], sB[2], sB[3] };
        const __m256i sC_prev[4] = { sC[0], sC[1], sC[2], sC[3] };
        const __m256i sD_prev[4] = { sD[0], sD[1], sD[2], sD[3] };

        // 20 rounds (10 double-rounds) for all 4 groups
        for (int i = 0; i < 10; i++) {
            // -- Row Round
            RoundFunction(sA[0], sA[1], sA[2], sA[3]);
            RoundFunction(sB[0], sB[1], sB[2], sB[3]);
            RoundFunction(sC[0], sC[1], sC[2], sC[3]);
            RoundFunction(sD[0], sD[1], sD[2], sD[3]);

            // -- Setting up for Column Round
            for (auto* g : { sA, sB, sC, sD }) {
                g[1] = _mm256_shuffle_epi32(g[1], cShuffleRotate1);
                g[2] = _mm256_shuffle_epi32(g[2], cShuffleRotate2);
                g[3] = _mm256_shuffle_epi32(g[3], cShuffleRotate3);
            }

            // Column Round
            RoundFunction(sA[0], sA[1], sA[2], sA[3]);
            RoundFunction(sB[0], sB[1], sB[2], sB[3]);
            RoundFunction(sC[0], sC[1], sC[2], sC[3]);
            RoundFunction(sD[0], sD[1], sD[2], sD[3]);

            // Reshuffle back for next Row operation
            for (auto* g : { sA, sB, sC, sD }) {
                g[1] = _mm256_shuffle_epi32(g[1], cShuffleRotate3);
                g[2] = _mm256_shuffle_epi32(g[2], cShuffleRotate2);
                g[3] = _mm256_shuffle_epi32(g[3], cShuffleRotate1);
            }
        }

        // Add original state
        for (int i = 0; i < 4; i++) {
            sA[i] = _mm256_add_epi32(sA[i], sA_prev[i]);
            sB[i] = _mm256_add_epi32(sB[i], sB_prev[i]);
            sC[i] = _mm256_add_epi32(sC[i], sC_prev[i]);
            sD[i] = _mm256_add_epi32(sD[i], sD_prev[i]);
        }

        // XOR with plaintext and store
        const __m128i* p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
        __m128i*       p_out_128 = reinterpret_cast<__m128i*>(pOutputText);

        // Each group stores 2 blocks (lo lane=block N, hi lane=block N+1)
        for (auto* g : { sA, sB, sC, sD }) {
            // Block N (lo 128-bit lane)
            for (int i = 0; i < 4; i++) {
                XorMessageKeyStreamStore<0>(g[i], p_in_128, p_out_128);
            }
            // Block N+1 (hi 128-bit lane)
            for (int i = 0; i < 4; i++) {
                XorMessageKeyStreamStore<1>(g[i], p_in_128, p_out_128);
            }
        }

        pInputText += 512;
        pOutputText += 512;
        counter += 8;
        blocks -= 8;
    }
}

inline void
ProcessChacha20ParallelBlocks2(const Uint8   key[],
                               Uint8         iv[],
                               const Uint8*& pInputText,
                               Uint8*&       pOutputText,
                               Uint64        blocks,
                               int           remBytes)
{
    // 2 Block Parallelization using 256-bit registers

    // -- Setup Registers
    // a
    __m256i s_prev[4];
    s_prev[0] = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(Chacha20Constants)));
    // b
    s_prev[1] = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(key)));
    // c
    s_prev[2] = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16)));
    // d
    s_prev[3] = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(iv)));

    __m256i s[4];

    Uint32* pIv     = reinterpret_cast<Uint32*>(iv);
    Uint32  counter = pIv[0];

    const __m128i* p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
    __m128i*       p_out_128 = reinterpret_cast<__m128i*>(pOutputText);

    while (blocks >= 2) {
        // Set counters: lo lane = counter, hi lane = counter+1
        s_prev[3] = _mm256_set_m128i(
            _mm_setr_epi32(counter + 1, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter,     pIv[1], pIv[2], pIv[3]));

        // Restoring registers to initial state
        for (int i = 0; i < 4; i++) {
            s[i] = s_prev[i];
        }

        Chacha20Avx2ParallelBlocks2(s, s_prev);

        // Store: lo lane rows then hi lane rows
        for (int i = 0; i < 4; i++) {
            XorMessageKeyStreamStore<0>(s[i], p_in_128, p_out_128);
        }
        for (int i = 0; i < 4; i++) {
            XorMessageKeyStreamStore<1>(s[i], p_in_128, p_out_128);
        }

        pInputText += 128;
        pOutputText += 128;
        counter += 2;
        blocks -= 2;
    }

    Uint64 totalbytes = blocks * CHACHA20_BLOCK_SIZE + remBytes;
    if (totalbytes > 0) {
        // Generate 2 blocks of keystream (same as main loop)
        // and extract only what we need
        s_prev[3] = _mm256_set_m128i(
            _mm_setr_epi32(counter + 1, pIv[1], pIv[2], pIv[3]),
            _mm_setr_epi32(counter,     pIv[1], pIv[2], pIv[3]));

        for (int i = 0; i < 4; i++) {
            s[i] = s_prev[i];
        }

        Chacha20Avx2ParallelBlocks2(s, s_prev);

        // Serialize 2-block keystream: block 0 (lo lane), block 1 (hi lane)
        alignas(32) Uint8 keystream[2 * CHACHA20_BLOCK_SIZE];
        for (int r = 0; r < 4; r++) {
            _mm_store_si128(
                reinterpret_cast<__m128i*>(keystream + r * 16),
                _mm256_extracti128_si256(s[r], 0));
        }
        for (int r = 0; r < 4; r++) {
            _mm_store_si128(
                reinterpret_cast<__m128i*>(keystream + CHACHA20_BLOCK_SIZE
                                           + r * 16),
                _mm256_extracti128_si256(s[r], 1));
        }

        for (Uint64 n = 0; n < totalbytes; n++) {
            pOutputText[n] = pInputText[n] ^ keystream[n];
        }
    }
}

alc_error_t
ProcessInput(const Uint8  key[],
             Uint8        iv[],
             const Uint8* pInputText,
             Uint8*       pOutputText,
             Uint64       blocks,
             int          remBytes)
{
    // Preserving the initial number of blocks to be processed as it maybe
    // modified in ProcessChacha20ParallelBlocks8
    Uint64 temp_blocks = blocks;
    if (blocks >= 8) {
        ProcessChacha20ParallelBlocks8(
            blocks, key, iv, pInputText, pOutputText);
        (*(reinterpret_cast<Uint32*>(iv))) += (temp_blocks - blocks);
    }
    if ((blocks > 0) || (remBytes > 0)) {
        ProcessChacha20ParallelBlocks2(
            key, iv, pInputText, pOutputText, blocks, remBytes);
    }
    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::avx2
