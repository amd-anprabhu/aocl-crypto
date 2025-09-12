/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"
/* Helper macros for AES operations using AVX512 instructions.
 * These macros define how to apply the AES encryption steps for different
 * numbers of buffers (1, 2, 4, 8, 16) using the AVX512 intrinsics.
 */

/* First round key addition */
#define VAES512_AESENCFIRST_APPLY(key, var) var = _mm512_xor_si512(var, key);

#define VAES512_AESENCFIRST_1(key, v1) VAES512_AESENCFIRST_APPLY(key, v1)

#define VAES512_AESENCFIRST_2(key, v1, v2)                                     \
    VAES512_AESENCFIRST_APPLY(key, v1);                                        \
    VAES512_AESENCFIRST_APPLY(key, v2)

#define VAES512_AESENCFIRST_4(key, v1, v2, v3, v4)                             \
    VAES512_AESENCFIRST_2(key, v1, v2);                                        \
    VAES512_AESENCFIRST_2(key, v3, v4)

#define VAES512_AESENCFIRST_8(key, v1, v2, v3, v4, v5, v6, v7, v8)             \
    VAES512_AESENCFIRST_4(key, v1, v2, v3, v4);                                \
    VAES512_AESENCFIRST_4(key, v5, v6, v7, v8)

#define VAES512_AESENCFIRST_16(key,                                            \
                               v1,                                             \
                               v2,                                             \
                               v3,                                             \
                               v4,                                             \
                               v5,                                             \
                               v6,                                             \
                               v7,                                             \
                               v8,                                             \
                               v9,                                             \
                               v10,                                            \
                               v11,                                            \
                               v12,                                            \
                               v13,                                            \
                               v14,                                            \
                               v15,                                            \
                               v16)                                            \
    VAES512_AESENCFIRST_8(key, v1, v2, v3, v4, v5, v6, v7, v8);                \
    VAES512_AESENCFIRST_8(key, v9, v10, v11, v12, v13, v14, v15, v16)

/* AES encryption rounds */
#define VAES512_AESENC_APPLY(key, var) var = _mm512_aesenc_epi128(var, key)

#define VAES512_AESENC_1(key, v1) VAES512_AESENC_APPLY(key, v1)

#define VAES512_AESENC_2(key, v1, v2)                                          \
    VAES512_AESENC_APPLY(key, v1);                                             \
    VAES512_AESENC_APPLY(key, v2)

#define VAES512_AESENC_4(key, v1, v2, v3, v4)                                  \
    VAES512_AESENC_2(key, v1, v2);                                             \
    VAES512_AESENC_2(key, v3, v4)

#define VAES512_AESENC_8(key, v1, v2, v3, v4, v5, v6, v7, v8)                  \
    VAES512_AESENC_4(key, v1, v2, v3, v4);                                     \
    VAES512_AESENC_4(key, v5, v6, v7, v8)

#define VAES512_AESENC_16(key,                                                 \
                          v1,                                                  \
                          v2,                                                  \
                          v3,                                                  \
                          v4,                                                  \
                          v5,                                                  \
                          v6,                                                  \
                          v7,                                                  \
                          v8,                                                  \
                          v9,                                                  \
                          v10,                                                 \
                          v11,                                                 \
                          v12,                                                 \
                          v13,                                                 \
                          v14,                                                 \
                          v15,                                                 \
                          v16)                                                 \
    VAES512_AESENC_8(key, v1, v2, v3, v4, v5, v6, v7, v8);                     \
    VAES512_AESENC_8(key, v9, v10, v11, v12, v13, v14, v15, v16)

/* AES last round */
#define VAES512_AESENCLAST_APPLY(key, var)                                     \
    var = _mm512_aesenclast_epi128(var, key)

#define VAES512_AESENCLAST_1(key, v1) VAES512_AESENCLAST_APPLY(key, v1)

#define VAES512_AESENCLAST_2(key, v1, v2)                                      \
    VAES512_AESENCLAST_APPLY(key, v1);                                         \
    VAES512_AESENCLAST_APPLY(key, v2)

#define VAES512_AESENCLAST_4(key, v1, v2, v3, v4)                              \
    VAES512_AESENCLAST_2(key, v1, v2);                                         \
    VAES512_AESENCLAST_2(key, v3, v4)

#define VAES512_AESENCLAST_8(key, v1, v2, v3, v4, v5, v6, v7, v8)              \
    VAES512_AESENCLAST_4(key, v1, v2, v3, v4);                                 \
    VAES512_AESENCLAST_4(key, v5, v6, v7, v8)

#define VAES512_AESENCLAST_16(key,                                             \
                              v1,                                              \
                              v2,                                              \
                              v3,                                              \
                              v4,                                              \
                              v5,                                              \
                              v6,                                              \
                              v7,                                              \
                              v8,                                              \
                              v9,                                              \
                              v10,                                             \
                              v11,                                             \
                              v12,                                             \
                              v13,                                             \
                              v14,                                             \
                              v15,                                             \
                              v16)                                             \
    VAES512_AESENCLAST_8(key, v1, v2, v3, v4, v5, v6, v7, v8);                 \
    VAES512_AESENCLAST_8(key, v9, v10, v11, v12, v13, v14, v15, v16)

/* ------------------------- For all buffer sizes-------------------------------*/
/* AES encryption  for 128 key size */
#define VAES512_AESENCRYPT_10(keys, buffer, ...)                               \
    VAES512_AESENCFIRST_##buffer(keys.key_512_0, __VA_ARGS__);                 \
    VAES512_AESENC_##buffer(keys.key_512_1, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_2, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_3, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_4, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_5, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_6, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_7, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_8, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_9, __VA_ARGS__);                      \
    VAES512_AESENCLAST_##buffer(keys.key_512_10, __VA_ARGS__)

/* AES encryption for 196 key size */
#define VAES512_AESENCRYPT_12(keys, buffer, ...)                               \
    VAES512_AESENCFIRST_##buffer(keys.key_512_0, __VA_ARGS__);                 \
    VAES512_AESENC_##buffer(keys.key_512_1, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_2, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_3, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_4, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_5, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_6, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_7, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_8, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_9, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_10, __VA_ARGS__);                     \
    VAES512_AESENC_##buffer(keys.key_512_11, __VA_ARGS__);                     \
    VAES512_AESENCLAST_##buffer(keys.key_512_12, __VA_ARGS__)

/* AES encryption for 256 key size */
#define VAES512_AESENCRYPT_14(keys, buffer, ...)                               \
    VAES512_AESENCFIRST_##buffer(keys.key_512_0, __VA_ARGS__);                 \
    VAES512_AESENC_##buffer(keys.key_512_1, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_2, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_3, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_4, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_5, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_6, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_7, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_8, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_9, __VA_ARGS__);                      \
    VAES512_AESENC_##buffer(keys.key_512_10, __VA_ARGS__);                     \
    VAES512_AESENC_##buffer(keys.key_512_11, __VA_ARGS__);                     \
    VAES512_AESENC_##buffer(keys.key_512_12, __VA_ARGS__);                     \
    VAES512_AESENC_##buffer(keys.key_512_13, __VA_ARGS__);                     \
    VAES512_AESENCLAST_##buffer(keys.key_512_14, __VA_ARGS__)
/* ------------------------- For all buffer sizes-------------------------------*/

/*----------------PACK_LANES_TO_ZMM----MACROS FOR BUFFER SIZES----------------*/
#define VAES512_PACK_LANES_TO_ZMM_1(p_in_block, iv_block)                      \
    __m512i zmm0 = pack_lanes_to_zmm(p_in_block, iv_block)
#define VAES512_PACK_LANES_TO_ZMM_2(p_in_block, iv_block)                      \
    __m512i zmm0 = pack_lanes_to_zmm(p_in_block, iv_block),                    \
            zmm1 = pack_lanes_to_zmm(&(p_in_block)[4], &(iv_block)[4])
#define VAES512_PACK_LANES_TO_ZMM_4(p_in_block, iv_block)                      \
    __m512i zmm0 = pack_lanes_to_zmm(p_in_block, iv_block),                    \
            zmm1 = pack_lanes_to_zmm(&(p_in_block)[4], &(iv_block)[4]),        \
            zmm2 = pack_lanes_to_zmm(&(p_in_block)[8], &(iv_block)[8]),        \
            zmm3 = pack_lanes_to_zmm(&(p_in_block)[12], &(iv_block)[12])
#define VAES512_PACK_LANES_TO_ZMM_8(p_in_block, iv_block)                      \
    __m512i zmm0 = pack_lanes_to_zmm(p_in_block, iv_block),                    \
            zmm1 = pack_lanes_to_zmm(&(p_in_block)[4], &(iv_block)[4]),        \
            zmm2 = pack_lanes_to_zmm(&(p_in_block)[8], &(iv_block)[8]),        \
            zmm3 = pack_lanes_to_zmm(&(p_in_block)[12], &(iv_block)[12]),      \
            zmm4 = pack_lanes_to_zmm(&(p_in_block)[16], &(iv_block)[16]),      \
            zmm5 = pack_lanes_to_zmm(&(p_in_block)[20], &(iv_block)[20]),      \
            zmm6 = pack_lanes_to_zmm(&(p_in_block)[24], &(iv_block)[24]),      \
            zmm7 = pack_lanes_to_zmm(&(p_in_block)[28], &(iv_block)[28])
#define VAES512_PACK_LANES_TO_ZMM_16(p_in_block, iv_block)                     \
    __m512i zmm0  = pack_lanes_to_zmm(p_in_block, iv_block),                   \
            zmm1  = pack_lanes_to_zmm(&(p_in_block)[4], &(iv_block)[4]),       \
            zmm2  = pack_lanes_to_zmm(&(p_in_block)[8], &(iv_block)[8]),       \
            zmm3  = pack_lanes_to_zmm(&(p_in_block)[12], &(iv_block)[12]),     \
            zmm4  = pack_lanes_to_zmm(&(p_in_block)[16], &(iv_block)[16]),     \
            zmm5  = pack_lanes_to_zmm(&(p_in_block)[20], &(iv_block)[20]),     \
            zmm6  = pack_lanes_to_zmm(&(p_in_block)[24], &(iv_block)[24]),     \
            zmm7  = pack_lanes_to_zmm(&(p_in_block)[28], &(iv_block)[28]),     \
            zmm8  = pack_lanes_to_zmm(&(p_in_block)[32], &(iv_block)[32]),     \
            zmm9  = pack_lanes_to_zmm(&(p_in_block)[36], &(iv_block)[36]),     \
            zmm10 = pack_lanes_to_zmm(&(p_in_block)[40], &(iv_block)[40]),     \
            zmm11 = pack_lanes_to_zmm(&(p_in_block)[44], &(iv_block)[44]),     \
            zmm12 = pack_lanes_to_zmm(&(p_in_block)[48], &(iv_block)[48]),     \
            zmm13 = pack_lanes_to_zmm(&(p_in_block)[52], &(iv_block)[52]),     \
            zmm14 = pack_lanes_to_zmm(&(p_in_block)[56], &(iv_block)[56]),     \
            zmm15 = pack_lanes_to_zmm(&(p_in_block)[60], &(iv_block)[60])
/*----------------PACK_LANES_TO_ZMM----MACROS FOR BUFFER SIZES----------------*/

/*----------------UNPACK_ZMM_TO_LANES_AND_UPDATE----MACROS FOR BUFFER SIZES----------------*/
#define VAES512_UNPACK_TO_LANES_AND_UPDATE_1(p_out_block, p_in_block, iv_block) \
    unpack_zmm_to_lanes_and_update(zmm0, p_out_block, iv_block, p_in_block);

#define VAES512_UNPACK_TO_LANES_AND_UPDATE_2(p_out_block, p_in_block, iv_block) \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm0, p_out_block, iv_block, p_in_block);                              \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm1, &(p_out_block)[4], &(iv_block)[4], &(p_in_block)[4]);
#define VAES512_UNPACK_TO_LANES_AND_UPDATE_4(p_out_block, p_in_block, iv_block) \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm0, p_out_block, iv_block, p_in_block);                              \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm1, &(p_out_block)[4], &(iv_block)[4], &(p_in_block)[4]);            \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm2, &(p_out_block)[8], &(iv_block)[8], &(p_in_block)[8]);            \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm3, &(p_out_block)[12], &(iv_block)[12], &(p_in_block)[12]);

#define VAES512_UNPACK_TO_LANES_AND_UPDATE_8(p_out_block, p_in_block, iv_block) \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm0, p_out_block, iv_block, p_in_block);                              \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm1, &(p_out_block)[4], &(iv_block)[4], &(p_in_block)[4]);            \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm2, &(p_out_block)[8], &(iv_block)[8], &(p_in_block)[8]);            \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm3, &(p_out_block)[12], &(iv_block)[12], &(p_in_block)[12]);         \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm4, &(p_out_block)[16], &(iv_block)[16], &(p_in_block)[16]);         \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm5, &(p_out_block)[20], &(iv_block)[20], &(p_in_block)[20]);         \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm6, &(p_out_block)[24], &(iv_block)[24], &(p_in_block)[24]);         \
    unpack_zmm_to_lanes_and_update(                                            \
        zmm7, &(p_out_block)[28], &(iv_block)[28], &(p_in_block)[28]);

#define VAES512_UNPACK_TO_LANES_AND_UPDATE_16(p_out_block, p_in_block, iv_block) \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm0, p_out_block, iv_block, p_in_block);                               \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm1, &(p_out_block)[4], &(iv_block)[4], &(p_in_block)[4]);             \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm2, &(p_out_block)[8], &(iv_block)[8], &(p_in_block)[8]);             \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm3, &(p_out_block)[12], &(iv_block)[12], &(p_in_block)[12]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm4, &(p_out_block)[16], &(iv_block)[16], &(p_in_block)[16]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm5, &(p_out_block)[20], &(iv_block)[20], &(p_in_block)[20]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm6, &(p_out_block)[24], &(iv_block)[24], &(p_in_block)[24]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm7, &(p_out_block)[28], &(iv_block)[28], &(p_in_block)[28]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm8, &(p_out_block)[32], &(iv_block)[32], &(p_in_block)[32]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm9, &(p_out_block)[36], &(iv_block)[36], &(p_in_block)[36]);          \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm10, &(p_out_block)[40], &(iv_block)[40], &(p_in_block)[40]);         \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm11, &(p_out_block)[44], &(iv_block)[44], &(p_in_block)[44]);         \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm12, &(p_out_block)[48], &(iv_block)[48], &(p_in_block)[48]);         \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm13, &(p_out_block)[52], &(iv_block)[52], &(p_in_block)[52]);         \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm14, &(p_out_block)[56], &(iv_block)[56], &(p_in_block)[56]);         \
    unpack_zmm_to_lanes_and_update(                                             \
        zmm15, &(p_out_block)[60], &(iv_block)[60], &(p_in_block)[60]);
/*----------------UNPACK_ZMM_TO_LANES_AND_UPDATE----MACROS FOR BUFFER SIZES----------------*/

#define VAES512_ENCRYPT_BLOCK_LOOP_1(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, keys);           \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_1_1(num_zmm, rounds)                     \
        { \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, keys);           \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_2(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, keys);     \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_2_1(num_zmm, rounds)                     \
    { \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, keys);     \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_4(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, zmm2, zmm3, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_4_1(num_zmm, rounds)                     \
    { \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, zmm2, zmm3, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_8(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, keys);            \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_ENCRYPT_BLOCK_LOOP_8_1(num_zmm, rounds)                     \
    { \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, keys);            \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }
#define VAES512_ENCRYPT_BLOCK_LOOP_16(num_zmm, rounds)                        \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(p_in_128, current_ivs);           \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0,zmm1,zmm2,zmm3,zmm4,zmm5,zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(                         \
            &p_out_128[0], &p_in_128[0], &current_ivs[0]);                    \
    }
#define VAES512_ENCRYPT_BLOCK_LOOP_16_1(num_zmm, rounds)                     \
    { \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(p_in_128, current_ivs);           \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0,zmm1,zmm2,zmm3,zmm4,zmm5,zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(                         \
            &p_out_128[0], &p_in_128[0], &current_ivs[0]);                    \
    }
#define VAES512_ENCRYPT_SWITCH_ROUNDS(macro_name, num_zmm)                \
    switch (nRounds) {                                                        \
        case 10:                                                              \
            macro_name(num_zmm, 10);                                          \
            break;                                                            \
        case 12:                                                              \
            macro_name(num_zmm, 12);                                          \
            break;                                                            \
        case 14:                                                              \
            macro_name(num_zmm, 14);                                          \
            break;                                                            \
    }
namespace alcp::cipher { namespace vaes512 {

    struct sKeys10Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
    };

    struct sKeys12Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
        __m512i key_512_11;
        __m512i key_512_12;
    };

    struct sKeys14Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
        __m512i key_512_11;
        __m512i key_512_12;
        __m512i key_512_13;
        __m512i key_512_14;
    };

    struct sKeys
    {
        union
        {
            sKeys10Rounds keys10;
            sKeys12Rounds keys12;
            sKeys14Rounds keys14;
        } data;
        int numRounds;
    };

    static inline void alcp_load_key_zmm_10rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys10.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys10.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys10.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys10.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys10.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys10.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys10.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys10.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys10.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys10.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys10.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
    }

    static inline void alcp_load_key_zmm_12rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys12.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys12.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys12.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys12.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys12.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys12.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys12.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys12.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys12.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys12.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys12.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        keys.data.keys12.key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        keys.data.keys12.key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
    }

    static inline void alcp_load_key_zmm_14rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys14.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys14.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys14.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys14.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys14.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys14.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys14.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys14.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys14.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys14.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys14.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        keys.data.keys14.key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        keys.data.keys14.key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
        keys.data.keys14.key_512_13 = _mm512_broadcast_i64x2(*(pkey128 + 13));
        keys.data.keys14.key_512_14 = _mm512_broadcast_i64x2(*(pkey128 + 14));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10,
                                         __m512i&      key_512_11,
                                         __m512i&      key_512_12)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10,
                                         __m512i&      key_512_11,
                                         __m512i&      key_512_12,
                                         __m512i&      key_512_13,
                                         __m512i&      key_512_14)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
        key_512_13 = _mm512_broadcast_i64x2(*(pkey128 + 13));
        key_512_14 = _mm512_broadcast_i64x2(*(pkey128 + 14));
    }

    static inline void alcp_clear_keys_zmm_10rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
    }

    static inline void alcp_clear_keys_zmm_12rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
        keys.data.keys14.key_512_11 = _mm512_setzero_si512();
        keys.data.keys14.key_512_12 = _mm512_setzero_si512();
    }

    static inline void alcp_clear_keys_zmm_14rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
        keys.data.keys14.key_512_11 = _mm512_setzero_si512();
        keys.data.keys14.key_512_12 = _mm512_setzero_si512();
        keys.data.keys14.key_512_13 = _mm512_setzero_si512();
        keys.data.keys14.key_512_14 = _mm512_setzero_si512();
    }

    /* 16 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_16x512Rounds10(__m512i&     a,
                                                       __m512i&     b,
                                                       __m512i&     c,
                                                       __m512i&     d,
                                                       __m512i&     e,
                                                       __m512i&     f,
                                                       __m512i&     g,
                                                       __m512i&     h,
                                                       __m512i&     i,
                                                       __m512i&     j,
                                                       __m512i&     k,
                                                       __m512i&     l,
                                                       __m512i&     m,
                                                       __m512i&     n,
                                                       __m512i&     o,
                                                       __m512i&     p,
                                                       const sKeys& keys)
    {
        // clang-format off
        VAES512_AESENCRYPT_10(keys.data.keys10, 16,
                              a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
        // clang-format on
    }

    static inline void AesEncryptNoLoad_16x512Rounds12(__m512i&     a,
                                                       __m512i&     b,
                                                       __m512i&     c,
                                                       __m512i&     d,
                                                       __m512i&     e,
                                                       __m512i&     f,
                                                       __m512i&     g,
                                                       __m512i&     h,
                                                       __m512i&     i,
                                                       __m512i&     j,
                                                       __m512i&     k,
                                                       __m512i&     l,
                                                       __m512i&     m,
                                                       __m512i&     n,
                                                       __m512i&     o,
                                                       __m512i&     p,
                                                       const sKeys& keys)
    {
        // clang-format off
        VAES512_AESENCRYPT_12(keys.data.keys12, 16,
                              a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
        // clang-format on
    }

    static inline void AesEncryptNoLoad_16x512Rounds14(__m512i&     a,
                                                       __m512i&     b,
                                                       __m512i&     c,
                                                       __m512i&     d,
                                                       __m512i&     e,
                                                       __m512i&     f,
                                                       __m512i&     g,
                                                       __m512i&     h,
                                                       __m512i&     i,
                                                       __m512i&     j,
                                                       __m512i&     k,
                                                       __m512i&     l,
                                                       __m512i&     m,
                                                       __m512i&     n,
                                                       __m512i&     o,
                                                       __m512i&     p,
                                                       const sKeys& keys)
    {
        // clang-format off
        VAES512_AESENCRYPT_14(keys.data.keys14, 16,
                              a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
        // clang-format on
    }

    /* 8 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_8x512Rounds10(__m512i&     a,
                                                      __m512i&     b,
                                                      __m512i&     c,
                                                      __m512i&     d,
                                                      __m512i&     e,
                                                      __m512i&     f,
                                                      __m512i&     g,
                                                      __m512i&     h,
                                                      const sKeys& keys)

    {
        VAES512_AESENCRYPT_10(keys.data.keys10, 8, a, b, c, d, e, f, g, h);
    }

    static inline void AesEncryptNoLoad_8x512Rounds12(__m512i&     a,
                                                      __m512i&     b,
                                                      __m512i&     c,
                                                      __m512i&     d,
                                                      __m512i&     e,
                                                      __m512i&     f,
                                                      __m512i&     g,
                                                      __m512i&     h,
                                                      const sKeys& keys)

    {
        VAES512_AESENCRYPT_12(keys.data.keys12, 8, a, b, c, d, e, f, g, h);
    }

    static inline void AesEncryptNoLoad_8x512Rounds14(__m512i&     a,
                                                      __m512i&     b,
                                                      __m512i&     c,
                                                      __m512i&     d,
                                                      __m512i&     e,
                                                      __m512i&     f,
                                                      __m512i&     g,
                                                      __m512i&     h,
                                                      const sKeys& keys)

    {
        VAES512_AESENCRYPT_14(keys.data.keys14, 8, a, b, c, d, e, f, g, h);
    }

    /* 4 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_4x512Rounds10(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        VAES512_AESENCRYPT_10(keys.data.keys10, 4, a, b, c, d);
    }
    static inline void AesEncryptNoLoad_4x512Rounds12(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        VAES512_AESENCRYPT_12(keys.data.keys12, 4, a, b, c, d);
    }

    static inline void AesEncryptNoLoad_4x512Rounds14(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        VAES512_AESENCRYPT_14(keys.data.keys14, 4, a, b, c, d);
    }

    /* 2 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_2x512Rounds10(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)

    {
        VAES512_AESENCRYPT_10(keys.data.keys10, 2, a, b);
    }

    static inline void AesEncryptNoLoad_2x512Rounds12(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        VAES512_AESENCRYPT_12(keys.data.keys12, 2, a, b);
    }

    static inline void AesEncryptNoLoad_2x512Rounds14(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        VAES512_AESENCRYPT_14(keys.data.keys14, 2, a, b);
    }

    /* 1 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_1x512Rounds10(__m512i&     a,
                                                      const sKeys& keys)
    {
        VAES512_AESENCRYPT_10(keys.data.keys10, 1, a);
    }

    static inline void AesEncryptNoLoad_1x512Rounds12(__m512i&     a,
                                                      const sKeys& keys)
    {
        VAES512_AESENCRYPT_12(keys.data.keys12, 1, a);
    }

    static inline void AesEncryptNoLoad_1x512Rounds14(__m512i&     a,
                                                      const sKeys& keys)
    {
        VAES512_AESENCRYPT_14(keys.data.keys14, 1, a);
    }

    /*
     * AesDecrypt
     */
    static inline void AesDecryptNoLoad_4x512Rounds10(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);

        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_9);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys10.key_512_10);

        c = _mm512_xor_si512(c, keys.data.keys10.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_9);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys10.key_512_10);

        d = _mm512_xor_si512(d, keys.data.keys10.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_9);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_4x512Rounds12(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys12.key_512_12);

        c = _mm512_xor_si512(c, keys.data.keys12.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_9);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_10);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_11);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys12.key_512_12);

        d = _mm512_xor_si512(d, keys.data.keys12.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_9);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_10);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_11);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_4x512Rounds14(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys14.key_512_14);

        c = _mm512_xor_si512(c, keys.data.keys14.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_9);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_10);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_11);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_12);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_13);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys14.key_512_14);

        d = _mm512_xor_si512(d, keys.data.keys14.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_9);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_10);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_11);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_12);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_13);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys14.key_512_14);
    }

    /* 2 x 512bit aesDec */
    static inline void AesDecryptNoLoad_2x512Rounds10(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);

        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_9);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_2x512Rounds12(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_2x512Rounds14(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys14.key_512_14);
    }

    /* 1 x 512bit aesDec */
    static inline void AesDecryptNoLoad_1x512Rounds10(__m512i&     a,
                                                      const sKeys& keys)
    {

        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_1x512Rounds12(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_1x512Rounds14(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);
    }

}} // namespace alcp::cipher::vaes512
