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
#include "avx512.hh"

#include "../zen3/vaes.hh"
#include "../zen3/vaes_cbc.hh"
#include "../zen3/vaes_avx256_core.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

using namespace alcp;
using namespace alcp::base;
using namespace alcp::cipher;

// CBC mode encryption: Ciphertext = Plaintext ⊕ Encrypt(IV)
// IV Update: Next_IV = Ciphertext
namespace alcp::cipher::vaes512 {

/* @brief   Helper function to pack 4 lanes of __m128i data into a single
 *          __m512i register with XOR operation against the IVs.
 *
 * @param   p_in_block  Pointer to an array of 4 pointers to __m128i data
 *          blocks.
 * @param   iv_block    Pointer to an array of 4 __m128i IVs.
 * @return  A __m512i register containing the packed data.
 */

static inline __m512i
pack_lanes_to_zmm(const __m128i** p_in_block, const __m128i* iv_block)
{
    __m128i data0 = _mm_xor_si128(_mm_loadu_si128(p_in_block[0]), iv_block[0]);
    __m128i data1 = _mm_xor_si128(_mm_loadu_si128(p_in_block[1]), iv_block[1]);
    __m128i data2 = _mm_xor_si128(_mm_loadu_si128(p_in_block[2]), iv_block[2]);
    __m128i data3 = _mm_xor_si128(_mm_loadu_si128(p_in_block[3]), iv_block[3]);

    __m512i zmm_val = _mm512_castsi128_si512(data0);
    zmm_val         = _mm512_inserti32x4(zmm_val, data1, 1);
    zmm_val         = _mm512_inserti32x4(zmm_val, data2, 2);
    zmm_val         = _mm512_inserti32x4(zmm_val, data3, 3);
    return zmm_val;
}
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

/* @brief   Unpacks a __m512i register into 4 lanes of __m128i data and updates
 *          the output pointers and IVs.
 *
 * @param   zmm_val     The __m512i register containing the packed data.
 * @param   p_out_block Pointer to an array of 4 pointers to __m128i output
 *          blocks.
 * @param   iv_block    Pointer to an array of 4 __m128i IVs.
 * @param   p_in_block  Pointer to an array of 4 const __m128i input blocks.
 */

static inline void
unpack_zmm_to_lanes_and_update(const __m512i&  zmm_val,
                               __m128i**       p_out_block,
                               __m128i*        iv_block,
                               const __m128i** p_in_block)
{
    const __m128i ctext_lane0 = _mm512_extracti32x4_epi32(zmm_val, 0);
    const __m128i ctext_lane1 = _mm512_extracti32x4_epi32(zmm_val, 1);
    const __m128i ctext_lane2 = _mm512_extracti32x4_epi32(zmm_val, 2);
    const __m128i ctext_lane3 = _mm512_extracti32x4_epi32(zmm_val, 3);

    _mm_storeu_si128(p_out_block[0], ctext_lane0);
    _mm_storeu_si128(p_out_block[1], ctext_lane1);
    _mm_storeu_si128(p_out_block[2], ctext_lane2);
    _mm_storeu_si128(p_out_block[3], ctext_lane3);

    _mm_storeu_si128(&iv_block[0], ctext_lane0);
    _mm_storeu_si128(&iv_block[1], ctext_lane1);
    _mm_storeu_si128(&iv_block[2], ctext_lane2);
    _mm_storeu_si128(&iv_block[3], ctext_lane3);

    (p_in_block[0])++;
    (p_in_block[1])++;
    (p_in_block[2])++;
    (p_in_block[3])++;

    (p_out_block[0])++;
    (p_out_block[1])++;
    (p_out_block[2])++;
    (p_out_block[3])++;
}

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

#define VAES512_CBC_ENCRYPT_BLOCK_LOOP_1(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, keys);           \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_CBC_ENCRYPT_BLOCK_LOOP_2(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, keys);     \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_CBC_ENCRYPT_BLOCK_LOOP_4(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(zmm0, zmm1, zmm2, zmm3, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_CBC_ENCRYPT_BLOCK_LOOP_8(num_zmm, rounds)                     \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(&p_in_128[0], &current_ivs[0]);   \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, keys);            \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(&p_out_128[0], &p_in_128[0], &current_ivs[0]); \
    }

#define VAES512_CBC_ENCRYPT_BLOCK_LOOP_16(num_zmm, rounds)                        \
    for (Uint64 i = 0; i < blocks; i++) {                                     \
        VAES512_PACK_LANES_TO_ZMM_##num_zmm(p_in_128, current_ivs);           \
        AesEncryptNoLoad_##num_zmm##x512Rounds##rounds(                       \
            zmm0,zmm1,zmm2,zmm3,zmm4,zmm5,zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15, keys); \
        VAES512_UNPACK_TO_LANES_AND_UPDATE_##num_zmm(                         \
            &p_out_128[0], &p_in_128[0], &current_ivs[0]);                    \
    }

#define VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(macro_name, num_zmm)                \
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

/* @brief Encrypts data in CBC mode using AES with AVX512 instructions.                     
 *                                                                                          
 * @param   pPlainText   Pointer to an array of pointers to plaintext                       
 * buffers.                                                                                 
 * @param   pCipherText  Pointer to an array of pointers to ciphertext                      
 * buffers.                                                                                 
 * @param   len          Length of the plaintext in bytes.                                  
 * @param   pKey         Pointer to the encryption key.                                     
 * @param   nRounds      Number of rounds for AES (10, 12, or 14).                          
 * @param   num_buffers  Number of buffers to process (1, 2, 4, 8, 16,                      
 * 32, or 64).                                                                              
 * @param   pIv          Pointer to an array of pointers to IV buffers.                     
 * @return  ALC_ERROR_NONE on success, or an error code on failure.                         
 * Note: The function assumes that the input buffers are properly                           
 * aligned and sized. It also assumes that the input plaintext length is                    
 * a multiple of the block size (16 bytes). The function will process                       
 * multiple buffers in parallel using AVX512 instructions.                                  
 */
alc_error_t
EncryptCbc(const Uint8** pPlainText,
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
    auto p_in_128_storage       = std::make_unique<const __m128i*[]>(num_buffers);
    auto p_out_128_storage      = std::make_unique<__m128i*[]>(num_buffers);
    auto current_ivs_storage    = std::make_unique<__m128i[]>(num_buffers);
    const __m128i** p_in_128    = p_in_128_storage.get();
    __m128i**       p_out_128   = p_out_128_storage.get();
    __m128i*        current_ivs = current_ivs_storage.get();
    auto            pkey128     = reinterpret_cast<const __m128i*>(pKey);
    alignas(64) sKeys       keys;
    alignas(64) vaes::sKeys keys_ymm;

    for (int i = 0; i < num_buffers; i++) {
        p_in_128[i]  = reinterpret_cast<const __m128i*>(pPlainText[i]);
        p_out_128[i] = reinterpret_cast<__m128i*>(pCipherText[i]);
        //clang-format off
        current_ivs[i] =_mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv[i]));
        // clang-format on
    }

    // Load the AES key into the keys structure based on the number of
    // rounds Note : could be done outside this function.
    if (num_buffers == 2) {
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
    } else {
        switch (nRounds) {
            case 10:
                alcp_load_key_zmm_10rounds(pkey128, keys);
                break;
            case 12:
                alcp_load_key_zmm_12rounds(pkey128, keys);
                break;
            case 14:
                alcp_load_key_zmm_14rounds(pkey128, keys);
                break;
        }
    }
    switch(num_buffers) {
        case 2:
            vaes::EncryptCbc(blocks, p_in_128, current_ivs, nRounds, keys_ymm, p_out_128);
            break;
        case 4:
            VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(VAES512_CBC_ENCRYPT_BLOCK_LOOP_1, 1);
            break;
        case 8:
            VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(VAES512_CBC_ENCRYPT_BLOCK_LOOP_2, 2);
            break;
        case 16:
            VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(VAES512_CBC_ENCRYPT_BLOCK_LOOP_4, 4);
            break;
        case 32:
            VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(VAES512_CBC_ENCRYPT_BLOCK_LOOP_8, 8);
            break;
        case 64:
            VAES512_CBC_ENCRYPT_SWITCH_ROUNDS(VAES512_CBC_ENCRYPT_BLOCK_LOOP_16, 16);
            break;
    }

    // Update final IVs in the caller's pIv array if AES_MULTI_UPDATE is
    // defined
#ifdef AES_MULTI_UPDATE
            for (int i = 0; i < num_buffers; i++) {
                // Store the last ciphertext block (now in current_ivs[i]) back
                // to pIv[i]
                _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv[i]),
                                 current_ivs[i]);
            }
#endif
    return err;
}

}