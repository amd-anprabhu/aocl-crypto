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

#include "alcp/cipher/cipher_common.hh"
#include "alcp/error.h"

#include <cstdint>
#include <immintrin.h>
#include <vector>

#ifdef GCM_ALWAYS_COMPUTE
// 1: always compute, 0: compute, store and load from table
#define ALWAYS_COMPUTE 1
#else
#define ALWAYS_COMPUTE 0
#endif

/*
- Always compute without storage works well for real-world application where
init is called for every update call.
- OpenSSL speed uses single init and multiple update calls.
   - In such cases, it is better to store the precomputed table and load from
the table.
- By choosing always compute without storing, we are favoring real-world
application instead of OpenSSL speed or internal MicroBenchmark
*/

namespace alcp::cipher {

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note
 */

#define ALCP_GCM_TAG_MAX_SIZE 16
#define MAX_NUM_512_BLKS      8

typedef struct _alc_cipher_gcm_key_data
{
    __attribute__((aligned(64))) Uint64 m_hashSubkeyTable[MAX_NUM_512_BLKS * 8];

} _alc_cipher_gcm_key_data_t;

typedef struct _alc_gcm_ctx
{
    // gcm specific params
    Int32  m_num_512blks_precomputed;
    Int32  m_num_256blks_precomputed;
    Uint64 m_update_counter = 0;

    // GCM-specific state
    Uint64 m_dataLen   = 0;    // Total bytes processed (for tag calculation)
    bool   m_isEncrypt = true; // Direction: true=encrypt, false=decrypt

    // AAD buffering for multiple setAad calls
    std::vector<Uint8> m_aad_buffer;    // Vector for accumulated AAD data
    bool               m_aad_processed; // Track if AAD has been processed

    __m128i m_hash_subKey_128;
    __m128i m_gHash_128;
    __m128i m_counter_128;
    __m128i m_reverse_mask_128;
    __m128i m_tag_128;
    Uint64  m_additionalDataLen;
    Uint64  m_tagLength = 16; // Default tag length (16 bytes)
#if !ALWAYS_COMPUTE
    _alc_cipher_gcm_key_data_t m_gcm_key_data{};
    Uint64*                    m_pHashSubkeyTable_precomputed = nullptr;
#endif
} alc_gcm_ctx_t;

/**
 * @brief GCM cipher template class implementing iCipherAead interface
 *
 * Uses composition for state, key (with Rijndael), IV, and partial buffer management.
 * KeyManager inherits from Rijndael and handles key expansion internally.
 *
 * @tparam keyLenBits Key length (128, 192, or 256 bits)
 * @tparam arch CPU architecture features (eAesni, eVaes256, eVaes512)
 */
template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class GcmT
    : public virtual iCipherAead
{
  private:
    // Composed components
    StateManager  m_stateManager;
    KeyManager    m_keyManager;
    IvManager     m_ivManager;
    PartialBuffer m_partialBuffer;

  protected:
    alc_gcm_ctx_t m_gcm_ctx;

  public:
    GcmT()
        : m_keyManager(static_cast<Uint32>(keyLenBits) / 8)
        , m_ivManager(1, MAX_CIPHER_IV_SIZE) // GCM supports variable IV (default 12 bytes)
    {
        initGcmContext();
    }

    GcmT(alc_cipher_state_t* pCipherState)
        : m_keyManager(static_cast<Uint32>(keyLenBits) / 8)
        , m_ivManager(1, MAX_CIPHER_IV_SIZE)
    {
        initGcmContext();
        setTable(pCipherState);
    }

    ~GcmT()
    {
#if !ALWAYS_COMPUTE
        // clear precomputed hashtable
        if (m_gcm_ctx.m_pHashSubkeyTable_precomputed != nullptr) {
            memset(m_gcm_ctx.m_pHashSubkeyTable_precomputed,
                   0,
                   sizeof(Uint64) * MAX_NUM_512_BLKS * 8);
        }
#endif
        // AAD buffer cleanup is automatic with std::vector
    }

    // ===== iCipherAead interface implementation =====

    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override;

    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        Uint64*      outlen) override;

    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        Uint64*      outlen) override;

    alc_error_t setAad(const Uint8* pInput, Uint64 aadLen) override;

    alc_error_t getTag(Uint8* pTag, Uint64 tagLen) override;

    alc_error_t setTagLength(Uint64 tagLen) override;

    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) override
    {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    alc_error_t finish() override { return ALC_ERROR_NONE; }

  private:
    // Initialize GCM context
    void initGcmContext()
    {
        m_gcm_ctx.m_num_512blks_precomputed = 0;
        m_gcm_ctx.m_num_256blks_precomputed = 0;
        m_gcm_ctx.m_update_counter          = 0;

        // Initialize partial buffer
        m_partialBuffer.clear();

        m_gcm_ctx.m_hash_subKey_128 = _mm_setzero_si128();
        m_gcm_ctx.m_gHash_128       = _mm_setzero_si128();
        m_gcm_ctx.m_counter_128     = _mm_setzero_si128();

        m_gcm_ctx.m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#if !ALWAYS_COMPUTE
        // global precomputed hashtable pointer
        m_gcm_ctx.m_pHashSubkeyTable_precomputed =
            m_gcm_ctx.m_gcm_key_data.m_hashSubkeyTable;
#endif
        m_gcm_ctx.m_tag_128           = _mm_setzero_si128();
        m_gcm_ctx.m_additionalDataLen = 0;
        m_gcm_ctx.m_tagLength         = 16;

        // Initialize AAD buffering fields
        m_gcm_ctx.m_aad_buffer.clear();
        m_gcm_ctx.m_aad_processed = false;
    }

    void setTable(alc_cipher_state_t* pCipherState)
    {
#if !ALWAYS_COMPUTE
        if (pCipherState != nullptr) {
            m_gcm_ctx.m_pHashSubkeyTable_precomputed =
                pCipherState->alcp_precomputed_table;
        }
#endif
    }

    // Helper function to process buffered AAD data
    inline alc_error_t processBufferedAad();

    // Helper functions for calling encryption/decryption backends
    alc_error_t encryptBlock(const Uint8* pInput, Uint8* pOutput, Uint64 len);
    alc_error_t decryptBlock(const Uint8* pInput, Uint8* pOutput, Uint64 len);
};

} // namespace alcp::cipher
