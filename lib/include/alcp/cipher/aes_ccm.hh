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
#include "alcp/utils/copy.hh"

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher {

/**
 * @brief CCM mode context data
 * @struct ccm_data_t
 */

struct ccm_data_t
{
    alignas(16) Uint8 nonce[16];
    alignas(16) Uint8 cmac[16];
    const Uint8*  key    = nullptr;
    Uint64        blocks = 0;
    Uint32        rounds = 0;
    unsigned char flags0;
};

enum class CCM_ERROR
{
    NO_ERROR      = 0,
    LEN_MISMATCH  = -1,
    DATA_OVERFLOW = -2,
};

namespace aesni::ccm {
    // Defined in arch/zen3
    CCM_ERROR SetAad(ccm_data_t* ctx,
                     const Uint8 aad[],
                     Uint64      alen,
                     Uint64      plen);
    CCM_ERROR Finalize(ccm_data_t* ctx);

    CCM_ERROR Encrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      Uint64      dataLen);

    CCM_ERROR Decrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      Uint64      len);
} // namespace aesni::ccm

/**
 * @brief Unified CCM cipher class
 *
 * Uses composition for state, key (with Rijndael), and IV management.
 * KeyManager inherits from Rijndael and handles key expansion internally.
 * 
 * Template parameters:
 * - keyLenBits: Key length (128, 192, or 256 bits)
 * - arch: CPU architecture features (currently only eAesni supported)
 */
template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class CcmT
    : public iCipherCcm
{
  private:
    // Composed components
    StateManager m_stateManager;
    KeyManager   m_keyManager;
    IvManager    m_ivManager;

  protected:
    Uint64       m_tagLen            = 12; // default taglen
    Uint64       m_additionalDataLen = 0;
    const Uint8* m_additionalData{};
    Uint64       m_plainTextLength      = 0;
    bool         m_is_plaintext_len_set = false;
    Uint64       m_updatedLength        = 0;
    ccm_data_t   m_ccm_data{};

  protected:
    alc_error_t setIvInternal(ccm_data_t* ccm_data,
                              const Uint8 pIv[],
                              Uint64      ivLen,
                              Uint64      dataLen);

    alc_error_t cryptUpdate(const Uint8 pInput[],
                            Uint8       pOutput[],
                            Uint64      dataLen,
                            bool        isEncrypt);

  public:
    CcmT()
        : m_keyManager(static_cast<Uint32>(keyLenBits) / 8)
        , m_ivManager(7, 13) // CCM IV length: 7-13 bytes
    {
    }

    ~CcmT() = default;

  public:
    // iCipherAead auth methods
    alc_error_t setAad(const Uint8* pInput, Uint64 aadLen) override;
    alc_error_t getTag(Uint8* pOutput, Uint64 tagLen) override;
    alc_error_t setTagLength(Uint64 tagLength) override;
    alc_error_t setPlainTextLength(Uint64 len) override; // used in multiupdate case only

    // iCipher methods
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
    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) override
    {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    alc_error_t finish() override { return ALC_ERROR_NONE; }
};

template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
using Ccm = CcmT<keyLenBits, arch>;

} // namespace alcp::cipher
