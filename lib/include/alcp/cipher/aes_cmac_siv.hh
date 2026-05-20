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

#include "alcp/base.hh"
#include "alcp/cipher.hh"
#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/common.hh"

#include "alcp/cipher/aes_cmac_siv_arch.hh"

#include "alcp/mac/cmac.hh"
#include "alcp/utils/copy.hh"
#include <new>
#include <vector>

using Cmac = alcp::mac::Cmac;
#define SIZE_CMAC 128 / 8
namespace alcp::cipher {

/**
 * @brief Unified SIV cipher class
 *
 * Uses composition - no Rijndael inheritance needed:
 * - m_cmac handles S2V key expansion (uses KeyManager internally)
 * - m_ctrCipher handles CTR key expansion (has its own KeyManager)
 * 
 * SIV uses a dual-key construction:
 * - First half of key for S2V (authentication via CMAC)
 * - Second half of key for CTR encryption
 * 
 * Template parameters:
 * - keyLenBits: Key length (128, 192, or 256 bits)
 * - arch: CPU architecture features
 */
template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class SivT
    : public virtual iCipherAead
{
  private:
    // Internal CTR cipher for encryption/decryption (inline, no heap allocation)
    AesGenericCiphersT<CipherMode::eAesCTR, keyLenBits, arch> m_ctrCipher;

    // Simple IV storage for synthetic IV during decryption (16 bytes for SIV)
    alignas(16) Uint8 m_syntheticIv[16] = {};

  protected:
    // FIXME: simplify the vector code, unnecessary complication! Just allocate
    // max data size
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);

    alignas(16) Uint8 m_cmacTemp[SIZE_CMAC] = {};
    Uint64 m_additionalDataProcessedSize    = {};
    Uint8  m_key1[32]{};
    Uint8  m_key2[32]{};
    Uint64 m_padLen = 0;
    Cmac   m_cmac;

    alc_error_t cmacWrapper(const Uint8 data[],
                            Uint64      size,
                            Uint8       mac[],
                            Uint64      macSize);
    alc_error_t cmacWrapperMultiData(const Uint8 data1[],
                                     Uint64      size1,
                                     const Uint8 data2[],
                                     Uint64      size2,
                                     Uint8       mac[],
                                     Uint64      macSize);
    alc_error_t addAdditionalInput(const Uint8* pAad, Uint64 aadLen);
    alc_error_t setKeys(const Uint8 key1[], Uint64 length);
    alc_error_t s2v(const Uint8 plainText[], Uint64 size);

  public:
    SivT() = default;
    ~SivT()
    {
        memset(m_key1, 0, 32);
        memset(m_key2, 0, 32);
        memset(m_syntheticIv, 0, 16);
    }

  public:
    // iCipherAead auth methods
    alc_error_t setAad(const Uint8* pInput, Uint64 aadLen) override;
    alc_error_t getTag(Uint8* pTag, Uint64 tagLen) override;
    alc_error_t setTagLength(Uint64 tagLen) override;

    // iCipher methods
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override;
    alc_error_t encrypt(const Uint8* pInput,
                        Uint8*       pOutput,
                        Uint64       len,
                        Uint64*      outlen) override;
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        Uint64*      outlen) override;
    alc_error_t finish() override { return ALC_ERROR_NONE; }
    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) override
    {
        return ALC_ERROR_NOT_SUPPORTED;
    }
};

template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
using Siv = SivT<keyLenBits, arch>;

} // namespace alcp::cipher
