/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher/cipher_wrapper.hh"

#include <type_traits>

namespace alcp::cipher {

/**
 * @brief Compile-time check for multibuffer support
 *
 * Only CBC and CFB modes support multibuffer operations.
 * CTR and OFB do not need multibuffer support.
 */
template<CipherMode mode>
constexpr bool SupportsMultibuffer = (mode == CipherMode::eAesCBC || 
                                      mode == CipherMode::eAesCFB);

/**
 * @brief Direct storage for multibuffer operations
 *
 * Only included in cipher classes that support multibuffer (CBC, CFB).
 * Contains IVs for multiple parallel buffers and data pointers.
 */
struct MultibufferStorage
{
    static constexpr Uint32 cMaxBufferCount = MAX_CIPHER_BUFFER_SIZE; // 127
    static constexpr Uint32 cIvSize         = 16; // AES block size

    alignas(16) Uint8 m_ivs[cMaxBufferCount][cIvSize] = {};
    const Uint8**     m_pData                         = nullptr;
    Uint64            m_bufferLengths[cMaxBufferCount] = {};
    Uint64            m_numBuffers                    = 0;

    Uint8* getIvBuffer(Uint32 index) { return m_ivs[index]; }
    const Uint8* getIvBuffer(Uint32 index) const { return m_ivs[index]; }
};

/**
 * @brief AES Generic Cipher Template
 *
 * Unified template class for AES block cipher modes (CBC, CTR, OFB, CFB).
 * Uses composition for key management via KeyManager (which inherits from Rijndael).
 * Implements iCipher interface.
 *
 * For CBC and CFB modes, also inherits iMultibuffer interface for parallel
 * multi-buffer encryption support.
 *
 * Template parameters:
 * - mode: Cipher mode (eAesCBC, eAesCTR, eAesOFB, eAesCFB)
 * - keyLenBits: Key length in bits (128, 192, or 256)
 * - arch: CPU architecture features for optimized implementations
 */
template<CipherMode mode, CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class AesGenericCiphersT
    : public iCipher
    , public std::conditional_t<SupportsMultibuffer<mode>, iMultibuffer, EmptyComponent>
{
  private:
    // Core components (always present)
    StateManager  m_stateManager;
    KeyManager    m_keyManager;
    IvManager     m_ivManager;
    PartialBuffer m_partialBuffer;

    // Conditional multibuffer storage - only for CBC and CFB
    // EmptyComponent (1 byte) for modes that don't need it
    std::conditional_t<SupportsMultibuffer<mode>, MultibufferStorage, EmptyComponent>
        m_multibuffer;

  public:
    AesGenericCiphersT()
        : m_keyManager(static_cast<Uint32>(keyLenBits) / 8)
        , m_ivManager(16, 16) // Generic ciphers use fixed 16-byte IV
    {
    }

    ~AesGenericCiphersT() = default;

  public:
    // iCipher: Core methods marked final for devirtualization optimization
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) final;
    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        Uint64*      outlen) final;
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        Uint64*      outlen) final;
    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) final;
    alc_error_t finish() final { return ALC_ERROR_NONE; }

    // iMultibuffer: Only implemented for CBC/CFB (otherwise won't compile due to interface)
    // These are conditionally available based on SupportsMultibuffer<mode>
    alc_error_t multibufferInit(const Uint8*  pKey,
                                Uint64        keyLen,
                                const Uint8** pIv,
                                Uint64        ivLen,
                                Uint64        numBuffers);
    alc_error_t flush(const Uint8**  pPlainText,
                      const Uint64*  pLengths,
                      Uint64         numBuffers);
    alc_error_t dequeue(Uint8**       pCipherText,
                        Uint64        numBuffers,
                        const Uint64* pLengths);

    // Accessor for cipher key data (delegates to KeyManager)
    const alc_cipher_key_data_t& getCipherKeyData() const
    {
        return m_keyManager.getCipherKeyData();
    }

    // Compile-time query for multibuffer support
    static constexpr bool hasMultibufferSupport() { return SupportsMultibuffer<mode>; }
};

} // namespace alcp::cipher
