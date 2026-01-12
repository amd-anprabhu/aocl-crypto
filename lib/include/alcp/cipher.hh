/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

#include "config.h"

#include "alcp/alcp.hh"

#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/error.h"

#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <tuple>

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuCipherFeatures;
using alcp::utils::CpuId;

namespace alcp { namespace cipher {
    enum class CipherKeyLen
    {
        eKey128Bit = 128,
        eKey192Bit = 192,
        eKey256Bit = 256
    };

    enum class CipherMode
    {
        eCipherModeNone = 0,
        /* aes ciphers */
        eAesCBC,
        eAesOFB,
        eAesCTR,
        eAesCFB,
        eAesXTS,
        eCHACHA20, // non-aes
        /* aes aead ciphers */
        eAesGCM,
        eAesCCM,
        eAesSIV,
        eCHACHA20_POLY1305, // non-aes
        eCipherModeMax,
    };

    using cipherKeyLenTupleT = std::tuple<const CipherMode, const CipherKeyLen>;
    using cipherAlgoMapT     = std::map<const string, const cipherKeyLenTupleT>;

    // non-aead cipher interface
    class ALCP_API_EXPORT iCipher
    {

      public:
        virtual ~iCipher() = default;

        // Set key & iv
        virtual alc_error_t init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen)      = 0;
        virtual alc_error_t decrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len,
                                    Uint64*      outlen) = 0;
        virtual alc_error_t encrypt(const Uint8* pSrt,
                                    Uint8*       pDrc,
                                    Uint64       len,
                                    Uint64*      outlen) = 0;

        virtual alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) = 0;

        virtual alc_error_t finish(const void*)                = 0;
        virtual alc_error_t multibufferInit(const Uint8*  pKey,
                                            Uint64        keyLen,
                                            const Uint8** pIv,
                                            Uint64        ivLen,
                                            Uint64        numBuffers) = 0;

        /**
         * @brief Primary multi-buffer flush API (variable-length)
         *
         * Implementations must override this. The uniform-length version
         * below provides a default implementation that calls this.
         */
        virtual alc_error_t flush(const Uint8**  pPlainText,
                                  const Uint64*  pLengths,
                                  Uint64         numBuffers)          = 0;

        /**
         * @brief Primary multi-buffer dequeue API (variable-length)
         *
         * Implementations must override this. The uniform-length version
         * below provides a default implementation that calls this.
         */
        virtual alc_error_t dequeue(Uint8**       pCipherText,
                                    Uint64        numBuffers,
                                    const Uint64* pLengths)           = 0;
    };

    // iCipher segments
    class ALCP_API_EXPORT iCipherSeg
    {

      public:
        virtual ~iCipherSeg() = default;

        // Set key & iv
        virtual alc_error_t init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen)                          = 0;
        virtual alc_error_t decrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len)                         = 0;
        virtual alc_error_t encrypt(const Uint8* pSrt,
                                    Uint8*       pDrc,
                                    Uint64       len)                         = 0;
        virtual alc_error_t decryptSegment(const Uint8* pSrc,
                                           Uint8*       pDst,
                                           Uint64       len,
                                           Uint64       startBlockNum)        = 0;
        virtual alc_error_t encryptSegment(const Uint8* pSrt,
                                           Uint8*       pDrc,
                                           Uint64       len,
                                           Uint64       startBlockNum)        = 0;
        virtual alc_error_t finish(const void*)                         = 0;
        virtual alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) = 0;
    };

    // Additional Authentication functionality used for AEAD schemes
    class iCipherAuth
    {
      public:
        virtual ~iCipherAuth()                                       = default;
        virtual alc_error_t setAad(const Uint8* pAad, Uint64 aadLen) = 0;
        virtual alc_error_t getTag(Uint8* pTag, Uint64 tagLen)       = 0;
        // FIXME: Clean up setting lengths
        /* setPlaintextLength and setTageLength to be one single api */
        /* setLength(void*ctx, typeofLen, Uint64 len) */
        virtual alc_error_t setPlainTextLength(Uint64 plaintextLen)
        {
            // Only supported in CCM. Will be overridden there.
            return ALC_ERROR_EXISTS;
        }
        virtual alc_error_t setTagLength(Uint64 tagLen) = 0;
    };

    // aead cipher interface
    class ALCP_API_EXPORT iCipherAead
        : public virtual iCipher
        , public virtual iCipherAuth // authenication class - used for Aead
                                     // modes
    {
      public:
        virtual ~iCipherAead()                           = default;

        // Multi-buffer interface - default to NOT_SUPPORTED for AEAD modes
        // AEAD modes (GCM, CCM, etc.) have additional authentication requirements
        // that make multi-buffer processing more complex
        virtual alc_error_t flush(const Uint8**  pPlainText,
                                  const Uint64*  pLengths,
                                  Uint64         numBuffers) override
        {
            return ALC_ERROR_NOT_SUPPORTED;
        }
        virtual alc_error_t dequeue(Uint8**       pCipherText,
                                    Uint64        numBuffers,
                                    const Uint64* pLengths) override
        {
            return ALC_ERROR_NOT_SUPPORTED;
        }

    };

    /* Cipher Factory for different Aead and non-Aead modes */
    template<class INTERFACE>
    class ALCP_API_EXPORT CipherFactory
    {
      private:
        CpuCipherFeatures m_currentArch = getCpuCipherFeature();
        CpuCipherFeatures m_arch =
            m_currentArch; // Default to detected arch to avoid wrong dispatch
        INTERFACE*          m_iCipher      = nullptr;
        cipherAlgoMapT      m_cipherMap    = {};
        alc_cipher_state_t* m_cipher_state = nullptr;

      public:
        CipherFactory();
        ~CipherFactory();

        CipherKeyLen m_keyLen      = CipherKeyLen::eKey128Bit;
        CipherMode   m_cipher_mode = CipherMode::eCipherModeNone;
        // cipher creators
        INTERFACE* create(const string& name);
        INTERFACE* create(const string& name, CpuCipherFeatures arch);
        INTERFACE* create(const CipherMode mode, const CipherKeyLen keyLen);
        INTERFACE* create(const CipherMode    mode,
                          const CipherKeyLen  keyLen,
                          alc_cipher_state_t* pCipherState);
        INTERFACE* create(const CipherMode        mode,
                          const CipherKeyLen      keyLen,
                          const CpuCipherFeatures arch);

      private:
        void              initCipherMap();
        void              clearCipherMap();
        void              getCipher();
        CpuCipherFeatures getCpuCipherFeature();
    };

}} // namespace alcp::cipher
