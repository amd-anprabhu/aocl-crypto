/*
 * Copyright (C) 2021-2025, Advanced Micro Devices. All rights reserved.
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



#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_poly1305.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {

using alcp::utils::CpuCipherFeatures;

namespace {

// Index conversion helpers for dispatch tables
constexpr int
keyLenToIndex(CipherKeyLen k)
{
    switch (k) {
        case CipherKeyLen::eKey128Bit:
            return 0;
        case CipherKeyLen::eKey192Bit:
            return 1;
        case CipherKeyLen::eKey256Bit:
            return 2;
    }
    return -1;
}

constexpr int
archToIndex(CpuCipherFeatures a)
{
    switch (a) {
        case CpuCipherFeatures::eAesni:
            return 0;
        case CpuCipherFeatures::eVaes256:
            return 1;
        case CpuCipherFeatures::eVaes512:
            return 2;
        default:
            return -1;
    }
}

// Strategy dispatch table dimensions
constexpr int NUM_KEY_LENS = 3; // 128, 192, 256
constexpr int NUM_ARCHS    = 3; // eAesni, eVaes256, eVaes512

// -----------------------------------------------------------------------------
// Template-based Strategy Dispatcher
// Eliminates repetitive switch/if-else chains by using compile-time lookup
// -----------------------------------------------------------------------------

template<typename Interface,
         template<CipherKeyLen, CpuCipherFeatures>
         class CipherT>
struct CipherStrategy
{
    using CreatorFn = Interface* (*)();

    // Dispatch table: [keyLen][arch] -> creator function
    static constexpr CreatorFn creators[NUM_KEY_LENS][NUM_ARCHS] = {
        // eKey128Bit row
        { []() -> Interface* {
             return new CipherT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>();
         },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey128Bit,
                                 CpuCipherFeatures::eVaes256>();
          },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey128Bit,
                                 CpuCipherFeatures::eVaes512>();
          } },
        // eKey192Bit row
        { []() -> Interface* {
             return new CipherT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eAesni>();
         },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey192Bit,
                                 CpuCipherFeatures::eVaes256>();
          },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey192Bit,
                                 CpuCipherFeatures::eVaes512>();
          } },
        // eKey256Bit row
        { []() -> Interface* {
             return new CipherT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>();
         },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey256Bit,
                                 CpuCipherFeatures::eVaes256>();
          },
          []() -> Interface* {
              return new CipherT<CipherKeyLen::eKey256Bit,
                                 CpuCipherFeatures::eVaes512>();
          } },
    };

    static Interface* dispatch(CipherKeyLen keyLen, CpuCipherFeatures arch)
    {
        int keyIdx  = keyLenToIndex(keyLen);
        int archIdx = archToIndex(arch);
        if (keyIdx < 0 || archIdx < 0) {
            printf("\n Error: Invalid key length or architecture ");
            return nullptr;
        }
        return creators[keyIdx][archIdx]();
    }
};

// Specialized strategy for GCM with external state parameter
struct GcmWithStateStrategy
{
    using CreatorFn = iCipherAead* (*)(alc_cipher_state_t*);

    static constexpr CreatorFn creators[NUM_KEY_LENS][NUM_ARCHS] = {
        // eKey128Bit row
        { [](alc_cipher_state_t* s) -> iCipherAead* {
             return new GcmT<CipherKeyLen::eKey128Bit,
                             CpuCipherFeatures::eAesni>(s);
         },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey128Bit,
                              CpuCipherFeatures::eVaes256>(s);
          },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey128Bit,
                              CpuCipherFeatures::eVaes512>(s);
          } },
        // eKey192Bit row
        { [](alc_cipher_state_t* s) -> iCipherAead* {
             return new GcmT<CipherKeyLen::eKey192Bit,
                             CpuCipherFeatures::eAesni>(s);
         },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey192Bit,
                              CpuCipherFeatures::eVaes256>(s);
          },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey192Bit,
                              CpuCipherFeatures::eVaes512>(s);
          } },
        // eKey256Bit row
        { [](alc_cipher_state_t* s) -> iCipherAead* {
             return new GcmT<CipherKeyLen::eKey256Bit,
                             CpuCipherFeatures::eAesni>(s);
         },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey256Bit,
                              CpuCipherFeatures::eVaes256>(s);
          },
          [](alc_cipher_state_t* s) -> iCipherAead* {
              return new GcmT<CipherKeyLen::eKey256Bit,
                              CpuCipherFeatures::eVaes512>(s);
          } },
    };

    static iCipherAead* dispatch(CipherKeyLen        keyLen,
                                 CpuCipherFeatures   arch,
                                 alc_cipher_state_t* state)
    {
        int keyIdx  = keyLenToIndex(keyLen);
        int archIdx = archToIndex(arch);
        if (keyIdx < 0 || archIdx < 0) {
            printf("\n Error: Invalid key length or architecture ");
            return nullptr;
        }
        return creators[keyIdx][archIdx](state);
    }
};

// Strategy for generic ciphers (CBC, CTR, OFB, CFB) with mode as template param
template<CipherMode Mode>
struct GenericCipherStrategy
{
    using CreatorFn = iCipher* (*)();

    static constexpr CreatorFn creators[NUM_KEY_LENS][NUM_ARCHS] = {
        // eKey128Bit row
        { []() -> iCipher* {
             return new AesGenericCiphersT<Mode,
                                          CipherKeyLen::eKey128Bit,
                                          CpuCipherFeatures::eAesni>();
         },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey128Bit,
                                           CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey128Bit,
                                           CpuCipherFeatures::eVaes512>();
          } },
        // eKey192Bit row
        { []() -> iCipher* {
             return new AesGenericCiphersT<Mode,
                                          CipherKeyLen::eKey192Bit,
                                          CpuCipherFeatures::eAesni>();
         },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey192Bit,
                                           CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey192Bit,
                                           CpuCipherFeatures::eVaes512>();
          } },
        // eKey256Bit row
        { []() -> iCipher* {
             return new AesGenericCiphersT<Mode,
                                          CipherKeyLen::eKey256Bit,
                                          CpuCipherFeatures::eAesni>();
         },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey256Bit,
                                           CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipher* {
              return new AesGenericCiphersT<Mode,
                                           CipherKeyLen::eKey256Bit,
                                           CpuCipherFeatures::eVaes512>();
          } },
    };

    static iCipher* dispatch(CipherKeyLen keyLen, CpuCipherFeatures arch)
    {
        int keyIdx  = keyLenToIndex(keyLen);
        int archIdx = archToIndex(arch);
        if (keyIdx < 0 || archIdx < 0) {
            printf("\n Error: Invalid key length or architecture ");
            return nullptr;
        }
        return creators[keyIdx][archIdx]();
    }
};

// Strategy for XTS (only supports 128 and 256 bit keys)
struct XtsStrategy
{
    using CreatorFn = iCipher* (*)();

    // Only 128 and 256 bit keys supported, nullptr for 192
    static constexpr CreatorFn creators[NUM_KEY_LENS][NUM_ARCHS] = {
        // eKey128Bit row
        { []() -> iCipher* {
             return new XtsT<CipherKeyLen::eKey128Bit,
                             CpuCipherFeatures::eAesni>();
         },
          []() -> iCipher* {
              return new XtsT<CipherKeyLen::eKey128Bit,
                              CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipher* {
              return new XtsT<CipherKeyLen::eKey128Bit,
                              CpuCipherFeatures::eVaes512>();
          } },
        // eKey192Bit row - not supported
        { nullptr, nullptr, nullptr },
        // eKey256Bit row
        { []() -> iCipher* {
             return new XtsT<CipherKeyLen::eKey256Bit,
                             CpuCipherFeatures::eAesni>();
         },
          []() -> iCipher* {
              return new XtsT<CipherKeyLen::eKey256Bit,
                              CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipher* {
              return new XtsT<CipherKeyLen::eKey256Bit,
                              CpuCipherFeatures::eVaes512>();
          } },
    };

    static iCipher* dispatch(CipherKeyLen keyLen, CpuCipherFeatures arch)
    {
        int keyIdx  = keyLenToIndex(keyLen);
        int archIdx = archToIndex(arch);
        if (keyIdx < 0 || archIdx < 0 || creators[keyIdx][archIdx] == nullptr) {
            printf("\n Error: key length not supported for XTS ");
            return nullptr;
        }
        return creators[keyIdx][archIdx]();
    }
};

// Strategy for XTS Block (segmented capability) - only supports 128 and 256 bit keys
struct XtsBlockStrategy
{
    using CreatorFn = iCipherSegment* (*)();

    static constexpr CreatorFn creators[NUM_KEY_LENS][NUM_ARCHS] = {
        // eKey128Bit row
        { []() -> iCipherSegment* {
             return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>();
         },
          []() -> iCipherSegment* {
              return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                   CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipherSegment* {
              return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                   CpuCipherFeatures::eVaes512>();
          } },
        // eKey192Bit row - not supported
        { nullptr, nullptr, nullptr },
        // eKey256Bit row
        { []() -> iCipherSegment* {
             return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>();
         },
          []() -> iCipherSegment* {
              return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                   CpuCipherFeatures::eVaes256>();
          },
          []() -> iCipherSegment* {
              return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                   CpuCipherFeatures::eVaes512>();
          } },
    };

    static iCipherSegment* dispatch(CipherKeyLen keyLen, CpuCipherFeatures arch)
    {
        int keyIdx  = keyLenToIndex(keyLen);
        int archIdx = archToIndex(arch);
        if (keyIdx < 0 || archIdx < 0 || creators[keyIdx][archIdx] == nullptr) {
            printf("\n Error: key length not supported for XTS Block ");
            return nullptr;
        }
        return creators[keyIdx][archIdx]();
    }
};

// CCM Strategy - only supports eAesni architecture
struct CcmStrategy
{
    using CreatorFn = iCipherAead* (*)();

    static constexpr CreatorFn creators[NUM_KEY_LENS] = {
        []() -> iCipherAead* {
            return new Ccm<CipherKeyLen::eKey128Bit, CpuCipherFeatures::eAesni>();
        },
        []() -> iCipherAead* {
            return new Ccm<CipherKeyLen::eKey192Bit, CpuCipherFeatures::eAesni>();
        },
        []() -> iCipherAead* {
            return new Ccm<CipherKeyLen::eKey256Bit, CpuCipherFeatures::eAesni>();
        },
    };

    static iCipherAead* dispatch(CipherKeyLen keyLen)
    {
        int keyIdx = keyLenToIndex(keyLen);
        if (keyIdx < 0) {
            printf("\n Error: Invalid key length for CCM ");
            return nullptr;
        }
        return creators[keyIdx]();
    }
};

// CPU feature detection
CpuCipherFeatures
getCpuCipherFeature()
{
    CpuCipherFeatures cpu_feature = CpuCipherFeatures::eReference;

    if (CpuId::cpuHasAesni() && CpuId::cpuHasAvx2()) {
        cpu_feature = CpuCipherFeatures::eAesni;

        if (CpuId::cpuHasVaes()) {
            cpu_feature = CpuCipherFeatures::eVaes256;

            if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
                cpu_feature = CpuCipherFeatures::eVaes512;
            }
        }
    }
    return cpu_feature;
}

// Cached CPU feature - initialized once
CpuCipherFeatures
getCachedCpuFeature()
{
    static CpuCipherFeatures s_cpuFeatures = getCpuCipherFeature();
    return s_cpuFeatures;
}

} // anonymous namespace

iCipherAead*
createCipherAead(const CipherMode    mode,
                 const CipherKeyLen  keyLen,
                 alc_cipher_state_t* pCipherState)
{
    CpuCipherFeatures arch = getCachedCpuFeature();

    if (keyLenToIndex(keyLen) < 0) {
        printf("\n Error: key length not supported ");
        return nullptr;
    }

    if (arch < CpuCipherFeatures::eAesni) {
        printf("\n Error: Reference kernel not supported ");
        return nullptr;
    }

    switch (mode) {
        case CipherMode::eAesGCM:
            return GcmWithStateStrategy::dispatch(keyLen, arch, pCipherState);

        case CipherMode::eAesCCM:
            // CCM only supports eAesni architecture
            return CcmStrategy::dispatch(keyLen);

        case CipherMode::eAesSIV:
            return CipherStrategy<iCipherAead, Siv>::dispatch(keyLen, arch);

        case CipherMode::eCHACHA20_POLY1305:
            // ChaCha20-Poly1305 only supports 256-bit keys
            if (keyLen != CipherKeyLen::eKey256Bit) {
                printf("\n Error: ChaCha20-Poly1305 only supports 256-bit keys ");
                return nullptr;
            }
            if (arch >= CpuCipherFeatures::eVaes512) {
                return new vaes512::ChaChaPoly();
            }
            return new ref::ChaChaPoly();

        default:
            printf("\n Error: AEAD cipher mode not supported ");
            return nullptr;
    }
}

iCipher*
createCipher(const CipherMode mode, const CipherKeyLen keyLen)
{
    CpuCipherFeatures arch = getCachedCpuFeature();

    if (keyLenToIndex(keyLen) < 0) {
        printf("\n Error: key length not supported ");
        return nullptr;
    }

    if (arch < CpuCipherFeatures::eAesni) {
        printf("\n Error: Reference kernel not supported ");
        return nullptr;
    }

    switch (mode) {
        case CipherMode::eAesCBC:
            return GenericCipherStrategy<CipherMode::eAesCBC>::dispatch(keyLen, arch);

        case CipherMode::eAesCTR:
            return GenericCipherStrategy<CipherMode::eAesCTR>::dispatch(keyLen, arch);

        case CipherMode::eAesOFB:
            return GenericCipherStrategy<CipherMode::eAesOFB>::dispatch(keyLen, arch);

        case CipherMode::eAesCFB:
            return GenericCipherStrategy<CipherMode::eAesCFB>::dispatch(keyLen, arch);

        case CipherMode::eAesXTS:
            return XtsStrategy::dispatch(keyLen, arch);

        case CipherMode::eCHACHA20:
            // ChaCha20 only supports 256-bit keys
            if (keyLen != CipherKeyLen::eKey256Bit) {
                printf("\n Error: ChaCha20 only supports 256-bit keys ");
                return nullptr;
            }
            if (arch >= CpuCipherFeatures::eVaes512) {
                return new vaes512::ChaCha256();
            }
            return new ref::ChaCha256();

        default:
            printf("\n Error: Cipher mode not supported ");
            return nullptr;
    }
}

iCipherSegment*
createCipherSeg(const CipherMode mode, const CipherKeyLen keyLen)
{
    CpuCipherFeatures arch = getCachedCpuFeature();

    if (arch < CpuCipherFeatures::eAesni) {
        printf("\n Error: Reference kernel not supported ");
        return nullptr;
    }

    switch (mode) {
        case CipherMode::eAesXTS:
            return XtsBlockStrategy::dispatch(keyLen, arch);

        default:
            printf("\n Error: Cipher mode not supported for segmented ");
            return nullptr;
    }
}

} // namespace alcp::cipher