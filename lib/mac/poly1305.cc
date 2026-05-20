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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/mac/poly1305.hh"
#include "alcp/base.hh"
#include "alcp/mac/poly1305_zen4.hh"
#include "alcp/utils/cpuid.hh"
#include <algorithm>
#include <array>
#include <iostream>
#include <tuple>
namespace alcp::mac::poly1305 {
using utils::AlgorithmType;
using utils::CpuArchLevel;
using utils::CpuId;

template<CpuArchLevel archLevel>
Poly1305<archLevel>::Poly1305()
{
    if constexpr (CpuArchLevel::eReference == archLevel
                  || CpuArchLevel::eZen == archLevel
                  || CpuArchLevel::eZen3 == archLevel) {
        poly1305_impl = std::make_unique<reference::Poly1305Ref>();
    } else if constexpr (CpuArchLevel::eDynamic == archLevel) {
        // CpuArchLevel::eDynamic
        static CpuArchLevel arch =
            CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
        if (arch < CpuArchLevel::eZen4) {
            poly1305_impl = std::make_unique<reference::Poly1305Ref>();
        }
    }
}

template<CpuArchLevel archLevel>
Poly1305<archLevel>::Poly1305(const Poly1305& src)
{}

template<CpuArchLevel archLevel>
alc_error_t
Poly1305<archLevel>::init(const Uint8 key[], Uint64 keyLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (keyLen != 32) {
        std::cout << "ERROR KEYLEN:" << keyLen << std::endl;
        err = ALC_ERROR_NOT_SUPPORTED;
        return err;
    }
    state.finalized = false;
    if constexpr (CpuArchLevel::eReference == archLevel
                  || CpuArchLevel::eZen == archLevel
                  || CpuArchLevel::eZen3 == archLevel) {
        return poly1305_impl->init(key, keyLen);
    } else if constexpr (CpuArchLevel::eZen4 == archLevel) {
        zen4::poly1305_init_radix44(state, key);
        err = ALC_ERROR_NONE;
        return err;
    } else if constexpr (CpuArchLevel::eDynamic == archLevel) {
        // Manual dispatch in case we don't know where to dispatch to.
        static CpuArchLevel arch =
            CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
        if (arch >= CpuArchLevel::eZen4) {
            zen4::poly1305_init_radix44(state, key);
            err = ALC_ERROR_NONE;
            return err;
        } else {
            return poly1305_impl->init(key, keyLen);
        }
    }
    err = ALC_ERROR_BAD_STATE;
    return err;
}

template<CpuArchLevel archLevel>
alc_error_t
Poly1305<archLevel>::update(const Uint8 pMsg[], Uint64 msgLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if constexpr (CpuArchLevel::eReference == archLevel
                  || CpuArchLevel::eZen == archLevel
                  || CpuArchLevel::eZen3 == archLevel) {
        return poly1305_impl->update(pMsg, msgLen);
    } else if constexpr (CpuArchLevel::eZen4 == archLevel) {
        if (zen4::poly1305_update_radix44(state, pMsg, msgLen) == true) {
            err = ALC_ERROR_NONE;
            return err;
        } else {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
    } else if constexpr (CpuArchLevel::eDynamic == archLevel) {
        // Manual dispatch in case we don't know where to dispatch to.
        static CpuArchLevel arch =
            CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
        if (arch >= CpuArchLevel::eZen4) {
            if (zen4::poly1305_update_radix44(state, pMsg, msgLen) == true) {
                err = ALC_ERROR_NONE;
                return err;
            } else {
                err = ALC_ERROR_BAD_STATE;
                return err;
            }
        } else {
            return poly1305_impl->update(pMsg, msgLen);
        }
    }
    err = ALC_ERROR_BAD_STATE;
    return err;
}

template<CpuArchLevel archLevel>
alc_error_t
Poly1305<archLevel>::reset()
{
    alc_error_t err = ALC_ERROR_NONE;
    if constexpr (CpuArchLevel::eReference == archLevel
                  || CpuArchLevel::eZen == archLevel
                  || CpuArchLevel::eZen3 == archLevel) {
        return poly1305_impl->reset();
    } else if constexpr (CpuArchLevel::eZen4 == archLevel) {
        state.reset();
        err = ALC_ERROR_NONE;
        return err;
    } else if constexpr (CpuArchLevel::eDynamic == archLevel) {
        // Manual dispatch in case we don't know where to dispatch to.
        static CpuArchLevel arch =
            CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
        if (arch >= CpuArchLevel::eZen4) {
            state.reset();
            err = ALC_ERROR_NONE;
            return err;
        } else {
            return poly1305_impl->reset();
        }
    }
    err = ALC_ERROR_BAD_STATE;
    return err;
}

template<CpuArchLevel archLevel>
alc_error_t
Poly1305<archLevel>::finalize(Uint8 digest[], Uint64 digestLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if constexpr (CpuArchLevel::eReference == archLevel
                  || CpuArchLevel::eZen == archLevel
                  || CpuArchLevel::eZen3 == archLevel) {
        return poly1305_impl->finish(digest, digestLen);
    } else if constexpr (CpuArchLevel::eZen4 == archLevel) {
        if (zen4::poly1305_finalize_radix44(state, digest, digestLen) == true) {
            err = ALC_ERROR_NONE;
            return err;
        } else {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
    } else if constexpr (CpuArchLevel::eDynamic == archLevel) {
        // Manual dispatch in case we don't know where to dispatch to.
        static CpuArchLevel arch =
            CpuId::getCachedArchLevel(AlgorithmType::ePoly1305);
        if (arch >= CpuArchLevel::eZen4) {
            if (zen4::poly1305_finalize_radix44(state, digest, digestLen)
                == true) {
                err = ALC_ERROR_NONE;
                return err;
            } else {
                err = ALC_ERROR_BAD_STATE;
                return err;
            }
        } else {
            return poly1305_impl->finish(digest, digestLen);
        }
    }
    err = ALC_ERROR_BAD_STATE;
    return err;
}

template class Poly1305<CpuArchLevel::eZen4>;
template class Poly1305<CpuArchLevel::eZen3>;
template class Poly1305<CpuArchLevel::eZen>;
template class Poly1305<CpuArchLevel::eReference>;
template class Poly1305<CpuArchLevel::eDynamic>;
} // namespace alcp::mac::poly1305
