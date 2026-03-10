/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include <cstdlib>

#include "system_rng.hh"

namespace alcp::rng {

#if defined(__linux__)
#include <sys/random.h>
#define ALCP_CONFIG_OS_HAS_GETRANDOM 1
#elif defined(_WIN32)
#include <windows.h>

#include <bcrypt.h>
#define ALCP_CONFIG_OS_HAS_BCRYPT_RNG 1

#else
#include <sys/random.h>
#define ALCP_CONFIG_OS_HAS_GETRANDOM 1
#endif

#if defined(ALCP_CONFIG_OS_HAS_BCRYPT_RNG)

class SystemRngImpl
{
  private:
    using ProcessPrngFn = BOOL(WINAPI*)(PBYTE, SIZE_T);

    static ProcessPrngFn resolveProcessPrng()
    {
        HMODULE       hMod         = GetModuleHandleW(L"bcryptprimitives.dll");
        ProcessPrngFn pProcessPrng = nullptr;
        if (hMod) {
            pProcessPrng = reinterpret_cast<ProcessPrngFn>(
                reinterpret_cast<void*>(GetProcAddress(hMod, "ProcessPrng")));
        }
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "ProcessPrng check: %d", !!pProcessPrng);
#endif
        return pProcessPrng;
    }

  public:
    static alc_error_t randomize(Uint8 output[], size_t length)
    {
        static const ProcessPrngFn pProcessPrng = resolveProcessPrng();

        if (pProcessPrng) {
            if (pProcessPrng(reinterpret_cast<PBYTE>(output),
                             static_cast<SIZE_T>(length))) {
                return ALC_ERROR_NONE;
            }
        }

        NTSTATUS status = BCryptGenRandom(NULL,
                                          reinterpret_cast<PUCHAR>(output),
                                          static_cast<ULONG>(length),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            return ALC_ERROR_NO_ENTROPY;
        }
        return ALC_ERROR_NONE;
    }
};

#elif defined(ALCP_CONFIG_OS_HAS_GETRANDOM)

class SystemRngImpl
{
  public:
    static alc_error_t randomize(Uint8 output[], size_t length)
    {
        alc_error_t err = ALC_ERROR_NONE;
        const int flag = 0;
        size_t    out  = getrandom(&output[0], length, flag);

        for (int i = 0; i < 10; i++) {
            if (out < length) {
                auto delta = length - out;
                out += getrandom(&output[out], delta, flag);
            } else {
                break;
            }
        }

        if (out != length) {
            return ALC_ERROR_NO_ENTROPY;
        }
        return err;
    }
};

#endif

class ISeeder;

SystemRng::SystemRng()
//: m_pimpl{ std::make_unique<SystemRng::Impl>() }
{
    // UNUSED(rRngInfo);
}

SystemRng::SystemRng(ISeeder& iss)
//: m_pimpl{ std::make_unique<SystemRng::Impl>() }
{
    // UNUSED(rRngInfo);
}

alc_error_t
SystemRng::readRandom(Uint8* buf, size_t length)
{
    return SystemRngImpl::randomize(buf, length);
}

alc_error_t
SystemRng::randomize(Uint8 output[], size_t length)
{
    return SystemRngImpl::randomize(output, length);
}

bool
SystemRng::isSeeded() const
{
    return true;
}

size_t
SystemRng::reseed()
{
    return 0;
}

alc_error_t
SystemRng::setPredictionResistance(bool value)
{
    m_prediction_resistance = value;
    return ALC_ERROR_NONE;
}

} // namespace alcp::rng
