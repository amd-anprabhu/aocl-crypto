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

#include "alcp/utils/cpuid.hh"
#include <alcp/base.hh>
#include <array>
#include <mutex>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif
#else
#include <Windows.h>
#include <direct.h>
#include <io.h>
#endif
#ifdef ALCP_ENABLE_AOCL_UTILS
#include <Au/Cpuid/X86Cpu.hh>
#endif

namespace alcp::utils {
#ifdef ALCP_ENABLE_AOCL_UTILS
using namespace Au;
#endif

// FIXME: Memory Allocations for static variables
std::unique_ptr<CpuId::Impl> CpuId::pImpl = std::make_unique<CpuId::Impl>();

// Impl class declaration
class CpuId::Impl
{
  public:
    Impl();
    ~Impl() = default;
#ifdef ALCP_ENABLE_AOCL_UTILS
    std::unique_ptr<X86Cpu> m_cpu;
#endif

  public:
    bool AlcpEnableInstructionSet = false;
    bool cpuid_disable_avx512     = false;
    bool cpuid_disable_vaes       = false;

    /* cached CPU architecture detection results */
    bool        zen1_flag          = false;
    bool        zen2_flag          = false;
    bool        zen3_flag          = false;
    bool        zen4_flag          = false;
    bool        zen5_flag          = false;
    const char* actual_cpu_arch    = "Unknown";
    bool        cpu_detection_done = false;

    void get_alcp_enabled_instr();
    void detect_cpu_architecture();

    // Low-level CPU feature detection
    bool cpuHasAvx512f();
    bool cpuHasAvx512dq();
    bool cpuHasAvx512bw();
    bool cpuHasAvx512ifma();
    bool cpuHasAvx512vl();
    bool cpuHasAvx512(Avx512Flags flag);
    bool cpuHasVaes();
    bool cpuHasAesni();
    bool cpuHasShani();
    bool cpuHasAvx2();
    bool cpuHasSse3();
    bool cpuHasRdRand();
    bool cpuHasRdSeed();
    bool cpuHasAdx();
    bool cpuHasBmi2();

    // Zen microarchitecture detection
    bool cpuIsZen1();
    bool cpuIsZen2();
    bool cpuIsZen3();
    bool cpuIsZen4();
    bool cpuIsZen5();
};

CpuId::Impl::Impl()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
#ifdef ALCP_BUILD_OS_LINUX
    cpu_set_t current_mask = {};
    pid_t     tid          = gettid();
    int       result = sched_getaffinity(tid, sizeof(cpu_set_t), &current_mask);
    if (result != 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }

    // Find first available CPU from affinity mask
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &current_mask)) {
            m_cpu = std::make_unique<X86Cpu>(i);
            break;
        }
    }

    // Fallback: if no CPU was found in affinity mask, use CPU 0
    // This can happen in containers or unusual scheduling configurations
    if (!m_cpu) {
        m_cpu = std::make_unique<X86Cpu>(0);
    }

    result = sched_setaffinity(tid, sizeof(cpu_set_t), &current_mask);
    if (result != 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }
#else
    HANDLE hProcess = GetCurrentProcess();

    DWORD_PTR procAffinity, sysAffinity;
    if (!GetProcessAffinityMask(hProcess, &procAffinity, &sysAffinity))
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;

    m_cpu = std::make_unique<X86Cpu>(0);

    bool result = SetProcessAffinityMask(hProcess, procAffinity);
    if (result == 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }
#endif
#endif
    /* detect cpu architecture */
    detect_cpu_architecture();

    /* read environment variable to force cpu arch */
    get_alcp_enabled_instr();

#ifndef ALCP_ENABLE_AOCL_UTILS
    std::fprintf(stderr,
                 "AOCL-Utils is unavailable at compile time! Defaulting to "
                 "ZEN2 dispatch!\n");
    std::fprintf(stderr,
                 "Check ALCP_ENABLE_AOCL_UTILS param at configure stage!"
                 "\n");
#endif
}

/**
 * @brief Reads the environment variable `AOCL_ENABLE_INSTRUCTION` to determine
 * the enabled CPU instructions.
 *
 * Supported values: ZEN, ZEN1, ZEN2, ZEN3, ZEN4, ZEN5
 * - ZEN/ZEN1/ZEN2: Disables AVX512 and VAES (forces Zen1/Zen2 code paths)
 * - ZEN3: Disables AVX512 (forces Zen3 code paths with 256-bit VAES)
 * - ZEN4/ZEN5: No effect (native CPU detection used)
 */
void
CpuId::Impl::get_alcp_enabled_instr()
{
    const char* AOCL_Enable_Inst = std::getenv("AOCL_ENABLE_INSTRUCTION");

    if (AOCL_Enable_Inst == NULL) {
        AlcpEnableInstructionSet = true;
        return;
    }

    if (strcmp(AOCL_Enable_Inst, "ZEN5") == 0) {
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN5 has no effect "
                     "(native CPU detection used)\n");
    } else if (strcmp(AOCL_Enable_Inst, "ZEN4") == 0) {
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN4 has no effect "
                     "(native CPU detection used)\n");
    } else if (strcmp(AOCL_Enable_Inst, "ZEN3") == 0) {
        cpuid_disable_avx512 = true;
    } else if (strcmp(AOCL_Enable_Inst, "ZEN2") == 0) {
        cpuid_disable_avx512 = true;
        cpuid_disable_vaes   = true;
    } else if ((strcmp(AOCL_Enable_Inst, "ZEN") == 0)
               || (strcmp(AOCL_Enable_Inst, "ZEN1") == 0)) {
        cpuid_disable_avx512 = true;
        cpuid_disable_vaes   = true;
    } else {
        std::cerr << "Invalid option passed to environment variable "
                     "AOCL_ENABLE_INSTRUCTION "
                     "(Supported values: ZEN/ZEN1/ZEN2/ZEN3/ZEN4/ZEN5)"
                  << std::endl;
        std::exit(-1);
    }
    AlcpEnableInstructionSet = true;
}

/**
 * @brief Detects and caches the CPU architecture once during initialization
 *
 * This function performs the actual CPU detection and stores the results
 * in member variables to avoid repeated detection calls.
 */
void
CpuId::Impl::detect_cpu_architecture()
{
    if (cpu_detection_done) {
        return; // Already detected
    }

#ifdef ALCP_ENABLE_AOCL_UTILS
    zen1_flag = Impl::m_cpu->isUarch(EUarch::Zen);
    zen2_flag = Impl::m_cpu->isUarch(EUarch::Zen2);
    zen3_flag = Impl::m_cpu->isUarch(EUarch::Zen3);
    zen4_flag = Impl::m_cpu->isUarch(EUarch::Zen4);
    zen5_flag = Impl::m_cpu->isUarch(EUarch::Zen5);
#else
    // Default dispatch is to Zen2
    // If this condition is setup, you can never force it to zen3 or zen4
    // We need cpuid to verify it can actually run on the machine
    zen1_flag = false;
    zen2_flag = true;
    zen3_flag = false;
    zen4_flag = false;
    zen5_flag = false;
#endif

    // Determine actual CPU architecture for logging
    if (zen5_flag)
        actual_cpu_arch = "ZEN5";
    else if (zen4_flag)
        actual_cpu_arch = "ZEN4";
    else if (zen3_flag)
        actual_cpu_arch = "ZEN3";
    else if (zen2_flag)
        actual_cpu_arch = "ZEN2";
    else if (zen1_flag)
        actual_cpu_arch = "ZEN1";
    else
        actual_cpu_arch = "Unknown";

    cpu_detection_done = true;
}

bool
CpuId::Impl::cpuHasAvx512f()
{
    if (AlcpEnableInstructionSet && cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512f);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512dq()
{
    if (AlcpEnableInstructionSet && cpuid_disable_avx512) {
        return false;
    }

#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512dq);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512bw()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512bw);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512ifma()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512ifma);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512vl()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512vl);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512(Avx512Flags flag)
{
    if (cpuid_disable_avx512) {
        return false;
    }
    switch (flag) {
        case Avx512Flags::AVX512_DQ:
            return cpuHasAvx512dq();
        case Avx512Flags::AVX512_F:
            return cpuHasAvx512f();
        case Avx512Flags::AVX512_BW:
            return cpuHasAvx512bw();
        case Avx512Flags::AVX512_IFMA:
            return cpuHasAvx512ifma();
        case Avx512Flags::AVX512_VL:
            return cpuHasAvx512vl();
        default:
            return false;
    }
}

bool
CpuId::Impl::cpuHasVaes()
{
    if (cpuid_disable_vaes) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::vaes);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAesni()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::aes);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasShani()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::sha_ni);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx2()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx2);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasSse3()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::sse3);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasRdRand()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdrand);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasRdSeed()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdseed);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAdx()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::adx);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasBmi2()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::bmi2);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuIsZen1()
{
    return zen1_flag;
}

bool
CpuId::Impl::cpuIsZen2()
{
    return zen2_flag;
}

bool
CpuId::Impl::cpuIsZen3()
{
    return zen3_flag;
}

bool
CpuId::Impl::cpuIsZen4()
{
    return zen4_flag;
}

bool
CpuId::Impl::cpuIsZen5()
{
    return zen5_flag;
}

bool
CpuId::cpuHasAesni()
{
    return pImpl.get()->cpuHasAesni();
}

bool
CpuId::cpuHasAvx2()
{
    return pImpl.get()->cpuHasAvx2();
}

bool
CpuId::cpuHasSse3()
{
    return pImpl.get()->cpuHasSse3();
}

bool
CpuId::cpuHasAvx512(Avx512Flags flag)
{
    return pImpl.get()->cpuHasAvx512(flag);
}

bool
CpuId::cpuHasAvx512bw()
{
    return pImpl.get()->cpuHasAvx512bw();
}

bool
CpuId::cpuHasAvx512dq()
{
    return pImpl.get()->cpuHasAvx512dq();
}

bool
CpuId::cpuHasAvx512f()
{
    return pImpl.get()->cpuHasAvx512f();
}

bool
CpuId::cpuHasAvx512ifma()
{
    return pImpl.get()->cpuHasAvx512ifma();
}

bool
CpuId::cpuHasAvx512vl()
{
    return pImpl.get()->cpuHasAvx512vl();
}

bool
CpuId::cpuHasShani()
{
    return pImpl.get()->cpuHasShani();
}

bool
CpuId::cpuHasVaes()
{
    return pImpl.get()->cpuHasVaes();
}

bool
CpuId::cpuHasRdRand()
{
    return pImpl.get()->cpuHasRdRand();
}

bool
CpuId::cpuHasBmi2()
{
    return pImpl.get()->cpuHasBmi2();
}

bool
CpuId::cpuHasAdx()
{
    return pImpl.get()->cpuHasAdx();
}

bool
CpuId::cpuHasRdSeed()
{
    return pImpl.get()->cpuHasRdSeed();
}

bool
CpuId::cpuIsZen1()
{
    return pImpl.get()->cpuIsZen1();
}

bool
CpuId::cpuIsZen2()
{
    return pImpl.get()->cpuIsZen2();
}

bool
CpuId::cpuIsZen3()
{
    return pImpl.get()->cpuIsZen3();
}

bool
CpuId::cpuIsZen4()
{
    return pImpl.get()->cpuIsZen4();
}

bool
CpuId::cpuIsZen5()
{
    return pImpl.get()->cpuIsZen5();
}

bool
CpuId::cpuHasAvx512Base()
{
    static bool s_avx512Base = cpuHasAvx512(Avx512Flags::AVX512_F)
                               && cpuHasAvx512(Avx512Flags::AVX512_DQ)
                               && cpuHasAvx512(Avx512Flags::AVX512_BW);
    return s_avx512Base;
}


bool
CpuId::cpuHasAvx512VL()
{
    static bool s_avx512VL = cpuHasAvx512(Avx512Flags::AVX512_F)
                             && cpuHasAvx512(Avx512Flags::AVX512_VL)
                             && cpuHasAvx512(Avx512Flags::AVX512_BW);
    return s_avx512VL;
}

// Per-algorithm architecture level detection
// Each algorithm has different CPU feature requirements

static CpuArchLevel
getArchLevelCipher()
{
    // Cipher (AES modes, ChaCha20): AESNI → VAES → VAES+AVX512
    // Zen4: AVX512 full + VAES (512-bit vectorized)
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)
        && CpuId::cpuHasVaes()) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: VAES (256-bit vectorized) + AVX2
    if (CpuId::cpuHasVaes() && CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // Zen: AESNI (128-bit) + AVX2
    if (CpuId::cpuHasAesni() && CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelRsa()
{
    // RSA: ADX+BMI2 → ADX+BMI2 → ADX+BMI2+IFMA
    // RSA does NOT require VAES, only IFMA for Zen4 optimization
    // Zen4: ADX + AVX2 + BMI2 + IFMA (for optimized modular multiplication)
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()
        && CpuId::cpuHasAvx512ifma()) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: ADX + AVX2 + BMI2 (same as Zen for RSA, but keep hierarchy)
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()) {
        return CpuArchLevel::eZen3;
    }
    // Zen: ADX + AVX2 + BMI2
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelPoly1305()
{
    // Poly1305: Reference → Reference → AVX512Base + IFMA
    // Poly1305 uses AVX512 intrinsics, NOT ADX/BMI2
    // Only Zen4 has optimized kernel, requires AVX512 F+DQ+BW+IFMA
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)) {
        return CpuArchLevel::eZen4;
    }
    // Zen/Zen3 use reference implementation (only need AVX2 as baseline)
    if (CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelX25519()
{
    // X25519 implementations:
    // - Zen4: radix51bit (AVX512 F+DQ+BW+IFMA+VL) - NO ADX/BMI2
    // - Zen3: radix64bit via x25519.cc.inc - requires ADX+BMI2
    // - AVX2/Zen: radix64bit via x25519.cc.inc - requires ADX+BMI2
    // Zen4: Uses AVX512 radix51bit implementation
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: Uses radix64bit which requires ADX+BMI2
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()
        && CpuId::cpuHasVaes()) {
        return CpuArchLevel::eZen3;
    }
    // Zen: Uses radix64bit which requires ADX+BMI2
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelSha2_256()
{
    // SHA256 dispatch is orthogonal to architecture level
    // Primary path: SHA-NI (hardware acceleration) - available on all Zen CPUs
    // Fallback: Reference implementation (AVX2 fallback is disabled)
    if (CpuId::cpuHasShani()) {
        return CpuArchLevel::eZen; // All Zen CPUs have SHA-NI
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelSha2_512()
{
    // SHA512: AVX2+SSE3 → AVX256 → AVX512
    // SHA512 uses AVX2/AVX512 intrinsics, NOT ADX/BMI2
    // Zen4: AVX512 (F, DQ, BW, IFMA, VL)
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: AVX256 (uses zen3 kernel with VAES as differentiator)
    if (CpuId::cpuHasVaes() && CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // Zen: AVX2 + SSE3
    if (CpuId::cpuHasAvx2() && CpuId::cpuHasSse3()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelSha3()
{
    // SHA3: AVX2 → AVX2+VAES → AVX512
    // SHA3 uses AVX2/AVX512 intrinsics, NOT ADX/BMI2
    // Zen4: AVX512 (F, DQ, BW, IFMA, VL)
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: AVX2 + VAES (VAES as differentiator for Zen3 vs Zen)
    if (CpuId::cpuHasVaes() && CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // Zen: AVX2
    if (CpuId::cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

static CpuArchLevel
getArchLevelDefault()
{
    // Default: Original blanket check for backward compatibility
    // Zen4/Zen5: AVX512 full + VAES
    if (CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)
        && CpuId::cpuHasVaes()) {
        return CpuArchLevel::eZen4;
    }
    // Zen3: VAES (256-bit) + ADX + AVX2 + BMI2
    if (CpuId::cpuHasVaes() && CpuId::cpuHasAdx() && CpuId::cpuHasAvx2()
        && CpuId::cpuHasBmi2()) {
        return CpuArchLevel::eZen3;
    }
    // Zen1/Zen2: ADX, AVX2, BMI2, AESNI
    if (CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2()
        && CpuId::cpuHasAesni()) {
        return CpuArchLevel::eZen;
    }
    // Fallback
    return CpuArchLevel::eReference;
}

CpuArchLevel
CpuId::getArchLevel(AlgorithmType algo)
{
    switch (algo) {
        case AlgorithmType::eCipher:
            return getArchLevelCipher();
        case AlgorithmType::eRsa:
            return getArchLevelRsa();
        case AlgorithmType::ePoly1305:
            return getArchLevelPoly1305();
        case AlgorithmType::eX25519:
            return getArchLevelX25519();
        case AlgorithmType::eSha2_256:
            return getArchLevelSha2_256();
        case AlgorithmType::eSha2_512:
            return getArchLevelSha2_512();
        case AlgorithmType::eSha3:
            return getArchLevelSha3();
        case AlgorithmType::eDefault:
        default:
            return getArchLevelDefault();
    }
}

// Per-algorithm cached architecture levels
constexpr int kCacheSize = static_cast<int>(AlgorithmType::eDefault) + 1;
static std::array<CpuArchLevel, kCacheSize> s_cachedArchLevels = {};
static std::array<std::once_flag, kCacheSize> s_initFlags = {};

CpuArchLevel
CpuId::getCachedArchLevel(AlgorithmType algo)
{
    int idx = static_cast<int>(algo);
    // Ensure index is valid (eDefault maps to index 7)
    if (idx < 0 || idx >= kCacheSize) {
        idx = kCacheSize - 1; // Use default (index 7)
    }
    // This line guarantees that the initialization for s_cachedArchLevels[idx]
    // will only happen once for each algorithm, even if multiple threads or the same process
    // call this function multiple times.
    // If the same process calls this code repeatedly, only the first call will execute
    // getArchLevel(algo) and set s_cachedArchLevels[idx].
    // All subsequent calls for the same index will skip the lambda, immediately returning
    // the cached result, ensuring both thread safety and cached efficiency.
    std::call_once(s_initFlags[idx], [idx, algo]() {
        s_cachedArchLevels[idx] = getArchLevel(algo);
    });

    return s_cachedArchLevels[idx];
}

CpuCapability
CpuId::getCapabilities()
{
    CpuCapability caps = CpuCapability::eNone;

    if (cpuHasShani()) {
        caps = caps | CpuCapability::eShaNi;
    }
    if (cpuHasRdRand()) {
        caps = caps | CpuCapability::eRdRand;
    }
    if (cpuHasRdSeed()) {
        caps = caps | CpuCapability::eRdSeed;
    }

    return caps;
}

CpuCapability
CpuId::getCachedCapabilities()
{
    static CpuCapability s_caps = getCapabilities();
    return s_caps;
}

bool
CpuId::hasCapability(CpuCapability cap)
{
    return alcp::utils::hasCapability(getCachedCapabilities(), cap);
}

std::vector<CpuArchLevel>
CpuId::getSupportedArchLevels()
{
    std::vector<CpuArchLevel> levels;
    CpuArchLevel              maxLevel = getCachedArchLevel();

    switch (maxLevel) {
        case CpuArchLevel::eZen4:
            levels.push_back(CpuArchLevel::eZen4);
            [[fallthrough]];
        case CpuArchLevel::eZen3:
            levels.push_back(CpuArchLevel::eZen3);
            [[fallthrough]];
        case CpuArchLevel::eZen:
            levels.push_back(CpuArchLevel::eZen);
            break;
        default:
            levels.push_back(CpuArchLevel::eReference);
            break;
    }
    return levels;
}

} // namespace alcp::utils
