/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include <iostream>

using alcp::utils::Avx512Flags;
using alcp::utils::CpuId;

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define RESET "\033[0m"

void
printBoolMsg(const std::string& msg, bool val)
{
    if (val) {
        std::cout << GREEN;
    } else {
        std::cout << RED;
    }
    std::cout << "\t" << msg << ":";
    if (val) {
        std::cout << "YES";
    } else {
        std::cout << "NO";
    }
    std::cout << RESET << std::endl;
}

void
checkAVX512Support()
{
    std::cout << "======AVX512 FLAGS=======" << std::endl;
    printBoolMsg("AVX512F", CpuId::cpuHasAvx512f());
    printBoolMsg("AVX512BW", CpuId::cpuHasAvx512bw());
    printBoolMsg("AVX512DQ", CpuId::cpuHasAvx512dq());
}

void
checkAVX2Support()
{
    std::cout << "======AVX2 FLAGS=======" << std::endl;
    printBoolMsg("AVX2", CpuId::cpuHasAvx2());
}

void
checkAESSupport()
{
    std::cout << "======AES FLAGS=======" << std::endl;
    printBoolMsg("AESNI", CpuId::cpuHasAesni());
    printBoolMsg("VAES", CpuId::cpuHasVaes());
}

void
checkSHASupport()
{
    std::cout << "======SHA FLAGS=======" << std::endl;
    printBoolMsg("SHANI", CpuId::cpuHasShani());
}

void
checkRandSupport()
{
    std::cout << "======Rand FLAGS=======" << std::endl;
    printBoolMsg("RDRAND", CpuId::cpuHasRdRand());
    printBoolMsg("RDSEED", CpuId::cpuHasRdSeed());
}

void
checkAdxSupport()
{
    std::cout << "======ADX FLAGS=======" << std::endl;
    printBoolMsg("ADX", CpuId::cpuHasAdx());
}

void
checkBmi2Support()
{
    std::cout << "======BMI FLAGS=======" << std::endl;
    printBoolMsg("BMI2", CpuId::cpuHasBmi2());
}

void
checkAMDSupport()
{
    std::cout << "======AMD FLAGS SUPPORT=======" << std::endl;
    printBoolMsg("AMD",  CpuId::cpuIsAmd());
    printBoolMsg("ZEN3", CpuId::cpuIsZen3());
    printBoolMsg("ZEN4", CpuId::cpuIsZen4());
    printBoolMsg("ZEN5", CpuId::cpuIsZen5());
    printBoolMsg("ZEN_BASELINE (ADX+AVX2+BMI2)",
                 CpuId::cpuHasAdx() && CpuId::cpuHasAvx2()
                     && CpuId::cpuHasBmi2());
    printBoolMsg("AVX512_BASE (F+DQ+BW)", CpuId::cpuHasAvx512Base());
    printBoolMsg("AVX512_FULL (F+DQ+BW+IFMA+VL)",
                 CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL));
}

std::string
archLevelToString(alcp::utils::CpuArchLevel archLevel)
{
    using alcp::utils::CpuArchLevel;
    switch (archLevel) {
        case CpuArchLevel::eReference:
            return "Reference";
        case CpuArchLevel::eZen:
            return "Zen/Zen2";
        case CpuArchLevel::eZen3:
            return "Zen3";
        case CpuArchLevel::eZen4:
            return "Zen4/Zen5";
        default:
            return "Unknown";
    }
}

void
checkArchLevel()
{
    using alcp::utils::AlgorithmType;
    using alcp::utils::CpuArchLevel;
    using alcp::utils::CpuCapability;

    std::cout << "======DEFAULT ARCH LEVEL (Backward Compatible)======="
              << std::endl;
    CpuArchLevel defaultArch = CpuId::getCachedArchLevel();
    std::cout << "\tDefault: " << archLevelToString(defaultArch) << std::endl;

    std::cout << "======PER-ALGORITHM ARCH LEVELS=======" << std::endl;
    std::cout << "\tCipher:   "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eCipher))
              << std::endl;
    std::cout << "\tRSA:      "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eRsa))
              << std::endl;
    std::cout << "\tPoly1305: "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::ePoly1305))
              << std::endl;
    std::cout << "\tX25519:   "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eX25519))
              << std::endl;
    std::cout << "\tSHA2-256: "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha2_256))
              << std::endl;
    std::cout << "\tSHA2-512: "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha2_512))
              << std::endl;
    std::cout << "\tSHA3:     "
              << archLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha3))
              << std::endl;

    std::cout << "======SPECIAL CAPABILITIES=======" << std::endl;
    printBoolMsg("SHA-NI", CpuId::hasCapability(CpuCapability::eShaNi));
    printBoolMsg("RDRAND", CpuId::hasCapability(CpuCapability::eRdRand));
    printBoolMsg("RDSEED", CpuId::hasCapability(CpuCapability::eRdSeed));
}

int
main()
{
    checkArchLevel();
    checkAMDSupport();
    checkAESSupport();
    checkSHASupport();
    checkRandSupport();
    checkAVX2Support();
    checkAVX512Support();
    checkAdxSupport();
    checkBmi2Support();

    return 0;
}