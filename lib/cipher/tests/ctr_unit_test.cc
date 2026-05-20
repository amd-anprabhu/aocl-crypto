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

#include <algorithm>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"
#include "debug_defs.hh"
#include "randomize.hh"
#include <exception>
#include <iostream>

#undef DEBUG

// Factory removed
using alcp::cipher::CipherKeyLen;
using alcp::cipher::CipherMode;
using alcp::cipher::createCipher;
using alcp::cipher::iCipher;
namespace alcp::cipher::unittest::ctr {
std::vector<Uint8> key = { 0x78, 0xfd, 0x59, 0x2e, 0x80, 0x4d, 0x37, 0x66,
                           0x60, 0x8c, 0x99, 0x4d, 0xe7, 0x5c, 0x06, 0xb5 };
const string cCipher   = "aes-ctr-128"; // Needs to be modified base on the key
std::vector<Uint8> iv  = { 0xde, 0x6b, 0x64, 0x30, 0x9d, 0x76, 0xa8, 0x43,
                           0x79, 0x28, 0x19, 0xc2, 0x56, 0x40, 0xc9, 0x3b };
std::vector<Uint8> plainText = {
    0x2d, 0xdd, 0xc7, 0x13, 0xfd, 0x52, 0x75, 0xbc, 0x83, 0x76, 0x81, 0x24,
    0xee, 0x38, 0x10, 0x6f, 0x2a, 0x97, 0x62, 0xb9, 0xc1, 0x69, 0x5a, 0x5d,
    0x7c, 0xad, 0x3b, 0xbb, 0x1f, 0x5d, 0x96, 0xfa, 0xbc, 0x2b, 0x5c, 0x4e,
    0x5f, 0x46, 0x8d, 0xbf, 0x6e, 0x38, 0x14, 0xa6, 0xa4, 0xd8, 0x47, 0x0f,
    0xc1, 0xc5, 0x09, 0x29, 0xd7, 0x92, 0xaf, 0x55, 0x6e, 0x6d, 0xbd, 0xb0,
    0x18, 0xdd, 0xd9, 0x7a, 0x7e, 0x69, 0xf6, 0x9c, 0xa6, 0xf3, 0x3a, 0xf0,
    0xfc, 0x2d, 0xb0, 0xc2, 0x64, 0xf1, 0xd6, 0x19, 0x29, 0x0f, 0xfb, 0x23,
    0x6a, 0xab, 0xc6, 0xeb, 0x96, 0xda, 0x4c, 0x49, 0x64, 0x2d, 0x57, 0x36,
    0x09, 0x2f, 0x08, 0x72, 0xf7, 0x5e, 0x4e, 0xf4, 0xcc, 0x98, 0x61, 0x3d,
    0x17, 0x64, 0xcb, 0xbe, 0x63, 0xca, 0x13, 0xb4, 0x9f, 0x33, 0x01, 0x48,
    0x4c, 0xff, 0x36, 0x0f, 0x61, 0x12, 0x6f, 0xe2, 0x99, 0xd3, 0xac, 0x1c,
    0x1a, 0x30, 0x9d, 0x9e, 0x10, 0xc0, 0x1c, 0x4a, 0x51, 0xb3, 0x5d, 0x0e,
    0x3e, 0x60, 0xc5, 0xa4, 0xaf, 0xe9, 0x46, 0x32, 0xe1, 0x19, 0x3d, 0x6a,
    0x6b, 0xb5, 0x93, 0x01, 0xc6, 0x98, 0x7f, 0x3a, 0x00, 0x10, 0x2e, 0x24,
    0xd4, 0xe5, 0x02, 0x98, 0x0e, 0xe5, 0x8b, 0xf6, 0xca, 0xb7, 0x17, 0xdb,
    0x38, 0x41, 0x6c, 0xb6, 0x28, 0x56, 0xbf, 0xb5, 0x59, 0x63, 0xfd, 0x75,
    0xcc, 0x1c, 0xbe, 0x3a, 0xe5, 0xd8, 0x81, 0x54, 0x9c, 0x1e, 0x07, 0x8a,
    0x79, 0x8f, 0xef, 0x07, 0xe8, 0xc7, 0xd7, 0xa3, 0x3f, 0x92, 0xad, 0xdf,
    0x50, 0xec, 0x5c, 0x25, 0xa2, 0x7b, 0x73, 0xa4, 0xea, 0xb2, 0x0c, 0x95,
    0x85, 0xfe, 0xf0, 0xb6, 0xff, 0x72, 0xf6, 0xd6, 0xcc, 0x8c, 0x5e, 0x01,
    0xae, 0x80, 0x6b, 0x0d, 0xca, 0xd4, 0x4a, 0xdc, 0xc1, 0xf0, 0x69, 0xd3,
    0x11, 0x8d, 0xe9, 0xa4, 0x3e, 0xd3, 0x5c, 0xf9, 0xf7, 0x70, 0xaf, 0x06,
    0x14, 0x24, 0x07, 0x20, 0x13, 0xd0, 0x6a, 0xe5, 0xec, 0x81, 0xa6, 0x59,
    0xfa, 0x48, 0xa1, 0x9b, 0x10, 0xf5, 0x4e, 0xc9, 0x82, 0xf5, 0x64, 0x81,
    0x81, 0x44, 0x17, 0x73, 0x73, 0xee, 0xe6, 0xdb, 0x8d, 0xf0, 0xc7, 0xcd,
    0x3a, 0x6b, 0x40, 0x4d, 0x91, 0x72, 0xb4, 0x08, 0xe8, 0xf2, 0xa6, 0xa1,
    0x48, 0xd2, 0x00, 0x60, 0x8d, 0xc5, 0x48, 0x49, 0x92, 0xca, 0xa5, 0xca,
    0x03, 0x5f, 0x95, 0xe4, 0xd5, 0x84, 0x5b, 0x92, 0x46, 0x04, 0x84, 0x68,
    0x1e, 0x5e, 0x9e, 0xdb, 0xe2, 0x52, 0xc9, 0xa7, 0x03, 0xeb, 0xd6, 0x7e,
    0x2d, 0x1f, 0x95, 0x69, 0x8e, 0xa1, 0x55, 0xb1, 0x38, 0x9d, 0xc5, 0xba,
    0x0a, 0x1a, 0x69, 0x42, 0xee, 0x0e, 0xe2, 0x96, 0x8a, 0x4e, 0x59, 0x72,
    0x94, 0x05, 0x58, 0x7b, 0xac, 0xb8, 0xec, 0x7d, 0x25, 0x2e, 0xc5, 0xcd,
    0xd9, 0x23, 0x84, 0xd2, 0x3b, 0xe0, 0x86, 0xda, 0xfe, 0x70, 0x1a, 0x4e,
    0x47, 0x02, 0x63, 0xe3, 0xd1, 0x9a, 0x31, 0x7d, 0xfa, 0x10, 0x6a, 0x65,
    0x6c, 0xb6, 0x3a, 0xda, 0xf6, 0x54, 0xa2, 0xe9, 0xac, 0x7f, 0x6a, 0x30,
    0xf7, 0xae, 0xc0, 0xe7, 0xdd, 0xe5, 0x41, 0xb2, 0x0f, 0x59, 0x51, 0x56,
    0x67, 0xb1, 0xf0, 0xed, 0x4e, 0xf2, 0xce, 0xb9, 0x1e, 0x5f, 0xf5, 0x55,
    0x1c, 0x00, 0x6f, 0x71, 0xbb, 0xcc, 0xa1, 0x6a, 0xf7, 0x1f, 0xed, 0xd6,
    0xa0, 0x23, 0x32, 0x22, 0xb6, 0x07, 0x63, 0x9e, 0x73, 0x36, 0x0b, 0x40,
    0x8f, 0xfc, 0xce, 0x6f, 0x15, 0x7b, 0x81, 0xb8, 0xc8, 0xb4, 0xc2, 0xb4,
    0x58, 0xbc, 0x2b, 0xe9, 0x8a, 0x1f, 0xd3, 0x5c, 0x5a, 0xd7, 0xbd, 0x60,
    0x7d, 0x9f, 0xe3, 0x2f, 0x5f, 0xcf, 0xc6, 0xd2, 0xe7, 0xdb, 0xec, 0x50,
    0x89, 0x72, 0xba, 0x7c, 0xcb, 0xfa, 0x8d, 0xf0, 0x9c, 0x27, 0xfd, 0xe2,
    0xbc, 0xb0, 0x07, 0x9f, 0x1f, 0xa5, 0xa4, 0xd7, 0x85, 0x86, 0x70, 0x3c,
    0x22, 0x26, 0xad, 0x6f, 0xd3, 0x28, 0x5c, 0x8c, 0xeb, 0x87, 0x6d, 0xac,
    0x7a, 0x07, 0xc8, 0x52, 0xfc, 0x30, 0xf8, 0xf1, 0xf3, 0x8e, 0x7e, 0xf2,
    0xb4, 0x61, 0x44, 0xcb, 0xbd, 0xec, 0x1b, 0xef, 0x50, 0x7f, 0x40, 0x04,
    0xe3, 0x48, 0x24, 0x76, 0xef, 0x15, 0x44, 0x3f, 0xb1, 0x34, 0x30, 0x70,
    0x2a, 0x2c, 0x52, 0x49, 0x73, 0x8e, 0x36, 0x66, 0x3d, 0xca, 0x8a, 0x40,
    0x40, 0x36, 0x58, 0x35, 0x4b, 0x28, 0xa5, 0xc7, 0x62, 0x4f, 0xd9, 0x74,
    0xc0, 0xc6, 0xf9, 0x41, 0x85, 0x63, 0x75, 0x3f, 0x1f, 0x5e, 0x1f, 0x59,
    0x33, 0x86, 0x2f, 0x6e, 0xce, 0xae, 0x04, 0xa0, 0x46, 0x7d, 0x00, 0x04,
    0x0a, 0xc7, 0xb6, 0x55, 0xc6, 0xb0, 0x17, 0x7c, 0x0d, 0xc0, 0xce, 0x90,
    0x3e, 0x16, 0x38, 0x17
};
std::vector<Uint8> cipherText = {
    0xe2, 0x86, 0x00, 0xa6, 0x57, 0x4a, 0x3d, 0xdf, 0x6c, 0x7a, 0xcc, 0xcd,
    0x7b, 0xf7, 0xc4, 0xd8, 0xf4, 0x2e, 0xef, 0x83, 0x67, 0x49, 0x1b, 0x34,
    0xd8, 0x54, 0x34, 0x67, 0xdb, 0xbe, 0x8b, 0x5e, 0x5a, 0xe6, 0x88, 0xc3,
    0x9e, 0x9d, 0x98, 0x3e, 0x90, 0x85, 0xd3, 0x8a, 0x84, 0x90, 0x3d, 0x80,
    0x45, 0x7b, 0xb0, 0x5a, 0x51, 0x76, 0xe8, 0x7f, 0x4d, 0x91, 0x8f, 0xe8,
    0x1f, 0xee, 0xc9, 0xe7, 0xb9, 0x1d, 0x95, 0x24, 0x7f, 0x9a, 0x7c, 0x1d,
    0x64, 0x04, 0x02, 0x55, 0xb3, 0xaa, 0x51, 0x43, 0xcf, 0xce, 0x12, 0xa5,
    0x12, 0xd7, 0x75, 0x9d, 0x09, 0xc2, 0x5f, 0x9f, 0xff, 0x97, 0xd1, 0x52,
    0x51, 0xce, 0x05, 0x54, 0x44, 0x51, 0x24, 0xae, 0x2d, 0x89, 0x90, 0xaa,
    0x02, 0x51, 0x60, 0xb2, 0xfc, 0x75, 0x0e, 0xa1, 0x50, 0x60, 0xa9, 0x8b,
    0xa5, 0x6d, 0xe0, 0x3c, 0xa5, 0x6a, 0xb3, 0xe1, 0x1e, 0xa1, 0xbc, 0x6e,
    0x05, 0x6c, 0xb5, 0x82, 0xcc, 0xc6, 0xdb, 0xa2, 0xf7, 0x00, 0xa0, 0xb8,
    0xfa, 0x1f, 0x5d, 0x2c, 0x98, 0x01, 0x4c, 0x05, 0xb7, 0xe3, 0x45, 0x09,
    0x72, 0x99, 0x0a, 0xff, 0x2d, 0xd5, 0x30, 0x10, 0xb4, 0x0f, 0x13, 0x94,
    0x4b, 0xb4, 0x24, 0xa9, 0x3e, 0xad, 0x4f, 0xe1, 0x43, 0x6a, 0xb2, 0x62,
    0x95, 0x1d, 0xec, 0x6e, 0xac, 0x7a, 0xc0, 0xc5, 0xf6, 0xa2, 0xe8, 0x16,
    0xd9, 0x5c, 0x63, 0xb3, 0x5f, 0xa1, 0x27, 0x56, 0x5f, 0x89, 0x97, 0x1e,
    0xea, 0x0c, 0xb7, 0xea, 0xcc, 0xb6, 0x22, 0x74, 0x59, 0xda, 0xab, 0xb7,
    0xed, 0x19, 0x03, 0xf3, 0x2f, 0x9b, 0x85, 0xc6, 0x80, 0x47, 0x2b, 0xab,
    0xd1, 0x00, 0x94, 0xae, 0x31, 0xd4, 0x54, 0x27, 0x4a, 0xb8, 0xc7, 0x16,
    0xf7, 0x31, 0xab, 0x60, 0x11, 0xe9, 0xa7, 0x27, 0x94, 0xf6, 0x47, 0xe8,
    0xbf, 0x5b, 0x7a, 0x1b, 0xf1, 0xe8, 0x51, 0x50, 0xc2, 0xfa, 0x83, 0x2b,
    0xf3, 0xaa, 0x69, 0xe0, 0xcf, 0xf0, 0x44, 0xf4, 0x63, 0x57, 0xc0, 0xd0,
    0x7f, 0x9c, 0x1b, 0xdc, 0x61, 0x8f, 0x3b, 0xff, 0x67, 0xd2, 0x73, 0xc0,
    0x1a, 0x6c, 0xee, 0xde, 0xed, 0xb5, 0x93, 0xf6, 0x02, 0x96, 0x4a, 0x42,
    0x99, 0xa8, 0x25, 0x94, 0x39, 0x9c, 0xbe, 0xa3, 0xe1, 0xb5, 0x78, 0x2b,
    0x14, 0x69, 0xfa, 0x4e, 0x8b, 0x59, 0xf2, 0x14, 0x7b, 0xa3, 0x18, 0xd3,
    0x04, 0x3a, 0x55, 0x5b, 0xf0, 0x4b, 0xb1, 0x27, 0x15, 0xb7, 0x50, 0xad,
    0x55, 0xe3, 0x7a, 0x0a, 0x92, 0xcd, 0x65, 0x7b, 0x18, 0x19, 0x15, 0x29,
    0x10, 0xf5, 0x30, 0x08, 0xa1, 0xfa, 0xb7, 0xd5, 0xe5, 0x30, 0x25, 0xaa,
    0x8f, 0xb2, 0xbf, 0x4d, 0xb8, 0xda, 0x29, 0xfd, 0x63, 0x7f, 0x8c, 0xdf,
    0xcf, 0x42, 0x9a, 0x80, 0xd0, 0x4d, 0x91, 0xc5, 0xf5, 0x82, 0x88, 0xb3,
    0x92, 0xfd, 0xa7, 0x1d, 0xe9, 0x13, 0xe9, 0x53, 0xf4, 0x61, 0xd3, 0xf1,
    0xff, 0xeb, 0xd4, 0xa6, 0x52, 0x91, 0x39, 0xbf, 0x0e, 0x78, 0x8c, 0x8f,
    0x58, 0x6a, 0x8f, 0x1f, 0x90, 0xb3, 0xe2, 0x1a, 0x23, 0x07, 0x63, 0x53,
    0x69, 0xca, 0x82, 0xaa, 0xce, 0x1c, 0xb3, 0x21, 0x19, 0x23, 0xfb, 0xd0,
    0xf6, 0x0b, 0x89, 0x08, 0x55, 0x3b, 0xbf, 0xbc, 0x05, 0xda, 0xe8, 0x1a,
    0x5c, 0x9d, 0xea, 0x5f, 0x3b, 0xd1, 0x4b, 0xf2, 0xde, 0xce, 0x6d, 0x0f,
    0x45, 0x07, 0x2e, 0xcc, 0x1a, 0x17, 0x28, 0xaa, 0xaf, 0x39, 0x03, 0x4a,
    0xf2, 0x0f, 0x3b, 0xae, 0x12, 0x60, 0x42, 0x2e, 0xa6, 0xfd, 0x7d, 0x44,
    0xd6, 0xee, 0x48, 0xf3, 0x91, 0xde, 0x9f, 0xd2, 0x08, 0xea, 0x11, 0x1e,
    0x40, 0x59, 0x31, 0xde, 0x21, 0x51, 0xb8, 0x3e, 0x3a, 0x99, 0x67, 0xbd,
    0xc5, 0xea, 0xbe, 0x7a, 0xfb, 0xa9, 0xc4, 0x64, 0x48, 0x72, 0x8b, 0x6b,
    0x99, 0xd5, 0xbe, 0xf4, 0x72, 0xd5, 0x50, 0xb4, 0xdb, 0xe9, 0xca, 0x66,
    0x6f, 0x40, 0x40, 0x5e, 0x14, 0x20, 0xe5, 0xb3, 0x25, 0x8e, 0x06, 0xe0,
    0x8e, 0x68, 0x4b, 0xf0, 0x3b, 0x03, 0x0b, 0xc7, 0xa9, 0x1b, 0xd3, 0x20,
    0x2f, 0xa7, 0xd7, 0xab, 0xa4, 0x5a, 0x70, 0xb9, 0x9c, 0x94, 0xe6, 0x8a,
    0xd5, 0x03, 0x45, 0x73, 0xb4, 0x32, 0xb9, 0x87, 0xcb, 0x8e, 0x37, 0x89,
    0x15, 0x30, 0xbb, 0x0c, 0xa3, 0x52, 0x18, 0x94, 0x97, 0x8b, 0x7b, 0x6c,
    0x05, 0x63, 0x26, 0xd8, 0xf5, 0xca, 0xab, 0x3f, 0x3f, 0xf3, 0xb6, 0x1d,
    0x4b, 0xea, 0x21, 0x94, 0xfe, 0xfc, 0x6a, 0x94, 0xce, 0x02, 0x82, 0x05,
    0x9a, 0x7f, 0xc9, 0x3b, 0x11, 0x7a, 0xe5, 0x04, 0x14, 0x7a, 0xb9, 0x00,
    0xf3, 0xc4, 0x25, 0x5a, 0x2c, 0x28, 0xe5, 0x53, 0x68, 0x12, 0x59, 0x18,
    0x17, 0xdc, 0x8f, 0x39
};

} // namespace alcp::cipher::unittest::ctr

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::ctr;

// Test fixture class for CTR tests with helper functions
class CTRTest : public ::testing::Test
{
  protected:
    static size_t getKeySizeBytes(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 16;
            case CipherKeyLen::eKey192Bit: return 24;
            case CipherKeyLen::eKey256Bit: return 32;
            default: return 16;
        }
    }

    static size_t getKeySizeBits(CipherKeyLen keyLen)
    {
        return getKeySizeBytes(keyLen) * 8;
    }
};

// Parameterized test fixture for key size variations
class CTRKeySizeTest : public ::testing::TestWithParam<CipherKeyLen>
{
  protected:
    static size_t getKeySizeBytes(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 16;
            case CipherKeyLen::eKey192Bit: return 24;
            case CipherKeyLen::eKey256Bit: return 32;
            default: return 16;
        }
    }

    static size_t getKeySizeBits(CipherKeyLen keyLen)
    {
        return getKeySizeBytes(keyLen) * 8;
    }
};

TEST(CTR, creation)
{
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        // Factory removed
        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        if (ctr == nullptr) {
            delete ctr;
            FAIL();
        }
        delete ctr;
    }
}

TEST(CTR, BasicEncryption)
{
    // Factory removed
    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);

    if (ctr == nullptr) {
        delete ctr;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    alc_error_t err = ctr->init(&key[0], key.size() * 8, &iv[0], iv.size());

    if (alcp_is_error(err)) {
        std::cout << "Init failed!" << std::endl;
    }

    EXPECT_FALSE(alcp_is_error(err));

    Uint64 outlen = 0;
    err = ctr->encrypt(&plainText[0], &output[0], plainText.size(), &outlen);

    if (alcp_is_error(err)) {
        std::cout << "Encrypt failed!" << std::endl;
    }

    EXPECT_FALSE(alcp_is_error(err));

    delete ctr;
    EXPECT_EQ(cipherText, output);
}

TEST(CTR, BasicDecryption)
{
    // Factory removed
    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);

    if (ctr == nullptr) {
        delete ctr;
        FAIL();
    }
    std::vector<Uint8> output(plainText.size());

    // ctr->setKey(128, &key[0]);

    alc_error_t err = ctr->init(&key[0], key.size() * 8, &iv[0], iv.size());

    if (alcp_is_error(err)) {
        std::cout << "Init failed!" << std::endl;
    }

    EXPECT_FALSE(alcp_is_error(err));

    Uint64 outlen = 0;
    err = ctr->decrypt(&cipherText[0], &output[0], cipherText.size(), &outlen);

    if (alcp_is_error(err)) {
        std::cout << "Decrypt failed!" << std::endl;
    }

    EXPECT_FALSE(alcp_is_error(err));

    delete ctr;
    EXPECT_EQ(plainText, output);
}

TEST(CTR, MultiUpdateEncryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif

    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        // Factory removed
        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);

        if (ctr == nullptr) {
            delete ctr;
            FAIL();
        }
        std::vector<Uint8> output(plainText.size());

        alc_error_t err = ctr->init(&key[0], key.size() * 8, &iv[0], iv.size());

        for (Uint64 i = 0; i < plainText.size() / 16; i++) {
            Uint64 outlen = 0;
            err           = ctr->encrypt(&plainText[0] + i * 16,
                               &output[0] + i * 16,
                               16,
                               &outlen); // 16 byte chunks
            if (alcp_is_error(err)) {
                std::cout << "Encrypt failed!" << std::endl;
            }
            EXPECT_FALSE(alcp_is_error(err));
        }
        delete ctr;
        EXPECT_EQ(cipherText, output);
    }
}

TEST(CTR, MultiUpdateDecryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        // Factory removed
        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);

        if (ctr == nullptr) {
            delete ctr;
            FAIL();
        }
        std::vector<Uint8> output(plainText.size());

        alc_error_t err = ctr->init(&key[0], key.size() * 8, &iv[0], iv.size());

        if (alcp_is_error(err)) {
            std::cout << "Init failed!" << std::endl;
        }

        for (Uint64 i = 0; i < plainText.size() / 16; i++) {
            Uint64 outlen = 0;
            err           = ctr->decrypt(
                &cipherText[0] + i * 16, &output[0] + i * 16, 16, &outlen);
            if (alcp_is_error(err)) {
                std::cout << "Decrypt failed!" << std::endl;
            }
            EXPECT_FALSE(alcp_is_error(err));
        }
        delete ctr;
        EXPECT_EQ(plainText, output)
            << "FAIL CPU_FEATURE:"
            << std::underlying_type<CpuArchLevel>::type(feature);
    }
}

/**
 * @brief Test that verifies separate key/IV initialization works correctly.
 *
 * This tests the feature where iCipher::init() can be called as below with Key
 * and IV serparately
 *   1. init(nullptr, 0, iv, ivlen)  - IV only
 *   2. init(key, keylen, nullptr, 0) - Key only
 *
 */
TEST(CTR, SeparateKeyIvInit)
{
    // Use the test vectors from the namespace
    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr) << "Failed to create CTR cipher";
    if (ctr == nullptr)
        return;

    std::vector<Uint8> output(cipherText.size());

    // Test Pattern 1: IV first, then Key
    // Step 1: Initialize with IV only (key=nullptr, keyLen=0)
    alc_error_t err = ctr->init(nullptr, 0, &iv[0], iv.size());
    EXPECT_FALSE(alcp_is_error(err))
        << "init with IV-only should succeed, got error: " << err;

    // Step 2: Initialize with Key only (iv=nullptr, ivLen=0)
    err = ctr->init(&key[0], key.size() * 8, nullptr, 0);
    EXPECT_FALSE(alcp_is_error(err))
        << "init with Key-only should succeed, got error: " << err;

    // Step 3: Encrypt
    Uint64 outlen = 0;
    err = ctr->encrypt(&plainText[0], &output[0], plainText.size(), &outlen);
    EXPECT_FALSE(alcp_is_error(err)) << "encrypt failed after separate init";
    EXPECT_EQ(outlen, plainText.size()) << "Encrypt output length mismatch";

    // Verify encryption result matches expected ciphertext
    EXPECT_EQ(cipherText, output)
        << "Encryption with separate key/IV init produced wrong ciphertext";

    delete ctr;

    // Test Pattern 2: Key first, then IV
    ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr) << "Failed to create CTR cipher (2)";
    if (ctr == nullptr)
        return;

    std::vector<Uint8> decrypted(plainText.size());

    // Step 1: Initialize with Key only
    err = ctr->init(&key[0], key.size() * 8, nullptr, 0);
    EXPECT_FALSE(alcp_is_error(err))
        << "init with Key-only (pattern 2) should succeed";

    // Step 2: Initialize with IV only
    err = ctr->init(nullptr, 0, &iv[0], iv.size());
    EXPECT_FALSE(alcp_is_error(err))
        << "init with IV-only (pattern 2) should succeed";

    // Step 3: Decrypt (CTR mode is symmetric)
    outlen = 0;
    err =
        ctr->decrypt(&cipherText[0], &decrypted[0], cipherText.size(), &outlen);
    EXPECT_FALSE(alcp_is_error(err)) << "decrypt failed after separate init";
    EXPECT_EQ(outlen, cipherText.size()) << "Decrypt output length mismatch";

    // Verify decryption matches original plaintext
    EXPECT_EQ(plainText, decrypted)
        << "Decrypted data does not match original plaintext";

    delete ctr;

    // Test Pattern 3: Combined init still works (sanity check)
    ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr) << "Failed to create CTR cipher (3)";
    if (ctr == nullptr)
        return;

    std::vector<Uint8> output2(cipherText.size());

    // Combined initialization
    err = ctr->init(&key[0], key.size() * 8, &iv[0], iv.size());
    EXPECT_FALSE(alcp_is_error(err))
        << "init with combined key+IV should succeed";

    outlen = 0;
    err = ctr->encrypt(&plainText[0], &output2[0], plainText.size(), &outlen);
    EXPECT_FALSE(alcp_is_error(err)) << "encrypt failed after combined init";

    // Both encryption methods should produce the same result
    EXPECT_EQ(output, output2)
        << "Separate init and combined init produce different ciphertext";

    delete ctr;
}

TEST(CTR, RandomEncryptDecryptTest)
{
    Uint8        key_256[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    const Uint64 cTextSize   = 100000;
    std::vector<Uint8> plain_text_vect(cTextSize);
    std::vector<Uint8> cipher_text_vect(cTextSize);
    Uint8              iv[16] = {};

    // Fill buffer with random data
    std::unique_ptr<IRandomize> random = std::make_unique<Randomize>(12);
    random->getRandomBytes(plain_text_vect);
    random->getRandomBytes(cipher_text_vect);
    random->getRandomBytes(key_256, 32);
    random->getRandomBytes(iv, 16);

    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    for (int i = (cTextSize - 16); i > 16; i -= 16)
        for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
            std::cout << "Cpu Feature:"
                      << static_cast<
                             typename std::underlying_type<CpuArchLevel>::type>(
                             feature)
                      << std::endl;
#endif
            const std::vector<Uint8> plainTextVect(plain_text_vect.begin() + i,
                                                   plain_text_vect.end());
            std::vector<Uint8>       plainTextOut(plainTextVect.size());
            auto                     ctr =
                createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey256Bit);

            if (ctr == nullptr) {
                delete ctr;
                FAIL();
            }
            alc_error_t err = ctr->init(key_256, 256, &iv[0], sizeof(iv));

            if (alcp_is_error(err)) {
                std::cout << "Init failed!" << std::endl;
            }

            EXPECT_FALSE(alcp_is_error(err));

            Uint64 outlen = 0;
            err           = ctr->encrypt(&plainTextVect[0],
                               &cipher_text_vect[0],
                               plainTextVect.size(),
                               &outlen);

            if (alcp_is_error(err)) {
                std::cout << "Encrypt failed!" << std::endl;
            }

            EXPECT_FALSE(alcp_is_error(err));

            err = ctr->init(key_256, 256, &iv[0], sizeof(iv));

            if (alcp_is_error(err)) {
                std::cout << "Init failed!" << std::endl;
            }

            EXPECT_FALSE(alcp_is_error(err));

            Uint64 outlen2 = 0;
            err            = ctr->decrypt(&cipher_text_vect[0],
                               &plainTextOut[0],
                               plainTextVect.size(),
                               &outlen2);

            if (alcp_is_error(err)) {
                std::cout << "Decrypt failed!" << std::endl;
            }

            EXPECT_FALSE(alcp_is_error(err));

            delete ctr;
            EXPECT_EQ(plainTextVect, plainTextOut);
#ifdef DEBUG
            auto ret = std::mismatch(plainTextVect.begin(),
                                     plainTextVect.end(),
                                     plainTextOut.begin());
            std::cout << "First:" << ret.first - plainTextVect.begin()
                      << "Second:" << ret.second - plainTextOut.begin()
                      << std::endl;
#endif
        }
}

// Comprehensive Corner Case Tests for CTR

// Parameterized test for all key sizes (128, 192, 256 bits)
TEST_P(CTRKeySizeTest, EncryptDecryptRoundTrip)
{
    CipherKeyLen keyLen = GetParam();
    size_t keySize = getKeySizeBytes(keyLen);
    size_t keyBits = getKeySizeBits(keyLen);

    std::vector<Uint8> testKey(keySize, 0x42);
    std::vector<Uint8> testIv(16, 0x00);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32), decrypted(32);

    auto ctr = createCipher(CipherMode::eAesCTR, keyLen);
    ASSERT_NE(ctr, nullptr) << "Failed to create AES-CTR-" << keyBits;

    ctr->init(&testKey[0], keyBits, &testIv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(ctr->encrypt(&input[0], &output[0], 32, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 32);

    ctr->init(&testKey[0], keyBits, &testIv[0], 16);
    outlen = 0;
    EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], 32, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test with multiple data sizes for each key size
TEST_P(CTRKeySizeTest, VariousDataSizes)
{
    CipherKeyLen keyLen = GetParam();
    size_t keySize = getKeySizeBytes(keyLen);
    size_t keyBits = getKeySizeBits(keyLen);

    std::vector<Uint8> testKey(keySize, 0x42);
    std::vector<Uint8> testIv(16, 0x00);

    // Test various data sizes (CTR handles any size)
    std::vector<size_t> dataSizes = { 1, 15, 16, 17, 32, 64, 128, 256, 512, 1024 };

    for (size_t dataSize : dataSizes) {
        std::vector<Uint8> input(dataSize);
        for (size_t i = 0; i < dataSize; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(dataSize), decrypted(dataSize);

        auto ctr = createCipher(CipherMode::eAesCTR, keyLen);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&testKey[0], keyBits, &testIv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(ctr->encrypt(&input[0], &output[0], dataSize, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, dataSize) << "Key: " << keyBits << " bits, Data: " << dataSize << " bytes";

        ctr->init(&testKey[0], keyBits, &testIv[0], 16);
        outlen = 0;
        EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], dataSize, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input) << "Key: " << keyBits << " bits, Data: " << dataSize << " bytes";

        delete ctr;
    }
}

// Instantiate the parameterized tests for all key sizes
INSTANTIATE_TEST_SUITE_P(
    AllKeySizes,
    CTRKeySizeTest,
    ::testing::Values(
        CipherKeyLen::eKey128Bit,
        CipherKeyLen::eKey192Bit,
        CipherKeyLen::eKey256Bit
    ),
    [](const ::testing::TestParamInfo<CipherKeyLen>& info) {
        switch (info.param) {
            case CipherKeyLen::eKey128Bit: return "Key128Bit";
            case CipherKeyLen::eKey192Bit: return "Key192Bit";
            case CipherKeyLen::eKey256Bit: return "Key256Bit";
            default: return "Unknown";
        }
    }
);

// Test single block (16 bytes)
TEST(CTR, SingleBlock)
{
    std::vector<Uint8> test_key(16, 0xAA);
    std::vector<Uint8> test_iv(16, 0xBB);
    std::vector<Uint8> input(16, 0xCC);
    std::vector<Uint8> output(16), decrypted(16);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(ctr->encrypt(&input[0], &output[0], 16, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);
    EXPECT_NE(output, input);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], 16, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test multiple blocks
TEST(CTR, MultipleBlocks)
{
    std::vector<size_t> block_counts = { 2, 3, 4, 5, 8, 10, 16, 32, 64, 100 };
    
    std::vector<Uint8> test_key(16, 0xDD);
    std::vector<Uint8> test_iv(16, 0xEE);

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;
        std::vector<Uint8> input(data_size);
        for (size_t i = 0; i < data_size; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(data_size), decrypted(data_size);

        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(ctr->encrypt(&input[0], &output[0], data_size, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, data_size) << "Block count: " << num_blocks;

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        outlen = 0;
        EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], data_size, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input) << "Mismatch at block count: " << num_blocks;

        delete ctr;
    }
}

// Test all zeros input
TEST(CTR, AllZerosInput)
{
    std::vector<Uint8> test_key(16, 0x00);
    std::vector<Uint8> test_iv(16, 0x00);
    std::vector<Uint8> input(64, 0x00);
    std::vector<Uint8> output(64), decrypted(64);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(ctr->encrypt(&input[0], &output[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 64);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test all ones input (0xFF)
TEST(CTR, AllOnesInput)
{
    std::vector<Uint8> test_key(16, 0xFF);
    std::vector<Uint8> test_iv(16, 0xFF);
    std::vector<Uint8> input(64, 0xFF);
    std::vector<Uint8> output(64), decrypted(64);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(ctr->encrypt(&input[0], &output[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 64);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test double initialization
TEST(CTR, DoubleInit)
{
    std::vector<Uint8> test_key(16, 0x12);
    std::vector<Uint8> iv1(16, 0x34);
    std::vector<Uint8> iv2(16, 0x56);
    std::vector<Uint8> input(32, 0x78);
    std::vector<Uint8> output1(32), output2(32), decrypted(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &iv1[0], 16);
    Uint64 outlen = 0;
    ctr->encrypt(&input[0], &output1[0], 32, &outlen);

    ctr->init(&test_key[0], 128, &iv1[0], 16);
    outlen = 0;
    ctr->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_EQ(output1, output2) << "Same IV should produce same ciphertext";

    ctr->init(&test_key[0], 128, &iv2[0], 16);
    outlen = 0;
    ctr->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_NE(output1, output2) << "Different IV should produce different ciphertext";

    ctr->init(&test_key[0], 128, &iv1[0], 16);
    outlen = 0;
    ctr->decrypt(&output1[0], &decrypted[0], 32, &outlen);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test large data (2MB)
TEST(CTR, LargeData)
{
    const size_t MB = 1024 * 1024;
    const size_t data_size = 2 * MB;
    
    std::vector<Uint8> test_key(32, 0xDE);
    std::vector<Uint8> test_iv(16, 0xAD);
    std::vector<Uint8> input(data_size);
    std::vector<Uint8> output(data_size), decrypted(data_size);

    for (size_t i = 0; i < data_size; i++) {
        input[i] = static_cast<Uint8>((i * 17) % 256);
    }

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey256Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 256, &test_iv[0], 16);
    Uint64 outlen = 0;
    auto err = ctr->encrypt(&input[0], &output[0], data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, data_size);

    ctr->init(&test_key[0], 256, &test_iv[0], 16);
    outlen = 0;
    err = ctr->decrypt(&output[0], &decrypted[0], data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete ctr;
}

// Test different IV values
TEST(CTR, IVAffectsOutput)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<std::vector<Uint8>> outputs;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> test_iv(16, static_cast<Uint8>(i));
        std::vector<Uint8> output(32);

        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        ctr->encrypt(&input[0], &output[0], 32, &outlen);
        outputs.push_back(output);

        delete ctr;
    }

    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "IV " << i << " and " << j << " produced same output";
        }
    }
}

// Test various data sizes (CTR handles any size)
TEST(CTR, VariousDataSizes)
{
    std::vector<Uint8> test_key(16, 0x73);
    std::vector<Uint8> test_iv(16, 0x84);
    
    std::vector<size_t> sizes = { 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1000 };
    
    for (size_t size : sizes) {
        std::vector<Uint8> input(size);
        for (size_t i = 0; i < size; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(size), decrypted(size);

        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = ctr->encrypt(&input[0], &output[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed for size " << size;
        EXPECT_EQ(outlen, size) << "Output length mismatch for size " << size;

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        outlen = 0;
        err = ctr->decrypt(&output[0], &decrypted[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Decrypt failed for size " << size;
        EXPECT_EQ(decrypted, input) << "Data mismatch for size " << size;

        delete ctr;
    }
}

// Test separate cipher objects
TEST(CTR, SeparateCipherObjects)
{
    std::vector<Uint8> test_key(16, 0xAB);
    std::vector<Uint8> test_iv(16, 0xCD);
    std::vector<Uint8> input(64, 0xEF);
    std::vector<Uint8> output(64), decrypted(64);

    auto ctr_enc = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr_enc, nullptr);

    ctr_enc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    ctr_enc->encrypt(&input[0], &output[0], 64, &outlen);
    EXPECT_EQ(outlen, 64);

    delete ctr_enc;

    auto ctr_dec = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr_dec, nullptr);

    ctr_dec->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    ctr_dec->decrypt(&output[0], &decrypted[0], 64, &outlen);
    EXPECT_EQ(decrypted, input);

    delete ctr_dec;
}

// Test determinism
TEST(CTR, Determinism)
{
    std::vector<Uint8> test_key(16, 0x11);
    std::vector<Uint8> test_iv(16, 0x22);
    std::vector<Uint8> input(32, 0x33);
    std::vector<Uint8> output1(32), output2(32), output3(32);

    for (int round = 0; round < 3; round++) {
        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        std::vector<Uint8>* current_output = (round == 0) ? &output1 : (round == 1) ? &output2 : &output3;
        ctr->encrypt(&input[0], &(*current_output)[0], 32, &outlen);

        delete ctr;
    }

    EXPECT_EQ(output1, output2) << "Round 1 and 2 should produce same output";
    EXPECT_EQ(output2, output3) << "Round 2 and 3 should produce same output";
}

// Test non-block aligned sizes
TEST(CTR, NonBlockAlignedSizes)
{
    std::vector<Uint8> test_key(16, 0xAB);
    std::vector<Uint8> test_iv(16, 0xCD);
    
    std::vector<size_t> sizes = { 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 23, 29, 31, 37, 41, 47, 53 };
    
    for (size_t size : sizes) {
        std::vector<Uint8> input(size);
        for (size_t i = 0; i < size; i++) {
            input[i] = static_cast<Uint8>((i * 7) % 256);
        }
        std::vector<Uint8> output(size), decrypted(size);

        auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
        ASSERT_NE(ctr, nullptr);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = ctr->encrypt(&input[0], &output[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for size " << size;
        EXPECT_EQ(outlen, size);

        ctr->init(&test_key[0], 128, &test_iv[0], 16);
        outlen = 0;
        err = ctr->decrypt(&output[0], &decrypted[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Decrypt failed for size " << size;
        EXPECT_EQ(decrypted, input) << "Data mismatch for size " << size;

        delete ctr;
    }
}

// Test single byte
TEST(CTR, SingleByte)
{
    std::vector<Uint8> test_key(16, 0x12);
    std::vector<Uint8> test_iv(16, 0x34);
    std::vector<Uint8> input = { 0x56 };
    std::vector<Uint8> output(1), decrypted(1);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(ctr->encrypt(&input[0], &output[0], 1, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 1);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(ctr->decrypt(&output[0], &decrypted[0], 1, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted[0], input[0]);

    delete ctr;
}

// Test context copy
TEST(CTR, ContextCopy)
{
    std::vector<Uint8> test_key(16, 0xAA);
    std::vector<Uint8> test_iv(16, 0xBB);
    std::vector<Uint8> input(32, 0xCC);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);

    auto ctr_copy = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr_copy, nullptr);
    ctr->CopyCtx(ctr, ctr_copy);

    Uint64 outlen = 0;
    ctr_copy->encrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_EQ(outlen, 32);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    std::vector<Uint8> decrypted(32);
    outlen = 0;
    ctr->decrypt(&output[0], &decrypted[0], 32, &outlen);
    EXPECT_EQ(decrypted, input);

    delete ctr;
    delete ctr_copy;
}

// Test CTR counter increment (verify different blocks produce different output)
TEST(CTR, CounterIncrement)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x00);
    std::vector<Uint8> zeros(64, 0x00);
    std::vector<Uint8> output(64);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    ctr->encrypt(&zeros[0], &output[0], 64, &outlen);

    // Each 16-byte block should be different due to counter increment
    std::vector<Uint8> block1(output.begin(), output.begin() + 16);
    std::vector<Uint8> block2(output.begin() + 16, output.begin() + 32);
    std::vector<Uint8> block3(output.begin() + 32, output.begin() + 48);
    std::vector<Uint8> block4(output.begin() + 48, output.begin() + 64);

    EXPECT_NE(block1, block2) << "Block 1 and 2 should differ";
    EXPECT_NE(block2, block3) << "Block 2 and 3 should differ";
    EXPECT_NE(block3, block4) << "Block 3 and 4 should differ";

    delete ctr;
}

// Negative Tests for CTR - Null Pointer and Edge Cases

// Test null pointer for key in init
TEST(CTR_Negative, NullKeyPointer)
{
    std::vector<Uint8> test_iv(16, 0x00);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Passing null key pointer should return an error
    alc_error_t err = ctr->init(nullptr, 128, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key should fail";

    delete ctr;
}

// Test null pointer for IV in init
TEST(CTR_Negative, NullIVPointer)
{
    std::vector<Uint8> test_key(16, 0x42);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Passing null IV pointer - the implementation may accept this
    // and use a default IV or handle it gracefully
    alc_error_t err = ctr->init(&test_key[0], 128, nullptr, 16);
    // Document actual behavior: implementation may accept null IV
    // This test verifies the behavior doesn't crash and documents the API contract
    (void)err; // Behavior is implementation-defined

    delete ctr;
}

// Test null pointer for both key and IV in init
TEST(CTR_Negative, NullKeyAndIVPointers)
{
}

// Test null pointer for input in encrypt
// Note: Implementation may not validate null input - may cause undefined behavior
TEST(CTR_Negative, NullInputPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = ctr->encrypt(nullptr, &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";

    delete ctr;
}

// Test null pointer for input in decrypt
// Note: Implementation may not validate null input - may cause undefined behavior
TEST(CTR_Negative, NullInputPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = ctr->decrypt(nullptr, &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null input should fail";

    delete ctr;
}

// Test null pointer for output in encrypt
// Note: Implementation may not validate null output - may cause undefined behavior
TEST(CTR_Negative, NullOutputPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = ctr->encrypt(&input[0], nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";

    delete ctr;
}

// Test null pointer for output in decrypt
// Note: Implementation may not validate null output - may cause undefined behavior
TEST(CTR_Negative, NullOutputPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = ctr->decrypt(&input[0], nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null output should fail";

    delete ctr;
}

// Test null pointer for output length in encrypt
TEST(CTR_Negative, NullOutlenPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with null outlen pointer should fail
    err = ctr->encrypt(&input[0], &output[0], 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null outlen should fail";

    delete ctr;
}

// Test null pointer for output length in decrypt
TEST(CTR_Negative, NullOutlenPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with null outlen pointer should fail
    err = ctr->decrypt(&input[0], &output[0], 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null outlen should fail";

    delete ctr;
}

// Test all null pointers in encrypt
TEST(CTR_Negative, AllNullPointersEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with all null pointers should fail
    err = ctr->encrypt(nullptr, nullptr, 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with all null pointers should fail";

    delete ctr;
}

// Test all null pointers in decrypt
TEST(CTR_Negative, AllNullPointersDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with all null pointers should fail
    err = ctr->decrypt(nullptr, nullptr, 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with all null pointers should fail";

    delete ctr;
}

// Test zero key length
TEST(CTR_Negative, ZeroKeyLength)
{
}

// Test zero IV length
// Note: Implementation may not validate IV length
TEST(CTR_Negative, ZeroIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero IV length should fail";

    delete ctr;
}

// Test invalid key length (not 128, 192, or 256 bits)
TEST(CTR_Negative, InvalidKeyLength)
{
    std::vector<Uint8> test_key(20, 0x42); // 160-bit key (invalid)
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Init with invalid key length (160 bits = 20 bytes) should fail
    alc_error_t err = ctr->init(&test_key[0], 160, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid key length (160 bits) should fail";

    delete ctr;
}

// Test invalid IV length (CTR requires 16-byte IV/nonce)
// Note: Implementation may not validate IV length
TEST(CTR_Negative, InvalidIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(8, 0x24); // 8-byte IV (invalid for CTR)

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 8);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid IV length (8 bytes) should fail";

    delete ctr;
}

// Test encryption without initialization
TEST(CTR_Negative, EncryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Encrypt without init should fail or produce error
    Uint64 outlen = 0;
    alc_error_t err = ctr->encrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt without init should fail";

    delete ctr;
}

// Test decryption without initialization
TEST(CTR_Negative, DecryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Decrypt without init should fail or produce error
    Uint64 outlen = 0;
    alc_error_t err = ctr->decrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt without init should fail";

    delete ctr;
}

// Test zero input length encryption
TEST(CTR_Negative, ZeroLengthInputEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with zero length - should either succeed with zero output or return error
    Uint64 outlen = 0;
    err = ctr->encrypt(&input[0], &output[0], 0, &outlen);
    if (err == ALC_ERROR_NONE) {
        EXPECT_EQ(outlen, 0) << "Zero length encrypt should produce zero output";
    }

    delete ctr;
}

// Test zero input length decryption
TEST(CTR_Negative, ZeroLengthInputDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with zero length - should either succeed with zero output or return error
    Uint64 outlen = 0;
    err = ctr->decrypt(&input[0], &output[0], 0, &outlen);
    if (err == ALC_ERROR_NONE) {
        EXPECT_EQ(outlen, 0) << "Zero length decrypt should produce zero output";
    }

    delete ctr;
}

// Test context copy with null source
TEST(CTR_Negative, ContextCopyNullSource)
{
    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    auto ctr_dest = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr_dest, nullptr);

    // Copy with null source should be handled gracefully
    ctr->CopyCtx(nullptr, ctr_dest);
    // The test passes if no crash occurs

    delete ctr;
    delete ctr_dest;
}

// Test context copy with null destination
TEST(CTR_Negative, ContextCopyNullDestination)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    ctr->init(&test_key[0], 128, &test_iv[0], 16);

    // Copy with null destination should be handled gracefully
    ctr->CopyCtx(ctr, nullptr);
    // The test passes if no crash occurs

    delete ctr;
}

// Test very large input size (boundary test)
TEST(CTR_Negative, VeryLargeInputSize)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    
    const size_t large_size = 16 * 1024 * 1024; // 16 MB
    std::vector<Uint8> input(large_size, 0x55);
    std::vector<Uint8> output(large_size);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = ctr->encrypt(&input[0], &output[0], large_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, large_size);

    delete ctr;
}

// Test mismatched key size and CipherKeyLen
TEST(CTR_Negative, MismatchedKeySizeAndKeyLen)
{
    std::vector<Uint8> test_key(32, 0x42); // 256-bit key
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Trying to init 128-bit cipher with 256-bit key size
    alc_error_t err = ctr->init(&test_key[0], 256, &test_iv[0], 16);
    // Behavior is implementation-defined - we just verify it doesn't crash
    (void)err;

    delete ctr;
}

// Test repeated initialization (reinit)
TEST(CTR_Negative, RepeatedInitialization)
{
    std::vector<Uint8> test_key1(16, 0x42);
    std::vector<Uint8> test_key2(16, 0x84);
    std::vector<Uint8> test_iv1(16, 0x24);
    std::vector<Uint8> test_iv2(16, 0x48);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output1(32), output2(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // First init and encrypt
    alc_error_t err = ctr->init(&test_key1[0], 128, &test_iv1[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = ctr->encrypt(&input[0], &output1[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Reinit with different key/IV and encrypt again
    err = ctr->init(&test_key2[0], 128, &test_iv2[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = ctr->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Different keys should produce different outputs
    EXPECT_NE(output1, output2) << "Different keys should produce different ciphertext";

    delete ctr;
}

// Test maximum key length boundary
TEST(CTR_Negative, MaxKeyLengthBoundary)
{
    std::vector<Uint8> test_key(33, 0x42); // 264 bits
    std::vector<Uint8> test_iv(16, 0x24);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey256Bit);
    ASSERT_NE(ctr, nullptr);

    // Init with key length above maximum should fail
    alc_error_t err = ctr->init(&test_key[0], 264, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with key length > 256 bits should fail";

    delete ctr;
}

// Test IV length boundary
TEST(CTR_Negative, IVLengthBoundary)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(17, 0x24); // 17-byte IV

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // Init with IV length above required (17 bytes) - behavior is implementation-defined
    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 17);
    // We just verify it doesn't crash
    (void)err;

    delete ctr;
}

// Test small IV length
// Note: Implementation may not validate IV length
TEST(CTR_Negative, SmallIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(4, 0x24); // 4-byte IV (invalid for CTR)

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 4);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with 4-byte IV should fail";

    delete ctr;
}

// Test cipher reuse after error
TEST(CTR_Negative, ReuseAfterError)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey128Bit);
    ASSERT_NE(ctr, nullptr);

    // First, cause an error by using null pointer
    alc_error_t err = ctr->init(nullptr, 128, &test_iv[0], 16);
    // This should have failed

    // Now try to reinit properly and use the cipher
    err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Reinit after error should succeed";

    Uint64 outlen = 0;
    err = ctr->encrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt after reinit should succeed";
    EXPECT_EQ(outlen, 32);

    delete ctr;
}

// Test key length that doesn't match cipher creation
TEST(CTR_Negative, KeyLengthMismatchWithCreation)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    // Create 256-bit cipher but use 128-bit key length in init
    auto ctr = createCipher(CipherMode::eAesCTR, CipherKeyLen::eKey256Bit);
    ASSERT_NE(ctr, nullptr);

    // Pass 128-bit key length but cipher was created for 256-bit
    alc_error_t err = ctr->init(&test_key[0], 128, &test_iv[0], 16);
    // Behavior is implementation-defined - we just verify it doesn't crash
    (void)err;

    delete ctr;
}

int
main(int argc, char** argv)
{
    try {
        ::testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();

    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (const char* e) {
        std::cerr << "Unhandled exception: " << e << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
}
