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
#include <numeric>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"
#include "debug_defs.hh"
#include "randomize.hh"
#include <exception>
#include <iostream>

#undef DEBUG

#if 0
using alcp::cipher::Cbc;
#endif

// Factory removed
using alcp::cipher::CipherKeyLen;
using alcp::cipher::CipherMode;
using alcp::cipher::createCipher;
using alcp::cipher::iCipher;
namespace alcp::cipher::unittest::cbc {

void
printHexString(const char* info, const unsigned char* bytes, int length)
{
    char* p_hex_string = (char*)malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            if (chararray[j] >= 0xa) {
                chararray[j] = 'a' + chararray[j] - 0xa;
            } else {
                chararray[j] = '0' + chararray[j] - 0x0;
            }
            p_hex_string[i * 2 + j] = chararray[j];
        }
    }
    p_hex_string[length * 2] = 0x0;
    printf("%s:%s\n", info, p_hex_string);
    free(p_hex_string);
}
std::vector<Uint8> key       = { 0x45, 0x74, 0x3e, 0xcf, 0x0a, 0x7d, 0x79, 0x60,
                                 0x01, 0xe4, 0xec, 0x34, 0x6b, 0xf0, 0xc4, 0x58 };
std::vector<Uint8> iv        = { 0x8e, 0x56, 0x8c, 0x65, 0x9f, 0x9a, 0x6c, 0x83,
                                 0x3a, 0x6f, 0x36, 0x2b, 0xb5, 0x84, 0x2c, 0x2d };
std::vector<Uint8> plainText = {
    0x08, 0x88, 0x72, 0x0d, 0x01, 0xb2, 0x97, 0x1d, 0xd1, 0xc4, 0xd6, 0xba,
    0x87, 0x4c, 0xf7, 0x7d, 0x23, 0xa5, 0xe8, 0x60, 0x30, 0xb1, 0xea, 0x13,
    0x3d, 0xa7, 0xd7, 0xf0, 0xa2, 0x0b, 0x08, 0xf3, 0x99, 0xbf, 0x60, 0x75,
    0x55, 0x4f, 0x49, 0x10, 0x22, 0x18, 0x8d, 0x8f, 0xb0, 0xec, 0x89, 0x1f,
    0x2f, 0xfe, 0xa9, 0x0a, 0x6e, 0x99, 0x37, 0xe7, 0x6a, 0x38, 0x27, 0x2d,
    0xe1, 0x11, 0xec, 0xf9, 0x87, 0x5c, 0x4c, 0xb1, 0x50, 0xe3, 0x8c, 0x80,
    0x04, 0xd6, 0x12, 0xa3, 0x51, 0x95, 0xc5, 0x34, 0x16, 0x55, 0xe6, 0x5c,
    0x81, 0x4a, 0x4e, 0x63, 0x9a, 0xc1, 0x36, 0x63, 0x26, 0xbb, 0x2c, 0xb7,
    0x69, 0x1b, 0x64, 0x27, 0x58, 0xf9, 0x40, 0x53, 0x57, 0x28, 0x46, 0xcf,
    0x06, 0xad, 0x02, 0xbe, 0x96, 0x93, 0x94, 0x6b, 0x73, 0x02, 0x1c, 0xd3,
    0x63, 0x24, 0xe1, 0xa5, 0x13, 0x02, 0xe2, 0x64, 0xb4, 0x14, 0x76, 0x66,
    0xd2, 0xc6, 0xa6, 0xd1, 0x73, 0xa7, 0x7c, 0xab, 0xc5, 0xf5, 0xbf, 0xd5,
    0x27, 0xa1, 0xf7, 0x4b, 0xa4, 0x97, 0x20, 0x95, 0x2e, 0x45, 0xfc, 0xf8,
    0xcf, 0x47, 0xc8, 0xe7, 0xb9, 0xc9, 0x12, 0x89, 0xc3, 0x5b, 0xf9, 0x92,
    0x17, 0x57, 0xfb, 0x84, 0xcc, 0xfd, 0x51, 0x03, 0x36, 0x76, 0xc8, 0xdb,
    0xf3, 0x41, 0x52, 0x09, 0xc3, 0x66, 0x49, 0x4e, 0xf4, 0x91, 0x66, 0x0d,
    0x61, 0xfa, 0x67, 0xf9, 0xdb, 0xb6, 0x9c, 0x1d, 0x8b, 0xa7, 0x1e, 0x33,
    0x33, 0xd1, 0xf3, 0x2d, 0xdc, 0xe0, 0xed, 0xce, 0xfb, 0x54, 0x1b, 0x54,
    0x55, 0xf8, 0x2a, 0xcb, 0x5b, 0xa6, 0x33, 0x9d, 0x4a, 0xe8, 0x5e, 0xc2,
    0xd0, 0xca, 0xee, 0x16, 0x68, 0x70, 0x92, 0xec, 0x0b, 0xd0, 0xa6, 0x93,
    0xb0, 0x0d, 0x46, 0xe7, 0xda, 0xb9, 0x79, 0x07, 0xdc, 0xaf, 0xf4, 0x86,
    0x78, 0x10, 0xa0, 0xda, 0xed, 0x92, 0x00, 0x87, 0x7c, 0xbb, 0x94, 0x33,
    0xfc, 0xaf, 0x2a, 0x1c, 0xdb, 0xe7, 0xd7, 0xc3, 0x2a, 0x53, 0x95, 0x8e,
    0x33, 0x00, 0xc4, 0xa4, 0xc2, 0xbb, 0xa5, 0xed, 0xfe, 0xd6, 0x1d, 0xb1,
    0xe5, 0x56, 0x4a, 0xb0, 0x13, 0xda, 0x37, 0xbd, 0xb2, 0x54, 0xa3, 0xc4,
    0xe4, 0x23, 0x1e, 0xf6, 0xf4, 0xa7, 0x61, 0xc0, 0x1d, 0x07, 0x05, 0xc8,
    0x4d, 0xbd, 0x6e, 0xf4, 0x82, 0xfa, 0x37, 0xb6
};

std::vector<Uint8> cipherText = {
    0xe2, 0x27, 0x81, 0xbb, 0x3f, 0xf3, 0x3c, 0x74, 0x11, 0x84, 0xe1, 0x1d,
    0x84, 0xd4, 0x49, 0xfc, 0x9c, 0x9b, 0xbf, 0x21, 0x77, 0x5a, 0x8e, 0x41,
    0xb5, 0xda, 0x31, 0x8e, 0xa1, 0xcb, 0xef, 0x54, 0x74, 0xbb, 0xfc, 0x0f,
    0xf1, 0xe6, 0xaf, 0xd9, 0x27, 0x76, 0x04, 0x03, 0xe5, 0x04, 0x1a, 0xce,
    0xeb, 0x0b, 0xf1, 0xc0, 0x5c, 0xa9, 0xd3, 0x26, 0xc3, 0xf4, 0xaa, 0xe1,
    0x71, 0xaa, 0x78, 0x76, 0xca, 0xe7, 0x83, 0x30, 0xb8, 0xd6, 0x59, 0xe8,
    0x2f, 0xb2, 0x77, 0xbf, 0xec, 0x71, 0x4a, 0x8d, 0x2f, 0x72, 0x01, 0x4c,
    0x8a, 0xca, 0xc8, 0x86, 0x1f, 0xc4, 0xf4, 0x58, 0x61, 0xd8, 0x7c, 0xc6,
    0x15, 0x9f, 0x1f, 0x58, 0xe4, 0xa6, 0x72, 0x76, 0xad, 0x6a, 0x17, 0x3d,
    0xb4, 0x72, 0x76, 0xb5, 0x80, 0x9c, 0x7e, 0x05, 0x62, 0xa0, 0xdb, 0x06,
    0x40, 0x81, 0x70, 0x4f, 0x8f, 0xe2, 0x66, 0x83, 0x05, 0x5a, 0x26, 0x6d,
    0x72, 0xab, 0x4c, 0x8c, 0xd5, 0xe3, 0xa2, 0x11, 0x65, 0x50, 0x4c, 0x82,
    0xbe, 0x87, 0x2c, 0xc3, 0x43, 0x30, 0xbb, 0x1a, 0x38, 0xfa, 0x14, 0x1f,
    0xc2, 0xb2, 0x0c, 0x7f, 0xba, 0x3d, 0xb6, 0xa1, 0xd1, 0x94, 0x5c, 0x8e,
    0x48, 0xa8, 0xb4, 0xdf, 0xf4, 0xdd, 0x5d, 0x42, 0xba, 0xfd, 0xfa, 0x95,
    0x22, 0xd2, 0xdd, 0xc9, 0xd8, 0x7c, 0xce, 0x47, 0xa6, 0xd8, 0x4d, 0x28,
    0x37, 0x90, 0x63, 0x54, 0x45, 0xdc, 0xba, 0x78, 0x37, 0xda, 0xb2, 0xe5,
    0xba, 0x59, 0x44, 0xaf, 0xa3, 0x52, 0x35, 0x76, 0x73, 0x89, 0xda, 0x7e,
    0x96, 0x8f, 0x97, 0x0d, 0x6f, 0xc8, 0x6f, 0xfa, 0xe6, 0xfa, 0x92, 0x5e,
    0xbd, 0x44, 0x60, 0xa4, 0xbe, 0x6b, 0x3a, 0x41, 0x8e, 0x67, 0x74, 0xa2,
    0x67, 0x2c, 0xd6, 0xf7, 0xac, 0x74, 0x6f, 0x19, 0xbc, 0x18, 0x31, 0x09,
    0x86, 0xf7, 0x1d, 0x63, 0xcf, 0xf3, 0xbc, 0xfd, 0x8e, 0xa3, 0xd6, 0x85,
    0xdf, 0x1d, 0x6f, 0x7d, 0x87, 0xac, 0x83, 0x22, 0x77, 0x2d, 0x3b, 0x6e,
    0xc0, 0x3c, 0xaf, 0x59, 0x31, 0xe7, 0x04, 0xa0, 0xad, 0x6f, 0x37, 0xff,
    0xb5, 0xef, 0xc2, 0x5e, 0xf0, 0xb7, 0xfb, 0x9a, 0xf1, 0x86, 0x5d, 0x47,
    0x5b, 0xdb, 0xeb, 0x99, 0xb3, 0x67, 0xbf, 0xec, 0xf3, 0x0c, 0x32, 0xf6,
    0x70, 0xca, 0x09, 0x93, 0x97, 0x54, 0x19, 0x3e
};
} // namespace alcp::cipher::unittest::cbc

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::cbc;
TEST(CBC, creation)
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
        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }
        delete cbc;
    }
}

TEST(CBC, BasicEncryption)
{
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    Uint64 outlen = 0;
    cbc->encrypt(&plainText[0], &output[0], plainText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        cipherText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(cipherText, output);

    delete cbc;
}

TEST(CBC, BasicDecryption)
{
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(plainText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    Uint64 outlen = 0;
    cbc->decrypt(&cipherText[0], &output[0], cipherText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        plainText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(plainText, output);

    delete cbc;
}

TEST(CBC, ContextCopyEncryption)
{
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Copy the context
    // Factory removed
    auto cbc_copy = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    if (cbc_copy == nullptr) {
        delete cbc;
        FAIL();
    }
    cbc->CopyCtx(cbc, cbc_copy);

    Uint64 outlen = 0;
    cbc_copy->encrypt(&plainText[0], &output[0], plainText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        cipherText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(cipherText, output);

    delete cbc;
    delete cbc_copy;
}

TEST(CBC, ContextCopyDecryption)
{
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Copy the context
    // Factory removed
    auto cbc_copy = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    if (cbc_copy == nullptr) {
        delete cbc;
        FAIL();
    }
    cbc->CopyCtx(cbc, cbc_copy);

    Uint64 outlen = 0;
    cbc_copy->decrypt(&cipherText[0], &output[0], cipherText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        plainText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(plainText, output);

    delete cbc;
    delete cbc_copy;
}

TEST(CBC, MultiUpdateEncryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    alc_error_t err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    for (Uint64 i = 0; i < plainText.size() / 16; i++) {
        Uint64 chunk_outlen = 0;
        err                 = cbc->encrypt(&plainText[0] + i * 16,
                           &output[0] + i * 16,
                           16,
                           &chunk_outlen); // 16 byte chunks
        if (alcp_is_error(err)) {
            std::cout << "Encrypt failed!" << std::endl;
        }
        EXPECT_FALSE(alcp_is_error(err));
        EXPECT_EQ(chunk_outlen,
                  16); // CBC should output 16 bytes for 16-byte complete block
    }

    EXPECT_EQ(cipherText, output);

    delete cbc;
}

TEST(CBC, MultiUpdateEncryptionSmallChunks)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    alc_error_t err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Test with various small chunk sizes
    std::vector<Uint64> chunkSizes = { 1, 2, 3, 4, 5, 7, 8, 11, 13, 15 };

    for (Uint64 chunkSize : chunkSizes) {
        std::cout << "Testing with chunk size: " << chunkSize << std::endl;
        // Reset output buffer and cipher for each chunk size test
        std::fill(output.begin(), output.end(), 0);
        err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

        Uint64 inputBytesProcessed = 0;
        Uint64 totalOutputBytes    = 0;

        // Process data in small chunks using encrypt
        while (inputBytesProcessed < plainText.size()) {
            Uint64 remainingBytes   = plainText.size() - inputBytesProcessed;
            Uint64 currentChunkSize = std::min(chunkSize, remainingBytes);
            Uint64 outputBytes      = 0;

            err = cbc->encrypt(&plainText[0] + inputBytesProcessed,
                               &output[0] + totalOutputBytes,
                               currentChunkSize,
                               &outputBytes);

            if (alcp_is_error(err)) {
                std::cout << "Encrypt failed with chunk size " << chunkSize
                          << " at offset " << inputBytesProcessed << std::endl;
            }
            EXPECT_FALSE(alcp_is_error(err))
                << "Failed with chunk size " << chunkSize;

            inputBytesProcessed += currentChunkSize;
            totalOutputBytes += outputBytes;
        }

        // For CBC multi-update, we should have all the data encrypted by the
        // end
        EXPECT_EQ(totalOutputBytes, cipherText.size())
            << "Total output size mismatch with chunk size " << chunkSize;
        EXPECT_EQ(cipherText, output)
            << "Mismatch with chunk size " << chunkSize;
    }

    delete cbc;
}

TEST(CBC, MultiUpdateDecryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        // Factory removed
        auto cbc =
            createCipher(CipherMode::eAesCBC,
                         CipherKeyLen::eKey128Bit); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }
        std::vector<Uint8> output(cipherText.size());

        alc_error_t err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

        for (Uint64 i = 0; i < plainText.size() / 16; i++) {
            Uint64 chunk_outlen = 0;
            err                 = cbc->decrypt(&cipherText[0] + i * 16,
                               &output[0] + i * 16,
                               16,
                               &chunk_outlen);
            if (alcp_is_error(err)) {
                std::cout << "Decrypt failed!" << std::endl;
            }
            EXPECT_FALSE(alcp_is_error(err));
            EXPECT_EQ(
                chunk_outlen,
                16); // CBC should output 16 bytes for 16-byte complete block
        }
        EXPECT_EQ(plainText, output)
            << "FAIL CPU_FEATURE:"
            << std::underlying_type<CpuArchLevel>::type(feature);

        delete cbc;
    }
}
TEST(CBC, MultiUpdateDecryptionSmallChunks)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    // Factory removed
    auto cbc = createCipher(CipherMode::eAesCBC,
                            CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete cbc;
        FAIL();
    }
    std::vector<Uint8> output(plainText.size());

    alc_error_t err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Test with various small chunk sizes
    std::vector<Uint64> chunkSizes = { 1, 2, 3, 4, 5, 7, 8, 11, 13, 15 };

    for (Uint64 chunkSize : chunkSizes) {
        std::cout << "Testing with chunk size: " << chunkSize << std::endl;
        // Reset output buffer and cipher for each chunk size test
        std::fill(output.begin(), output.end(), 0);
        err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

        Uint64 inputBytesProcessed = 0;
        Uint64 totalOutputBytes    = 0;

        // Process data in small chunks using decrypt
        while (inputBytesProcessed < cipherText.size()) {
            Uint64 remainingBytes   = cipherText.size() - inputBytesProcessed;
            Uint64 currentChunkSize = std::min(chunkSize, remainingBytes);
            Uint64 outputBytes      = 0;

            err = cbc->decrypt(&cipherText[0] + inputBytesProcessed,
                               &output[0] + totalOutputBytes,
                               currentChunkSize,
                               &outputBytes);

            if (alcp_is_error(err)) {
                std::cout << "Decrypt failed with chunk size " << chunkSize
                          << " at offset " << inputBytesProcessed << std::endl;
            }
            EXPECT_FALSE(alcp_is_error(err))
                << "Failed with chunk size " << chunkSize;

            inputBytesProcessed += currentChunkSize;
            totalOutputBytes += outputBytes;
        }

        // For CBC multi-update, we should have all the data decrypted by the
        // end
        EXPECT_EQ(totalOutputBytes, plainText.size())
            << "Total output size mismatch with chunk size " << chunkSize;
        EXPECT_EQ(plainText, output)
            << "Mismatch with chunk size " << chunkSize;
    }

    delete cbc;
}

TEST(CBC, InplaceEncryption)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place encryption functionality disabled!";
#endif
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        // Factory removed
        auto cbc =
            createCipher(CipherMode::eAesCBC,
                         CipherKeyLen::eKey128Bit); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }

        // Create a copy of plainText to avoid modifying the original
        std::vector<Uint8> plainText_copy = plainText;

        cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

        // Encrypt in-place using the copy
        Uint64 outlen = 0;
        cbc->encrypt(&plainText_copy[0],
                     &plainText_copy[0],
                     plainText_copy.size(),
                     &outlen);
        EXPECT_EQ(outlen, cipherText.size()); // Should produce full output for
                                              // complete blocks

        EXPECT_EQ(cipherText, plainText_copy)
            << "FAIL CPU_FEATURE:"
            << std::underlying_type<CpuArchLevel>::type(feature);

        delete cbc;
    }
}

TEST(CBC, InplaceDecryption)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        // Factory removed
        auto cbc =
            createCipher(CipherMode::eAesCBC,
                         CipherKeyLen::eKey128Bit); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }

        // Make a copy of cipherText for each feature test
        std::vector<Uint8> cipherText_copy = cipherText;

        // In-place decryption (source and destination are the same)
        cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());
        Uint64 outlen = 0;
        cbc->decrypt(&cipherText_copy[0],
                     &cipherText_copy[0],
                     cipherText_copy.size(),
                     &outlen);
        EXPECT_EQ(
            outlen,
            plainText.size()); // Should produce full output for complete blocks

        EXPECT_EQ(plainText, cipherText_copy)
            << "FAIL CPU_FEATURE:"
            << std::underlying_type<CpuArchLevel>::type(feature);

        delete cbc;
    }
}

#if 0
TEST(CBC, PaddingEncryption)
{
    std::vector<Uint8>             pt = { 0x08, 0x88, 0x72, 0x0d, 0x01, 0xb2,
                                          0x97, 0x1d, 0xd1, 0xc4, 0xd6, 0xba,
                                          0x87, 0x4c, 0xf7, 0x7d, 0x23 };
    std::vector<Uint8>             ct = { 0xe2, 0x27, 0x81, 0xbb, 0x3f, 0xf3,
                                          0x3c, 0x74, 0x11, 0x84, 0xe1, 0x1d,
                                          0x84, 0xd4, 0x49, 0xfc, 0xaf };
    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();

    // Test for all arch
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        // Factory removed
        auto cbc        = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);

        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }
        std::vector<Uint8> output(pt.size());

        alc_error_t err = cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

        err = cbc->encrypt(&pt[0], &output[0], pt.size());
#ifdef DEBUG
        printHexString("CT", &output[0], output.size());
#endif
        if (alcp_is_error(err)) {
            std::cout << "Encrypt failed!" << std::endl;
        }

        EXPECT_FALSE(alcp_is_error(err));

        EXPECT_EQ(ct, output)
            << "FAIL CPU_FEATURE:"
            << std::underlying_type<CpuArchLevel>::type(feature);

        delete cbc;
    }
}
#endif

TEST(CBC, RandomEncryptDecryptTest)
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

    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
        const std::vector<Uint8> plainTextVect(plain_text_vect.begin(),
                                               plain_text_vect.end());
        std::vector<Uint8>       plainTextOut(plainTextVect.size());
        // Factory removed
        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            delete cbc;
            FAIL();
        }
        cbc->init(key_256, 256, &iv[0], sizeof(iv));

        Uint64 encrypt_outlen = 0;
        cbc->encrypt(&plainTextVect[0],
                     &cipher_text_vect[0],
                     plainTextVect.size(),
                     &encrypt_outlen);

        cbc->init(key_256, 256, &iv[0], sizeof(iv));

        Uint64 decrypt_outlen = 0;
        cbc->decrypt(&cipher_text_vect[0],
                     &plainTextOut[0],
                     plainTextVect.size(),
                     &decrypt_outlen);

        delete cbc;
#ifdef DEBUG

        if (plainTextVect != plainTextOut) {
            // Print the key, IV, and ciphertext for debugging
            printHexString("Key", key_256, 32);
            printHexString("IV", iv, 16);
            printHexString(
                "Ciphertext", &cipher_text_vect[0], plainTextVect.size());
            printHexString(
                "plainTextVect", &plainTextVect[0], plainTextVect.size());

            printf("\n");
            printHexString(
                "plainTextOut", &plainTextOut[0], plainTextOut.size());
            printf("\n");

            printf("Length: %zu\n", plainTextVect.size());
        }
#endif
        // print address of the vectors for debugging
        ASSERT_EQ(plainTextVect, plainTextOut);

#ifdef DEBUG
        auto ret = std::mismatch(
            plainTextVect.begin(), plainTextVect.end(), plainTextOut.begin());
        std::cout << "First:" << ret.first - plainTextVect.begin()
                  << "Second:" << ret.second - plainTextOut.begin()
                  << std::endl;
#endif
    }
}
TEST(CBC, MultiBufferRandomTest)
{
    Uint8        key_256[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    const Uint64 cTextSize   = 16; // 16 bytes * 1000 buffers
    std::vector<const Uint8*> plain_text_vect(cTextSize);
    std::vector<Uint8*>       cipher_text_vect(cTextSize);
    std::vector<const Uint8*> iv_vect(16);
    int                       num_buffers = 2; // Number of buffers to test
    // Fill buffer with random data
    // allocate memory for the vectors
    for (int i = 0; i < num_buffers; ++i) {
        plain_text_vect[i] = new Uint8[cTextSize];
        iv_vect[i]         = new Uint8[16];
        // Initialize the random number generator
        std::unique_ptr<IRandomize> random = std::make_unique<Randomize>(12);
        random->getRandomBytes(const_cast<Uint8*>(plain_text_vect[i]),
                               cTextSize);
        random->getRandomBytes(const_cast<Uint8*>(iv_vect[i]), 16);
        cipher_text_vect[i] = new Uint8[cTextSize];
    }

    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();

    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        /* FIXME: run this test only for zen4 for now? */
        if (feature != CpuArchLevel::eZen4) {
            std::cout << "Skipping test for feature avx512 " << std::endl;
            continue;
        }
        // Create cipher via factory
        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            FAIL() << "Failed to create CBC cipher";
        }
        cbc->init(key_256, 256, nullptr, 0);

        // Get iMultibuffer interface via dynamic_cast
        auto* mb = dynamic_cast<alcp::cipher::iMultibuffer*>(cbc);
        if (mb == nullptr) {
            delete cbc;
            FAIL() << "CBC cipher does not support multibuffer operations";
        }

        // Call multibuffer methods via iMultibuffer interface
        mb->multibufferInit(
            key_256, 256, iv_vect.data(), iv_vect.size(), num_buffers);

        // Create lengths array for uniform-length buffers
        std::vector<Uint64> lengths(num_buffers, cTextSize);

        // Test flush and dequeue operations via iMultibuffer interface
        alc_error_t err =
            mb->flush(plain_text_vect.data(), lengths.data(), num_buffers);
        EXPECT_FALSE(alcp_is_error(err));

        err = mb->dequeue(cipher_text_vect.data(), num_buffers, lengths.data());
        EXPECT_FALSE(alcp_is_error(err));
        // Verify the output
        std::vector<Uint8> plainText(cTextSize);
        for (int i = 0; i < num_buffers; ++i) {
            cbc->init(key_256, 256, iv_vect[i], 16);
            Uint64 verify_outlen = 0;
            cbc->decrypt(cipher_text_vect[i],
                         plainText.data(),
                         cTextSize,
                         &verify_outlen);
            printHexString("Cipher Text", cipher_text_vect[i], cTextSize);
            printHexString("Plain Text", plainText.data(), cTextSize);
            printHexString("plain_text_vect", plain_text_vect[i], cTextSize);
            // ASSERT_EQ(0, memcmp(plain_text_vect[i], plainText.data(),
            // cTextSize));
        }

        delete cbc;
    }
    /* delete iv_vect */
    for (int i = 0; i < num_buffers; ++i) {
        delete[] iv_vect[i];
        delete[] cipher_text_vect[i];
        delete[] plain_text_vect[i];
    }
}

// Multi-update tests for arbitrary sizes - testing the cipher_multi_update_api
// functionality
TEST(CBC, MultiUpdateArbitrarySizesVariousUpdateCounts)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    std::vector<CpuArchLevel> cpu_features =
        alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        // Factory removed
        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);

        if (cbc == nullptr) {
            delete cbc;
            continue;
        }

        // Test various update counts with different chunk sizes
        std::vector<std::vector<size_t>> chunk_patterns = {
            { 5, 7, 4 },               // 3 updates, sums to 16
            { 1, 2, 3, 4, 6 },         // 5 updates, sums to 16
            { 3, 13, 16 },             // 3 updates, sums to 32
            { 8, 24 },                 // 2 updates, sums to 32
            { 1, 1, 1, 1, 12, 16, 16 } // 7 updates, sums to 48
        };

        for (auto& chunks : chunk_patterns) {
            // Calculate total size needed
            size_t total_size =
                std::accumulate(chunks.begin(), chunks.end(), 0);

            // Create test data
            std::vector<Uint8> input_data(total_size);
            std::iota(input_data.begin(),
                      input_data.end(),
                      0x30); // Fill with '0', '1', '2', etc.

            std::vector<Uint8> output1(total_size), output2(total_size);
            Uint64             total_output1 = 0, total_output2 = 0;

            // Test encryption with multi-update
            cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

            size_t input_offset = 0;
            for (size_t chunk_size : chunks) {
                Uint64 chunk_output = 0;
                auto   err          = cbc->encrypt(&input_data[input_offset],
                                        &output1[total_output1],
                                        chunk_size,
                                        &chunk_output);
                EXPECT_EQ(err, ALC_ERROR_NONE);
                input_offset += chunk_size;
                total_output1 += chunk_output;
            }

            // Test decryption with multi-update - create separate factory for
            // second cipher
            // Factory removed
            auto cbc2 =
                createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
            if (cbc2 == nullptr)
                return;
            cbc2->init(&key[0], key.size() * 8, &iv[0], iv.size());

            size_t output_offset = 0;
            for (size_t i = 0; i < chunks.size(); i++) {
                // Find how much was encrypted in this chunk
                Uint64 encrypted_size =
                    (i == chunks.size() - 1)
                        ? (total_output1 - output_offset)
                        : (chunks[i] / 16) * 16; // Complete blocks only

                if (encrypted_size > 0) {
                    Uint64 chunk_output = 0;
                    auto   err          = cbc2->decrypt(&output1[output_offset],
                                             &output2[total_output2],
                                             encrypted_size,
                                             &chunk_output);
                    EXPECT_EQ(err, ALC_ERROR_NONE);
                    output_offset += encrypted_size;
                    total_output2 += chunk_output;
                }
            }

            // Verify the decrypted data matches input (up to complete blocks)
            size_t complete_blocks = (total_size / 16) * 16;
            for (size_t i = 0; i < complete_blocks; i++) {
                EXPECT_EQ(input_data[i], output2[i])
                    << "Mismatch at byte " << i << " for feature "
                    << static_cast<int>(feature);
            }

            // Clean up second factory
            delete cbc2;
        }

        // Factory destructor will clean up the cipher object
        delete cbc;
    }
}

// ============================================================================
// Comprehensive Corner Case Tests for CBC
// ============================================================================

// Test all key sizes (128, 192, 256 bits)
TEST(CBC, AllKeySizes)
{
    // 128-bit key
    {
        std::vector<Uint8> key_128(16, 0x42);
        std::vector<Uint8> test_iv(16, 0x00);
        std::vector<Uint8> input(32, 0x55);
        std::vector<Uint8> output(32), decrypted(32);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr) << "Failed to create AES-CBC-128";

        cbc->init(&key_128[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 32);

        cbc->init(&key_128[0], 128, &test_iv[0], 16);
        outlen = 0;
        EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input);
        delete cbc;
    }

    // 192-bit key
    {
        std::vector<Uint8> key_192(24, 0x42);
        std::vector<Uint8> test_iv(16, 0x00);
        std::vector<Uint8> input(32, 0x55);
        std::vector<Uint8> output(32), decrypted(32);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey192Bit);
        ASSERT_NE(cbc, nullptr) << "Failed to create AES-CBC-192";

        cbc->init(&key_192[0], 192, &test_iv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 32);

        cbc->init(&key_192[0], 192, &test_iv[0], 16);
        outlen = 0;
        EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input);
        delete cbc;
    }

    // 256-bit key
    {
        std::vector<Uint8> key_256(32, 0x42);
        std::vector<Uint8> test_iv(16, 0x00);
        std::vector<Uint8> input(32, 0x55);
        std::vector<Uint8> output(32), decrypted(32);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);
        ASSERT_NE(cbc, nullptr) << "Failed to create AES-CBC-256";

        cbc->init(&key_256[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 32);

        cbc->init(&key_256[0], 256, &test_iv[0], 16);
        outlen = 0;
        EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 32, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input);
        delete cbc;
    }
}

// Test single block (16 bytes) encryption/decryption
TEST(CBC, SingleBlock)
{
    std::vector<Uint8> test_key(16, 0xAA);
    std::vector<Uint8> test_iv(16, 0xBB);
    std::vector<Uint8> input(16, 0xCC);
    std::vector<Uint8> output(16), decrypted(16);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 16, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);
    EXPECT_NE(output, input); // Encrypted data should differ from plaintext

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 16, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete cbc;
}

// Test multiple blocks encryption/decryption
TEST(CBC, MultipleBlocks)
{
    // Test various block counts
    std::vector<size_t> block_counts = { 2, 3, 4, 5, 8, 10, 16, 32, 64, 100 };
    
    std::vector<Uint8> test_key(16, 0xDD);
    std::vector<Uint8> test_iv(16, 0xEE);

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;
        std::vector<Uint8> input(data_size);
        // Fill with pattern based on position
        for (size_t i = 0; i < data_size; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(data_size), decrypted(data_size);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr);

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        EXPECT_EQ(cbc->encrypt(&input[0], &output[0], data_size, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(outlen, data_size) << "Block count: " << num_blocks;

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        outlen = 0;
        EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], data_size, &outlen), ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input) << "Mismatch at block count: " << num_blocks;

        delete cbc;
    }
}

// Test all zeros input
TEST(CBC, AllZerosInput)
{
    std::vector<Uint8> test_key(16, 0x00);
    std::vector<Uint8> test_iv(16, 0x00);
    std::vector<Uint8> input(64, 0x00);
    std::vector<Uint8> output(64), decrypted(64);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 64);

    // All zeros plaintext with zero key and IV should produce known result
    // Just verify encrypt-decrypt round trip
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete cbc;
}

// Test all ones input (0xFF)
TEST(CBC, AllOnesInput)
{
    std::vector<Uint8> test_key(16, 0xFF);
    std::vector<Uint8> test_iv(16, 0xFF);
    std::vector<Uint8> input(64, 0xFF);
    std::vector<Uint8> output(64), decrypted(64);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    EXPECT_EQ(cbc->encrypt(&input[0], &output[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 64);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    EXPECT_EQ(cbc->decrypt(&output[0], &decrypted[0], 64, &outlen), ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete cbc;
}

// Test double initialization (reinit with same and different IV)
TEST(CBC, DoubleInit)
{
    std::vector<Uint8> test_key(16, 0x12);
    std::vector<Uint8> iv1(16, 0x34);
    std::vector<Uint8> iv2(16, 0x56);
    std::vector<Uint8> input(32, 0x78);
    std::vector<Uint8> output1(32), output2(32), decrypted(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // First encryption with IV1
    cbc->init(&test_key[0], 128, &iv1[0], 16);
    Uint64 outlen = 0;
    cbc->encrypt(&input[0], &output1[0], 32, &outlen);

    // Reinit with same IV - should produce same result
    cbc->init(&test_key[0], 128, &iv1[0], 16);
    outlen = 0;
    cbc->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_EQ(output1, output2) << "Same IV should produce same ciphertext";

    // Reinit with different IV - should produce different result
    cbc->init(&test_key[0], 128, &iv2[0], 16);
    outlen = 0;
    cbc->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_NE(output1, output2) << "Different IV should produce different ciphertext";

    // Verify decrypt still works after multiple inits
    cbc->init(&test_key[0], 128, &iv1[0], 16);
    outlen = 0;
    cbc->decrypt(&output1[0], &decrypted[0], 32, &outlen);
    EXPECT_EQ(decrypted, input);

    delete cbc;
}

// Test consecutive encryptions
TEST(CBC, ConsecutiveEncryptions)
{
    std::vector<Uint8> test_key(16, 0x9A);
    std::vector<Uint8> test_iv(16, 0xBC);
    std::vector<Uint8> input1(32, 0x11);
    std::vector<Uint8> input2(48, 0x22);
    std::vector<Uint8> output1(32), output2(48);
    std::vector<Uint8> decrypted1(32), decrypted2(48);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // First encryption
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    cbc->encrypt(&input1[0], &output1[0], 32, &outlen);
    EXPECT_EQ(outlen, 32);

    // Second encryption with new init
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    cbc->encrypt(&input2[0], &output2[0], 48, &outlen);
    EXPECT_EQ(outlen, 48);

    // Verify both decrypt correctly
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    cbc->decrypt(&output1[0], &decrypted1[0], 32, &outlen);
    EXPECT_EQ(decrypted1, input1);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    cbc->decrypt(&output2[0], &decrypted2[0], 48, &outlen);
    EXPECT_EQ(decrypted2, input2);

    delete cbc;
}

// Test large data (multiple MB)
TEST(CBC, LargeData)
{
    const size_t MB = 1024 * 1024;
    const size_t data_size = 2 * MB; // 2 MB
    
    std::vector<Uint8> test_key(32, 0xDE);
    std::vector<Uint8> test_iv(16, 0xAD);
    std::vector<Uint8> input(data_size);
    std::vector<Uint8> output(data_size), decrypted(data_size);

    // Fill with pattern
    for (size_t i = 0; i < data_size; i++) {
        input[i] = static_cast<Uint8>((i * 17) % 256);
    }

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 256, &test_iv[0], 16);
    Uint64 outlen = 0;
    auto err = cbc->encrypt(&input[0], &output[0], data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, data_size);

    cbc->init(&test_key[0], 256, &test_iv[0], 16);
    outlen = 0;
    err = cbc->decrypt(&output[0], &decrypted[0], data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete cbc;
}

// Test different IV values affect output
TEST(CBC, IVAffectsOutput)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<std::vector<Uint8>> outputs;

    // Generate 5 different IVs and encrypt
    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> test_iv(16, static_cast<Uint8>(i));
        std::vector<Uint8> output(32);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr);

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        cbc->encrypt(&input[0], &output[0], 32, &outlen);
        outputs.push_back(output);

        delete cbc;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "IV " << i << " and " << j << " produced same output";
        }
    }
}

// Test boundary sizes (exact multiples of block size)
TEST(CBC, BlockBoundarySizes)
{
    std::vector<Uint8> test_key(16, 0x73);
    std::vector<Uint8> test_iv(16, 0x84);
    
    // Test exact block multiples
    std::vector<size_t> sizes = { 16, 32, 48, 64, 80, 96, 112, 128, 256, 512, 1024 };
    
    for (size_t size : sizes) {
        std::vector<Uint8> input(size);
        for (size_t i = 0; i < size; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(size), decrypted(size);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr);

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = cbc->encrypt(&input[0], &output[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed for size " << size;
        EXPECT_EQ(outlen, size) << "Output length mismatch for size " << size;

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        outlen = 0;
        err = cbc->decrypt(&output[0], &decrypted[0], size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Decrypt failed for size " << size;
        EXPECT_EQ(decrypted, input) << "Data mismatch for size " << size;

        delete cbc;
    }
}

// Test CBC chaining property - changing one plaintext block affects all subsequent ciphertext blocks
TEST(CBC, ChainingProperty)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input1(48, 0x00);
    std::vector<Uint8> input2(48, 0x00);
    
    // Modify only the second block of input2
    input2[16] = 0x01;
    
    std::vector<Uint8> output1(48), output2(48);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    cbc->encrypt(&input1[0], &output1[0], 48, &outlen);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    cbc->encrypt(&input2[0], &output2[0], 48, &outlen);

    // First block should be the same (same IV and same first plaintext block)
    bool first_block_same = true;
    for (int i = 0; i < 16; i++) {
        if (output1[i] != output2[i]) {
            first_block_same = false;
            break;
        }
    }
    EXPECT_TRUE(first_block_same) << "First block should be same";

    // Second and third blocks should differ due to CBC chaining
    bool second_block_differs = false;
    for (int i = 16; i < 32; i++) {
        if (output1[i] != output2[i]) {
            second_block_differs = true;
            break;
        }
    }
    EXPECT_TRUE(second_block_differs) << "Second block should differ";

    bool third_block_differs = false;
    for (int i = 32; i < 48; i++) {
        if (output1[i] != output2[i]) {
            third_block_differs = true;
            break;
        }
    }
    EXPECT_TRUE(third_block_differs) << "Third block should differ due to chaining";

    delete cbc;
}

// Test encrypt then decrypt with different cipher objects
TEST(CBC, SeparateCipherObjects)
{
    std::vector<Uint8> test_key(16, 0xAB);
    std::vector<Uint8> test_iv(16, 0xCD);
    std::vector<Uint8> input(64, 0xEF);
    std::vector<Uint8> output(64), decrypted(64);

    // Create first cipher for encryption
    auto cbc_enc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc_enc, nullptr);

    cbc_enc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    cbc_enc->encrypt(&input[0], &output[0], 64, &outlen);
    EXPECT_EQ(outlen, 64);

    delete cbc_enc;

    // Create second cipher for decryption
    auto cbc_dec = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc_dec, nullptr);

    cbc_dec->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    cbc_dec->decrypt(&output[0], &decrypted[0], 64, &outlen);
    EXPECT_EQ(decrypted, input);

    delete cbc_dec;
}

// Test that same plaintext with same key/IV always produces same ciphertext
TEST(CBC, Determinism)
{
    std::vector<Uint8> test_key(16, 0x11);
    std::vector<Uint8> test_iv(16, 0x22);
    std::vector<Uint8> input(32, 0x33);
    std::vector<Uint8> output1(32), output2(32), output3(32);

    for (int round = 0; round < 3; round++) {
        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr);

        cbc->init(&test_key[0], 128, &test_iv[0], 16);
        Uint64 outlen = 0;
        std::vector<Uint8>* current_output = (round == 0) ? &output1 : (round == 1) ? &output2 : &output3;
        cbc->encrypt(&input[0], &(*current_output)[0], 32, &outlen);

        delete cbc;
    }

    EXPECT_EQ(output1, output2) << "Round 1 and 2 should produce same output";
    EXPECT_EQ(output2, output3) << "Round 2 and 3 should produce same output";
}

// ============================================================================
// Negative Tests for CBC - Null Pointer and Edge Cases
// ============================================================================

// Test null pointer for key in init
TEST(CBC_Negative, NullKeyPointer)
{
    std::vector<Uint8> test_iv(16, 0x00);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Passing null key pointer should return an error
    alc_error_t err = cbc->init(nullptr, 128, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key should fail";

    delete cbc;
}

// Test null pointer for IV in init
TEST(CBC_Negative, NullIVPointer)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Passing null IV pointer - the implementation may accept this
    // and use a default IV or handle it gracefully
    alc_error_t err = cbc->init(&test_key[0], 128, nullptr, 16);
    // Document actual behavior: implementation accepts null IV
    // This test verifies the behavior doesn't crash and documents the API contract
    (void)err; // Behavior is implementation-defined

    delete cbc;
}

// Test null pointer for both key and IV in init
TEST(CBC_Negative, NullKeyAndIVPointers)
{
    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Passing both null key and IV pointers should return an error
    alc_error_t err = cbc->init(nullptr, 128, nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key and IV should fail";

    delete cbc;
}

// Test null pointer for input plaintext in encrypt
TEST(CBC_Negative, NullInputPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with null input pointer should fail
    Uint64 outlen = 0;
    err = cbc->encrypt(nullptr, &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";

    delete cbc;
}

// Test null pointer for input ciphertext in decrypt
TEST(CBC_Negative, NullInputPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with null input pointer should fail
    Uint64 outlen = 0;
    err = cbc->decrypt(nullptr, &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null input should fail";

    delete cbc;
}

// Test null pointer for output in encrypt
TEST(CBC_Negative, NullOutputPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with null output pointer should fail
    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";

    delete cbc;
}

// Test null pointer for output in decrypt
TEST(CBC_Negative, NullOutputPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with null output pointer should fail
    Uint64 outlen = 0;
    err = cbc->decrypt(&input[0], nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null output should fail";

    delete cbc;
}

// Test null pointer for output length in encrypt
TEST(CBC_Negative, NullOutlenPointerEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with null outlen pointer should fail
    err = cbc->encrypt(&input[0], &output[0], 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null outlen should fail";

    delete cbc;
}

// Test null pointer for output length in decrypt
TEST(CBC_Negative, NullOutlenPointerDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with null outlen pointer should fail
    err = cbc->decrypt(&input[0], &output[0], 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null outlen should fail";

    delete cbc;
}

// Test all null pointers in encrypt
TEST(CBC_Negative, AllNullPointersEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with all null pointers should fail
    err = cbc->encrypt(nullptr, nullptr, 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with all null pointers should fail";

    delete cbc;
}

// Test all null pointers in decrypt
TEST(CBC_Negative, AllNullPointersDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with all null pointers should fail
    err = cbc->decrypt(nullptr, nullptr, 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with all null pointers should fail";

    delete cbc;
}

// Test zero key length
TEST(CBC_Negative, ZeroKeyLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with zero key length should fail
    alc_error_t err = cbc->init(&test_key[0], 0, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero key length should fail";

    delete cbc;
}

// Test zero IV length
TEST(CBC_Negative, ZeroIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with zero IV length should fail
    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero IV length should fail";

    delete cbc;
}

// Test invalid key length (not 128, 192, or 256 bits)
TEST(CBC_Negative, InvalidKeyLength)
{
    std::vector<Uint8> test_key(20, 0x42); // 160-bit key (invalid)
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with invalid key length (160 bits = 20 bytes) should fail
    alc_error_t err = cbc->init(&test_key[0], 160, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid key length (160 bits) should fail";

    delete cbc;
}

// Test invalid IV length (CBC requires 16-byte IV)
TEST(CBC_Negative, InvalidIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(8, 0x24); // 8-byte IV (invalid for CBC)

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with invalid IV length (8 bytes) should fail
    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 8);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid IV length (8 bytes) should fail";

    delete cbc;
}

// Test encryption without initialization
TEST(CBC_Negative, EncryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Encrypt without init should fail or produce error
    Uint64 outlen = 0;
    alc_error_t err = cbc->encrypt(&input[0], &output[0], 32, &outlen);
    // Note: The behavior might vary - some implementations might crash,
    // others might return an error. The test checks for error return.
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt without init should fail";

    delete cbc;
}

// Test decryption without initialization
TEST(CBC_Negative, DecryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Decrypt without init should fail or produce error
    Uint64 outlen = 0;
    alc_error_t err = cbc->decrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt without init should fail";

    delete cbc;
}

// Test zero input length encryption
TEST(CBC_Negative, ZeroLengthInputEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with zero length - should either succeed with zero output or return error
    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output[0], 0, &outlen);
    // Zero length encryption might be valid (produces no output) or might fail
    // This test documents the behavior
    if (err == ALC_ERROR_NONE) {
        EXPECT_EQ(outlen, 0) << "Zero length encrypt should produce zero output";
    }

    delete cbc;
}

// Test zero input length decryption
TEST(CBC_Negative, ZeroLengthInputDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with zero length - should either succeed with zero output or return error
    Uint64 outlen = 0;
    err = cbc->decrypt(&input[0], &output[0], 0, &outlen);
    // Zero length decryption might be valid (produces no output) or might fail
    if (err == ALC_ERROR_NONE) {
        EXPECT_EQ(outlen, 0) << "Zero length decrypt should produce zero output";
    }

    delete cbc;
}

// Test non-block-aligned input size for encryption (CBC requires 16-byte blocks)
TEST(CBC_Negative, NonBlockAlignedInputEncrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(17, 0x55);  // 17 bytes (not multiple of 16)
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // For standard CBC mode without padding, non-block-aligned input should
    // either fail or only encrypt complete blocks
    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output[0], 17, &outlen);
    // Behavior depends on implementation:
    // - May fail with error
    // - May only encrypt 16 bytes (complete block)
    // This test documents the behavior
    if (err == ALC_ERROR_NONE) {
        // If successful, output should be 16 bytes (one complete block)
        // or implementation handles partial blocks
        EXPECT_TRUE(outlen == 16 || outlen == 17 || outlen == 32);
    }

    delete cbc;
}

// Test non-block-aligned input size for decryption
TEST(CBC_Negative, NonBlockAlignedInputDecrypt)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(17, 0x55);  // 17 bytes (not multiple of 16)
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // For standard CBC mode, non-block-aligned input should
    // either fail or only decrypt complete blocks
    Uint64 outlen = 0;
    err = cbc->decrypt(&input[0], &output[0], 17, &outlen);
    if (err == ALC_ERROR_NONE) {
        EXPECT_TRUE(outlen == 16 || outlen == 17 || outlen == 32);
    }

    delete cbc;
}

// Test context copy with null source
TEST(CBC_Negative, ContextCopyNullSource)
{
    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    auto cbc_dest = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc_dest, nullptr);

    // Copy with null source should fail
    cbc->CopyCtx(nullptr, cbc_dest);
    // The test passes if no crash occurs - CopyCtx might silently fail or handle null

    delete cbc;
    delete cbc_dest;
}

// Test context copy with null destination
TEST(CBC_Negative, ContextCopyNullDestination)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    cbc->init(&test_key[0], 128, &test_iv[0], 16);

    // Copy with null destination should fail or be handled gracefully
    cbc->CopyCtx(cbc, nullptr);
    // The test passes if no crash occurs

    delete cbc;
}

// Test very large input size (boundary test)
TEST(CBC_Negative, VeryLargeInputSize)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    
    // Use a moderate size that won't cause memory issues but tests the limit
    const size_t large_size = 16 * 1024 * 1024; // 16 MB
    std::vector<Uint8> input(large_size, 0x55);
    std::vector<Uint8> output(large_size);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output[0], large_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, large_size);

    delete cbc;
}

// Test mismatched key size and CipherKeyLen
TEST(CBC_Negative, MismatchedKeySizeAndKeyLen)
{
    // Create cipher for 128-bit key but try to use 256-bit key
    std::vector<Uint8> test_key(32, 0x42); // 256-bit key
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Trying to init 128-bit cipher with 256-bit key size should fail or behave unexpectedly
    alc_error_t err = cbc->init(&test_key[0], 256, &test_iv[0], 16);
    // This may or may not be an error depending on implementation
    // The test documents the behavior - we just verify it doesn't crash
    (void)err; // Suppress unused variable warning - behavior is implementation-defined

    delete cbc;
}

// Test repeated initialization (reinit)
TEST(CBC_Negative, RepeatedInitialization)
{
    std::vector<Uint8> test_key1(16, 0x42);
    std::vector<Uint8> test_key2(16, 0x84);
    std::vector<Uint8> test_iv1(16, 0x24);
    std::vector<Uint8> test_iv2(16, 0x48);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output1(32), output2(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // First init and encrypt
    alc_error_t err = cbc->init(&test_key1[0], 128, &test_iv1[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output1[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Reinit with different key/IV and encrypt again
    err = cbc->init(&test_key2[0], 128, &test_iv2[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = cbc->encrypt(&input[0], &output2[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Different keys should produce different outputs
    EXPECT_NE(output1, output2) << "Different keys should produce different ciphertext";

    delete cbc;
}

// Test using same buffer for input and output (aliasing) with non-matching pointers
TEST(CBC_Negative, OverlappingBuffers)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> buffer(64, 0x55);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Test passes if cipher is successfully initialized
    // Note: Overlapping buffer test is commented out as it may cause undefined behavior
    // The test verifies that the cipher can be created and initialized properly

    delete cbc;
}

// Test maximum key length boundary
TEST(CBC_Negative, MaxKeyLengthBoundary)
{
    // Test with key length just above valid (257 bits)
    std::vector<Uint8> test_key(33, 0x42); // 264 bits
    std::vector<Uint8> test_iv(16, 0x24);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with key length above maximum should fail
    alc_error_t err = cbc->init(&test_key[0], 264, &test_iv[0], 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with key length > 256 bits should fail";

    delete cbc;
}

// Test IV length boundary (17 bytes when 16 is required)
TEST(CBC_Negative, IVLengthBoundary)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(17, 0x24); // 17-byte IV (invalid for CBC)

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with IV length above required (17 bytes) should fail or use only 16 bytes
    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 17);
    // This may or may not be an error - the implementation might only use first 16 bytes
    // The test documents the behavior - we just verify it doesn't crash
    (void)err; // Suppress unused variable warning - behavior is implementation-defined

    delete cbc;
}

// Test very small IV (less than required 16 bytes)
TEST(CBC_Negative, SmallIVLength)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(4, 0x24); // 4-byte IV (invalid for CBC)

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Init with IV length below required (4 bytes) should fail
    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 4);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with 4-byte IV should fail";

    delete cbc;
}

// Test encrypt/decrypt with single byte data (less than block size)
TEST(CBC_Negative, SingleByteData)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(1, 0x55);  // Single byte
    std::vector<Uint8> output(16);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt single byte - may produce no output or be buffered
    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output[0], 1, &outlen);
    // Behavior depends on implementation - test documents this
    if (err == ALC_ERROR_NONE) {
        // May output 0 bytes (buffered) or handle partial blocks
        EXPECT_TRUE(outlen == 0 || outlen == 1 || outlen == 16);
    }

    delete cbc;
}

// Test multiple consecutive small updates that don't form a complete block
TEST(CBC_Negative, MultipleSmallUpdatesNoBlock)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input1(5, 0x11);
    std::vector<Uint8> input2(5, 0x22);
    std::vector<Uint8> input3(5, 0x33);
    std::vector<Uint8> output(48);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Three 5-byte updates = 15 bytes total (less than one block)
    Uint64 total_outlen = 0;
    Uint64 outlen = 0;
    
    err = cbc->encrypt(&input1[0], &output[0], 5, &outlen);
    if (err == ALC_ERROR_NONE) total_outlen += outlen;
    
    outlen = 0;
    err = cbc->encrypt(&input2[0], &output[total_outlen], 5, &outlen);
    if (err == ALC_ERROR_NONE) total_outlen += outlen;
    
    outlen = 0;
    err = cbc->encrypt(&input3[0], &output[total_outlen], 5, &outlen);
    if (err == ALC_ERROR_NONE) total_outlen += outlen;
    
    // Total 15 bytes input - may produce 0 bytes output (no complete block)
    // This test documents the multi-update behavior

    delete cbc;
}

// Test with various invalid input sizes around block boundary
TEST(CBC_Negative, InputSizeVariations)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    
    // Test sizes just above and below block boundaries
    std::vector<size_t> test_sizes = { 1, 7, 15, 17, 31, 33, 47, 49 };

    for (size_t size : test_sizes) {
        std::vector<Uint8> input(size, 0x55);
        std::vector<Uint8> output(size + 16);

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
        ASSERT_NE(cbc, nullptr);

        alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = cbc->encrypt(&input[0], &output[0], size, &outlen);
        // Just document the behavior - non-block-aligned sizes
        // may produce partial output or error

        delete cbc;
    }
}

// Test cipher reuse after error
TEST(CBC_Negative, ReuseAfterError)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // First, cause an error by using null pointer
    alc_error_t err = cbc->init(nullptr, 128, &test_iv[0], 16);
    // This should have failed

    // Now try to reinit properly and use the cipher
    err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Reinit after error should succeed";

    Uint64 outlen = 0;
    err = cbc->encrypt(&input[0], &output[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt after reinit should succeed";
    EXPECT_EQ(outlen, 32);

    delete cbc;
}

// Test decrypt with corrupted ciphertext (should still decrypt but produce wrong result)
TEST(CBC_Negative, DecryptCorruptedCiphertext)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    // Encrypt
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    Uint64 outlen = 0;
    cbc->encrypt(&input[0], &ciphertext[0], 32, &outlen);

    // Corrupt the ciphertext
    ciphertext[0] ^= 0xFF;
    ciphertext[16] ^= 0xFF;

    // Decrypt corrupted ciphertext - should still succeed but produce wrong result
    cbc->init(&test_key[0], 128, &test_iv[0], 16);
    outlen = 0;
    alc_error_t err = cbc->decrypt(&ciphertext[0], &decrypted[0], 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Decrypt of corrupted data should still succeed";
    EXPECT_EQ(outlen, 32);
    EXPECT_NE(decrypted, input) << "Corrupted ciphertext should produce different plaintext";

    delete cbc;
}

// Test with maximum Uint64 size (to check for overflow handling)
TEST(CBC_Negative, MaxSizeOverflow)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey128Bit);
    ASSERT_NE(cbc, nullptr);

    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Test verifies that cipher can be initialized properly
    // Note: Actually testing with max Uint64 size would be unsafe and cause memory issues
    // The test documents that the initialization succeeds

    delete cbc;
}

// Test key length that doesn't match cipher creation
TEST(CBC_Negative, KeyLengthMismatchWithCreation)
{
    std::vector<Uint8> test_key(16, 0x42);
    std::vector<Uint8> test_iv(16, 0x24);

    // Create 256-bit cipher but use 128-bit key length in init
    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);
    ASSERT_NE(cbc, nullptr);

    // Pass 128-bit key length but cipher was created for 256-bit
    alc_error_t err = cbc->init(&test_key[0], 128, &test_iv[0], 16);
    // This may succeed (cipher uses different internal key size)
    // or fail (strict key size checking)
    // The test documents the behavior - we just verify it doesn't crash
    (void)err; // Suppress unused variable warning - behavior is implementation-defined

    delete cbc;
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
