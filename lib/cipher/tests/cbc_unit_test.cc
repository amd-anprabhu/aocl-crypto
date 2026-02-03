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

TEST(CBC, InplaceDecryptionSmallBlocks)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif

    // Test sizes that specifically hit the blocks < 4 path (the buggy path)
    // 1 block = 16 bytes, 2 blocks = 32 bytes, 3 blocks = 48 bytes
    std::vector<size_t> small_block_counts = { 1, 2, 3 };

    for (size_t num_blocks : small_block_counts) {
        size_t data_size = num_blocks * 16;

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            FAIL() << "Failed to create CBC cipher";
        }

        // Create test data with recognizable pattern
        std::vector<Uint8> original_plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            original_plaintext[i] = static_cast<Uint8>('A' + (i % 26));
        }

        std::vector<Uint8> test_key(32, 0x42);
        std::vector<Uint8> test_iv(16, 0x17);
        std::vector<Uint8> buffer(data_size);

        // Encrypt: plaintext -> buffer (separate buffers)
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = cbc->encrypt(&original_plaintext[0], &buffer[0], data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, data_size);

        // Decrypt IN-PLACE: buffer -> buffer (same buffer!)
        // This is the critical test case
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        err = cbc->decrypt(&buffer[0], &buffer[0], data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, data_size);

        // Verify decrypted data matches original
        EXPECT_EQ(buffer, original_plaintext)
            << "In-place decryption failed for " << num_blocks << " blocks";

        delete cbc;
    }
}

/**
 * @brief Test in-place CBC decryption with large block counts for all architectures
 *
 * This test verifies in-place CBC decryption for large data sizes (>= 256 bytes)
 * across all supported CPU architectures. A previous bug in VAES512 (Zen4+ only)
 * manifested for in-place decryption when processing more than 16 blocks (>= 256 bytes),
 * where the next IV was read from already-overwritten ciphertext.
 */
TEST(CBC, InplaceDecryptionLargeBlocks)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif

    // Sizes chosen to cross the 16-block (256-byte) boundary and exercise
    // multiple optimized loop iterations.
    std::vector<size_t> block_counts = { 17, 18, 32, 33, 64 };

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

    if (cbc == nullptr) {
        FAIL() << "Failed to create CBC cipher";
    }

    std::vector<Uint8> test_key(32, 0x42);
    std::vector<Uint8> test_iv(16, 0x17);

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;

        // Plaintext pattern (non-random) to make corruption obvious.
        std::vector<Uint8> plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>(0xA0 ^ (i & 0xFF));
        }

        std::vector<Uint8> ciphertext(data_size);

        // Encrypt out-of-place to produce ciphertext.
        Uint64 outlen = 0;
        auto   err    = cbc->init(test_key.data(), 256, test_iv.data(), 16);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        err = cbc->encrypt(plaintext.data(), ciphertext.data(), data_size, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        ASSERT_EQ(outlen, data_size);

        // Decrypt IN-PLACE: ciphertext -> ciphertext.
        err = cbc->init(test_key.data(), 256, test_iv.data(), 16);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err    = cbc->decrypt(ciphertext.data(),
                           ciphertext.data(),
                           data_size,
                           &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        ASSERT_EQ(outlen, data_size);

        EXPECT_EQ(ciphertext, plaintext)
            << "In-place CBC decryption mismatch for " << num_blocks
            << " blocks (" << data_size << " bytes)";
    }

    delete cbc;
}

/**
 * @brief Comprehensive kernel transition tests for in-place CBC decryption
 *
 * TEST SCENARIO:
 * The VAES512 CBC decrypt implementation selects different optimized kernels
 * based on the number of blocks to process:
 *   - 16-block kernel: Decrypts 16 blocks (256 bytes) at once using 4x512-bit registers
 *   - 8-block kernel:  Decrypts 8 blocks (128 bytes) at once using 2x512-bit registers
 *   - 4-block kernel:  Decrypts 4 blocks (64 bytes) at once using 1x512-bit register
 *   - 1-block kernel:  Decrypts 1 block (16 bytes) at a time (residual loop)
 *
 * WHAT THIS TEST VERIFIES:
 * When the code decrypts in-place (same buffer for input and output), it must
 * save the ciphertext block BEFORE overwriting it with plaintext, because
 * the next block's XOR operation requires that ciphertext block as the IV.
 *
 * This test verifies that IV chaining works correctly when the code:
 * 1. Transitions between different kernel sizes (e.g., 16-block → 4-block)
 * 2. Uses the last block of one kernel as the IV for the first block of the next kernel
 *
 * POTENTIAL BUG PATTERN:
 * If the code fails to pre-load the next IV before storing decrypted data,
 * the in-place write corrupts the ciphertext that the next block's decryption
 * requires, causing all subsequent blocks to decrypt incorrectly.
 *
 */
TEST(CBC, InplaceDecryptionKernelTransitions)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif

    // Test all kernel transition points
    std::vector<size_t> block_counts = {
        // Single kernel tests
        4, 8, 16,
        // 4-block + residual (1-3 blocks)
        5, 6, 7,
        // 8-block + residual
        9, 10, 11,
        // 8-block + 4-block
        12,
        // 8-block + 4-block + residual
        13, 14, 15,
        // 16-block + residual (1-3 blocks)
        17, 18, 19,
        // 16-block + 4-block
        20,
        // 16-block + 4-block + residual
        21, 22, 23,
        // 16-block + 8-block
        24,
        // 16-block + 8-block + residual
        25, 26, 27,
        // 16-block + 8-block + 4-block
        28,
        // 16-block + 8-block + 4-block + residual
        29, 30, 31,
        // Multiple 16-block iterations
        32, 33, 36, 40, 44, 48,
        // Large sizes
        64, 100, 128
    };

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            FAIL() << "Failed to create CBC cipher";
        }

        // Create test data with recognizable pattern
        std::vector<Uint8> original_plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            // Use a pattern that makes corruption obvious
            original_plaintext[i] = static_cast<Uint8>((i / 16) ^ (i % 16));
        }

        std::vector<Uint8> test_key(32);
        std::vector<Uint8> test_iv(16);
        // Use deterministic but non-trivial key/IV
        for (int i = 0; i < 32; i++) test_key[i] = static_cast<Uint8>(0x42 + i);
        for (int i = 0; i < 16; i++) test_iv[i] = static_cast<Uint8>(0x17 + i);

        std::vector<Uint8> buffer(data_size);

        // Encrypt: plaintext -> buffer (separate buffers)
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = cbc->encrypt(&original_plaintext[0], &buffer[0], data_size, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for " << num_blocks << " blocks";
        ASSERT_EQ(outlen, data_size);

        // Decrypt IN-PLACE: buffer -> buffer (same buffer!)
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        err = cbc->decrypt(&buffer[0], &buffer[0], data_size, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE) << "Decrypt failed for " << num_blocks << " blocks";
        ASSERT_EQ(outlen, data_size);

        // Verify decrypted data matches original
        bool match = (buffer == original_plaintext);
        if (!match) {
            // Find first mismatch for debugging
            for (size_t i = 0; i < data_size; i++) {
                if (buffer[i] != original_plaintext[i]) {
                    std::cout << "First mismatch at byte " << i 
                              << " (block " << (i / 16) << ", offset " << (i % 16) << ")"
                              << " expected: 0x" << std::hex << (int)original_plaintext[i]
                              << " got: 0x" << (int)buffer[i] << std::dec << std::endl;
                    break;
                }
            }
        }
        EXPECT_TRUE(match)
            << "In-place decryption failed for " << num_blocks << " blocks"
            << " (" << data_size << " bytes)";

        delete cbc;
    }
}

/**
 * @brief Test multi-update in-place decryption with kernel transitions
 *
 * TEST SCENARIO:
 * In multi-update mode, the application calls decrypt() multiple times with
 * different chunk sizes. The cipher maintains the IV state between calls,
 * using the last ciphertext block from the previous call as the IV for the next call.
 *
 * WHAT THIS TEST VERIFIES:
 * This test verifies that the code:
 * 1. Saves the IV correctly after each decrypt() call (last ciphertext block)
 * 2. Uses the saved IV correctly for the next decrypt() call
 * 3. Handles different kernel sizes across calls without corruption
 *
 * POTENTIAL BUG PATTERN:
 * If the code fails to save the last ciphertext block as the new IV after
 * each decrypt() call, subsequent calls use the wrong IV, causing
 * decryption to fail starting from the second call.
 *
 */
TEST(CBC, MultiUpdateInplaceDecryptionKernelTransitions)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif

    // Test patterns: each vector represents chunk sizes (in bytes) for multi-update
    std::vector<std::vector<size_t>> test_patterns = {
        // Transition from large kernel to small kernel
        {256, 16},   // 16-block then 1-block
        {256, 32},   // 16-block then 2-block
        {256, 48},   // 16-block then 3-block
        {256, 64},   // 16-block then 4-block
        {256, 128},  // 16-block then 8-block
        
        // Transition from small kernel to large kernel
        {16, 256},   // 1-block then 16-block
        {64, 256},   // 4-block then 16-block
        {128, 256},  // 8-block then 16-block
        
        // Multiple transitions
        {256, 64, 16},   // 16-block, 4-block, 1-block
        {16, 64, 256},   // 1-block, 4-block, 16-block
        {128, 64, 32, 16},  // 8-block, 4-block, 2-block, 1-block
        
        // Many small chunks
        {16, 16, 16, 16},  // 4x 1-block
        {32, 32, 32, 32},  // 4x 2-block
        {64, 64, 64, 64},  // 4x 4-block
        
        // Mixed sizes
        {256, 128, 64, 32, 16},  // decreasing sizes
        {16, 32, 64, 128, 256},  // increasing sizes
        {256, 16, 256, 16},      // alternating large/small
    };

    for (const auto& chunks : test_patterns) {
        // Calculate total size
        size_t total_size = 0;
        for (size_t chunk : chunks) total_size += chunk;

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            FAIL() << "Failed to create CBC cipher";
        }

        // Create test data
        std::vector<Uint8> original_plaintext(total_size);
        for (size_t i = 0; i < total_size; i++) {
            original_plaintext[i] = static_cast<Uint8>((i / 16) ^ (i % 16));
        }

        std::vector<Uint8> test_key(32);
        std::vector<Uint8> test_iv(16);
        for (int i = 0; i < 32; i++) test_key[i] = static_cast<Uint8>(0x42 + i);
        for (int i = 0; i < 16; i++) test_iv[i] = static_cast<Uint8>(0x17 + i);

        std::vector<Uint8> buffer(total_size);

        // Encrypt in one shot
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        auto err = cbc->encrypt(&original_plaintext[0], &buffer[0], total_size, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);

        // Decrypt IN-PLACE in multiple chunks
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        size_t offset = 0;
        for (size_t chunk_size : chunks) {
            Uint64 chunk_outlen = 0;
            err = cbc->decrypt(&buffer[offset], &buffer[offset], chunk_size, &chunk_outlen);
            ASSERT_EQ(err, ALC_ERROR_NONE) 
                << "Decrypt failed at offset " << offset 
                << " for chunk size " << chunk_size;
            offset += chunk_size;
        }

        // Verify
        bool match = (buffer == original_plaintext);
        if (!match) {
            std::cout << "Pattern: ";
            for (size_t c : chunks) std::cout << c << " ";
            std::cout << std::endl;
            for (size_t i = 0; i < total_size; i++) {
                if (buffer[i] != original_plaintext[i]) {
                    std::cout << "First mismatch at byte " << i 
                              << " (block " << (i / 16) << ")"
                              << " expected: 0x" << std::hex << (int)original_plaintext[i]
                              << " got: 0x" << (int)buffer[i] << std::dec << std::endl;
                    break;
                }
            }
        }
        EXPECT_TRUE(match)
            << "Multi-update in-place decryption failed";

        delete cbc;
    }
}

/**
 * @brief Test non-inplace decryption with kernel transitions
 *
 * TEST SCENARIO:
 * This baseline test verifies that non-inplace decryption works correctly
 * for all block counts. Unlike in-place mode, non-inplace mode does not have
 * the IV corruption issue because the code never overwrites the ciphertext buffer.
 *
 * WHAT THIS TEST VERIFIES:
 * This test serves as a reference to compare against in-place tests. If this
 * test passes but in-place tests fail, it confirms the bug exists specifically
 * in the in-place buffer handling logic.
 *
 * TEST CASES:
 * All block counts from 4 to 100, covering all kernel transition points.
 */
TEST(CBC, NonInplaceDecryptionKernelTransitions)
{
    std::vector<size_t> block_counts = {
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 36, 40, 44, 48, 64, 100
    };

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;

        auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

        if (cbc == nullptr) {
            FAIL() << "Failed to create CBC cipher";
        }

        std::vector<Uint8> plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>((i / 16) ^ (i % 16));
        }

        std::vector<Uint8> test_key(32);
        std::vector<Uint8> test_iv(16);
        for (int i = 0; i < 32; i++) test_key[i] = static_cast<Uint8>(0x42 + i);
        for (int i = 0; i < 16; i++) test_iv[i] = static_cast<Uint8>(0x17 + i);

        std::vector<Uint8> ciphertext(data_size);
        std::vector<Uint8> decrypted(data_size);

        // Encrypt
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        cbc->encrypt(&plaintext[0], &ciphertext[0], data_size, &outlen);

        // Decrypt (non-inplace)
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        cbc->decrypt(&ciphertext[0], &decrypted[0], data_size, &outlen);

        EXPECT_EQ(decrypted, plaintext)
            << "Non-inplace decryption failed for " << num_blocks << " blocks";

        delete cbc;
    }
}

/**
 * @brief Stress test with random data and sizes
 */
TEST(CBC, InplaceDecryptionRandomStress)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif

    std::mt19937 gen(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<> size_dist(1, 200); // 1-200 blocks

    auto cbc = createCipher(CipherMode::eAesCBC, CipherKeyLen::eKey256Bit);

    if (cbc == nullptr) {
        FAIL() << "Failed to create CBC cipher";
    }

    // Run 100 random tests
    for (int test = 0; test < 100; test++) {
        size_t num_blocks = size_dist(gen);
        size_t data_size = num_blocks * 16;

        std::vector<Uint8> plaintext(data_size);
        std::vector<Uint8> test_key(32);
        std::vector<Uint8> test_iv(16);

        // Random data
        std::uniform_int_distribution<> byte_dist(0, 255);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>(byte_dist(gen));
        }
        for (int i = 0; i < 32; i++) test_key[i] = static_cast<Uint8>(byte_dist(gen));
        for (int i = 0; i < 16; i++) test_iv[i] = static_cast<Uint8>(byte_dist(gen));

        std::vector<Uint8> buffer(data_size);

        // Encrypt
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        Uint64 outlen = 0;
        cbc->encrypt(&plaintext[0], &buffer[0], data_size, &outlen);

        // Decrypt in-place
        cbc->init(&test_key[0], 256, &test_iv[0], 16);
        cbc->decrypt(&buffer[0], &buffer[0], data_size, &outlen);

        EXPECT_EQ(buffer, plaintext)
            << "Random stress test failed for " << num_blocks << " blocks"
            << " (test #" << test << ")";
    }

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
