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

#include <algorithm>
#include <memory>
#include <numeric>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "debug_defs.hh"
#include "dispatcher.hh"
#include "randomize.hh"

#undef DEBUG

#if 0
using alcp::cipher::Cbc;
#endif

using alcp::cipher::CipherFactory;
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
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc        = alcpCipher->create("aes-cbc-128", feature);
        if (cbc == nullptr) {
            delete alcpCipher;
            FAIL();
        }
        delete alcpCipher;
    }
}

TEST(CBC, BasicEncryption)
{
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
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

    delete alcpCipher;
}

TEST(CBC, BasicDecryption)
{
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
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

    delete alcpCipher;
}

TEST(CBC, ContextCopyEncryption)
{
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Copy the context
    auto alcpCipher2_cpy = new CipherFactory<iCipher>;
    auto cbc_copy        = alcpCipher2_cpy->create("aes-cbc-128");
    if (cbc_copy == nullptr) {
        delete alcpCipher;
        delete alcpCipher2_cpy;
        FAIL();
    }
    cbc->CopyCtx(cbc, cbc_copy);

    Uint64 outlen = 0;
    cbc_copy->encrypt(&plainText[0], &output[0], plainText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        cipherText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(cipherText, output);

    delete alcpCipher;
    delete alcpCipher2_cpy;
}

TEST(CBC, ContextCopyDecryption)
{
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
        FAIL();
    }
    std::vector<Uint8> output(cipherText.size());

    cbc->init(&key[0], key.size() * 8, &iv[0], iv.size());

    // Copy the context
    auto alcpCipher2_cpy = new CipherFactory<iCipher>;
    auto cbc_copy        = alcpCipher2_cpy->create("aes-cbc-128");
    if (cbc_copy == nullptr) {
        delete alcpCipher;
        delete alcpCipher2_cpy;
        FAIL();
    }
    cbc->CopyCtx(cbc, cbc_copy);

    Uint64 outlen = 0;
    cbc_copy->decrypt(&cipherText[0], &output[0], cipherText.size(), &outlen);
    EXPECT_EQ(
        outlen,
        plainText.size()); // Should produce full output for complete blocks

    EXPECT_EQ(plainText, output);

    delete alcpCipher;
    delete alcpCipher2_cpy;
}

TEST(CBC, MultiUpdateEncryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
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

    delete alcpCipher;
}

TEST(CBC, MultiUpdateEncryptionSmallChunks)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
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

    delete alcpCipher;
}

TEST(CBC, MultiUpdateDecryption)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    // Test for all arch
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete alcpCipher;
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
            << std::underlying_type<CpuCipherFeatures>::type(feature);

        delete alcpCipher;
    }
}
TEST(CBC, MultiUpdateDecryptionSmallChunks)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    auto alcpCipher = new CipherFactory<iCipher>;
    auto cbc        = alcpCipher->create("aes-cbc-128"); // KeySize is 128 bits

    if (cbc == nullptr) {
        delete alcpCipher;
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

    delete alcpCipher;
}

TEST(CBC, InplaceEncryption)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place encryption functionality disabled!";
#endif
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    // Test for all arch
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc =
            alcpCipher->create("aes-cbc-128", feature); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete alcpCipher;
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
            << std::underlying_type<CpuCipherFeatures>::type(feature);

        delete alcpCipher;
    }
}

TEST(CBC, InplaceDecryption)
{
#ifndef CBC_INPLACE_BUFFER
    GTEST_SKIP() << "In-place decryption functionality disabled!";
#endif
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    // Test for all arch
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc =
            alcpCipher->create("aes-cbc-128", feature); // KeySize is 128 bits

        if (cbc == nullptr) {
            delete alcpCipher;
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
            << std::underlying_type<CpuCipherFeatures>::type(feature);

        delete alcpCipher;
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
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    // Test for all arch
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc        = alcpCipher->create("aes-cbc-128", feature);

        if (cbc == nullptr) {
            delete alcpCipher;
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
            << std::underlying_type<CpuCipherFeatures>::type(feature);

        delete alcpCipher;
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

    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        const std::vector<Uint8> plainTextVect(plain_text_vect.begin(),
                                               plain_text_vect.end());
        std::vector<Uint8>       plainTextOut(plainTextVect.size());
        auto                     alcpCipher = new CipherFactory<iCipher>;
        auto cbc = alcpCipher->create("aes-cbc-256", feature);

        if (cbc == nullptr) {
            delete alcpCipher;
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

        delete alcpCipher;
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

    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    for (CpuCipherFeatures feature : cpu_features) {
        /* FIXME: run this test only for zen4 for now? */
        if (feature != CpuCipherFeatures::eVaes512) {
            std::cout << "Skipping test for feature avx512 " << std::endl;
            continue;
        }
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc        = alcpCipher->create("aes-cbc-256", feature);

        if (cbc == nullptr) {
            delete alcpCipher;
            FAIL();
        }
        cbc->init(key_256, 256, nullptr, 0);
        cbc->multibufferInit(
            key_256, 256, iv_vect.data(), iv_vect.size(), num_buffers);

        // Test flush and dequeue operations
        alc_error_t err =
            cbc->flush(plain_text_vect.data(), num_buffers, cTextSize);
        EXPECT_FALSE(alcp_is_error(err));

        err = cbc->dequeue(cipher_text_vect.data(), num_buffers, cTextSize);
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

        delete alcpCipher;
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
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();
    for (CpuCipherFeatures feature : cpu_features) {
        auto alcpCipher = new CipherFactory<iCipher>;
        auto cbc        = alcpCipher->create("aes-cbc-128", feature);

        if (cbc == nullptr) {
            delete alcpCipher;
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
            auto alcpCipher2 = new CipherFactory<iCipher>;
            auto cbc2        = alcpCipher2->create("aes-cbc-128", feature);
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
            delete alcpCipher2;
        }

        // Factory destructor will clean up the cipher object
        delete alcpCipher;
    }
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
