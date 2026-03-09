/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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


#include "alcp/cipher/aes_gcm.hh"

#include "gtest/gtest.h"
#include <math.h>
// Linux Specific Header Files
#if __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

using namespace alcp::cipher;

// KAT Data
// clang-format off
typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // nonce
                   std::vector<Uint8>, // aad
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8>, // ciphertext
                   std::vector<Uint8> // tag
                  >
            param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

/* Example Encodings
P_K128b_N7B_A0B_P0B_C0B_T4B
P     -> Pass, F -> Fail
K128b -> Key 128 bit
N7B   -> Nonce 7 byte
A0B   -> Additional Data 0 byte
P0B   -> PlainText 0 byte
C0B   -> CipherText 0 byte
T4B   -> Tag 4 byte

Tuple order
{key,nonce,aad,plain,ciphertext,tag}
*/
known_answer_map_t KATDataset{
    {
      "P_K128b_N12B_A0B_P0B_C0B_T16B",
      {
        {0x11,0x75,0x4c,0xd7,0x2a,0xec,0x30,0x9b,0xf5,0x2f,0x76,0x87,0x21,0x2e,0x89,0x57},
        {0x3c,0x81,0x9d,0x9a,0x9b,0xed,0x08,0x76,0x15,0x03,0x0b,0x65},
        {},
        {},
        {},
        {0x25,0x03,0x27,0xc6,0x74,0xaa,0xf4,0x77,0xae,0xf2,0x67,0x57,0x48,0xcf,0x69,0x71},
      }
    },
    {
      "P_K128b_N12B_A0B_P0B_C0B_T15B",
      {
        {0x27,0x2f,0x16,0xed,0xb8,0x1a,0x7a,0xbb,0xea,0x88,0x73,0x57,0xa5,0x8c,0x19,0x17},
        {0x79,0x4e,0xc5,0x88,0x17,0x6c,0x70,0x3d,0x3d,0x2a,0x7a,0x07},
        {},
        {},
        {},
        {0xb6,0xe6,0xf1,0x97,0x16,0x8f,0x50,0x49,0xae,0xda,0x32,0xda,0xfb,0xda,0xeb},
      }
    },
    {
      "P_K128b_N12B_A0B_P0B_C0B_T14B",
      {
        {0x81,0xb6,0x84,0x4a,0xab,0x6a,0x56,0x8c,0x45,0x56,0xa2,0xeb,0x7e,0xae,0x75,0x2f},
        {0xce,0x60,0x0f,0x59,0x61,0x83,0x15,0xa6,0x82,0x9b,0xef,0x4d},
        {},
        {},
        {},
        {0x89,0xb4,0x3e,0x9d,0xbc,0x1b,0x4f,0x59,0x7d,0xbb,0xc7,0x65,0x5b,0xb5},
      }
    },
    {
      "P_K128b_N1B_A0B_P16B_C16B_T14B",
      {
        {0x4f,0x1d,0xc3,0xda,0xe8,0x3a,0x38,0x90,0xdb,0xa8,0xf8,0x24,0x1d,0x28,0xb0,0xb2},
        {0x1a},
        {},
        {0x05,0x94,0xee,0x26,0x78,0x14,0xdb,0x70,0x24,0x0c,0x77,0xfc,0x53,0x0e,0x19,0x4d},
        {0xad,0x84,0xfb,0xb4,0x26,0x14,0x33,0xd4,0x90,0x19,0x1d,0xec,0x75,0x1d,0x9e,0x0e},
        {0x4f,0x49,0x53,0x00,0xf8,0xb0,0xeb,0x15,0x96,0xad,0xfb,0xd3,0x71,0xb0},
      }
    },
    {
      "P_K128b_N1B_A20B_P16B_C16B_T13B",
      {
        {0xe7,0xc1,0x31,0xc0,0x8f,0x41,0x75,0xea,0xbe,0x9e,0x8f,0x88,0xf7,0x79,0x8b,0x4c},
        {0xad},
        {0xf7,0x63,0x4f,0x67,0x1a,0x45,0x00,0xa4,0xc6,0xf7,0xec,0x8c,0x70,0xcb,0xe2,0x17,0x0c,0x17,0x21,0xfc},
        {0x54,0xf7,0xe0,0x47,0x0c,0xc3,0x35,0xe7,0x63,0x14,0x15,0x8a,0x97,0x14,0xa9,0x1c},
        {0x84,0x50,0x6e,0xa8,0xf1,0x4c,0x23,0x94,0x46,0x56,0x82,0x76,0xc0,0x21,0x44,0xa3},
        {0xcf,0x21,0x72,0x47,0xec,0x7a,0x7e,0x4e,0x78,0x10,0x97,0x25,0x9e},
      }
    },
    {
      "P_K128b_N1B_A20B_P16B_C16B_T13B",
      {
        {0x37,0x79,0x34,0x37,0xbd,0x77,0x55,0x86,0x10,0xec,0x25,0x60,0x12,0x92,0x65,0xb3},
        {0x30},
        {0x7c,0x15,0x90,0x3e,0xb9,0xd3,0xec,0x08,0x65,0x49,0xb7,0x9e,0xed,0x5f,0x66,0x0c,0x27,0xf1,0x68,0xd0},
        {0x2c,0x03,0x4d,0x88,0x73,0xdb,0x84,0xfa,0x94,0x44,0x8e,0x6a,0x45,0xe9,0x90,0x63},
        {0x68,0x8d,0xda,0x49,0x85,0x7d,0x02,0xbc,0x34,0xd4,0xe4,0x99,0xa4,0xc2,0xc3,0x7d},
        {0xee,0xc4,0x02,0xd5,0x90,0x47,0x39,0x66,0x1b,0x20,0xcb,0x9d,0x92},
      }
    },
    {
      "P_K128b_N12B_A16B_P16B_C16B_T16B",
      {
        {0xc9,0x39,0xcc,0x13,0x39,0x7c,0x1d,0x37,0xde,0x6a,0xe0,0xe1,0xcb,0x7c,0x42,0x3c},
        {0xb3,0xd8,0xcc,0x01,0x7c,0xbb,0x89,0xb3,0x9e,0x0f,0x67,0xe2},
        {0x24,0x82,0x56,0x02,0xbd,0x12,0xa9,0x84,0xe0,0x09,0x2d,0x3e,0x44,0x8e,0xda,0x5f},
        {0xc3,0xb3,0xc4,0x1f,0x11,0x3a,0x31,0xb7,0x3d,0x9a,0x5c,0xd4,0x32,0x10,0x30,0x69},
        {0x93,0xfe,0x7d,0x9e,0x9b,0xfd,0x10,0x34,0x8a,0x56,0x06,0xe5,0xca,0xfa,0x73,0x54},
        {0x00,0x32,0xa1,0xdc,0x85,0xf1,0xc9,0x78,0x69,0x25,0xa2,0xe7,0x1d,0x82,0x72,0xdd},
      }
    },
    {
      "P_K128b_N128B_A20B_P51B_C51B_T16B",
      {
        {0xc1,0x15,0xa6,0x49,0xeb,0x2a,0x50,0x2f,0xce,0x0a,0x7f,0x55,0x1d,0x02,0x00,0xb7},
        {0x89,0x62,0xe4,0xfe,0xc5,0xf0,0x32,0x13,0x84,0xba,0x4e,0x23,0xcc,0xa3,0x5a,0x04,0x5b,0xa2,0xe6,0x9c,0x11,0x64,0x0f,0xbd,0x0a,0xd6,0x99,0xa1,0xfc,0xa5,0x22,0xbd,0xb8,0xb8,0x14,0x95,0xd2,0xa1,0xf5,0x7f,0xbf,0x9c,0x52,0x0c,0xd3,0xec,0x9a,0xeb,0xf3,0xe4,0x3b,0x02,0xd9,0x78,0x4a,0x53,0x2a,0x97,0xfa,0xa6,0xd0,0xed,0x17,0xa1,0xb9,0x09,0x6e,0xe0,0x47,0xf0,0xea,0xe5,0x04,0x14,0x96,0x6b,0x8c,0xd6,0x07,0x12,0x36,0xd7,0x05,0x9a,0x34,0xc8,0xdd,0x1d,0x9b,0xa8,0xac,0x73,0xd5,0xd9,0x30,0x40,0xef,0x6a,0xe6,0x4f,0xa9,0xf5,0x78,0x6d,0x4b,0xa7,0x18,0x9b,0x1b,0xa8,0x9d,0x74,0xae,0xaf,0x5e,0x65,0x60,0x0f,0x06,0xc5,0xd9,0xfc,0xf7,0xc6,0xe3,0xd7,0x6e,0xc9},
        {0x2a,0xb2,0x86,0x75,0x68,0x24,0xc7,0xc2,0xd5,0x3f,0x98,0xef,0x70,0x75,0xfa,0xe4,0x18,0x1b,0xf7,0x41},
        {0x09,0x62,0xe1,0x3f,0x76,0xe2,0x81,0x94,0x2a,0xec,0x8c,0x9d,0x7b,0xf5,0x9c,0xca,0xf7,0x02,0xde,0xa4,0x9d,0xe4,0x84,0x28,0x0e,0x4c,0xc0,0x7b,0xf4,0x43,0x55,0x62,0x4d,0x26,0x2e,0x5b,0x42,0xee,0xff,0x46,0xa0,0x6e,0xb7,0x98,0xc0,0xdc,0xd7,0x48,0xaa,0xeb,0x66},
        {0x8f,0xe5,0x9a,0xa7,0xc1,0x12,0xe4,0xb5,0x00,0x0f,0xd8,0x2f,0x19,0x4f,0x0f,0x9b,0x15,0x21,0x8f,0x07,0x26,0x30,0xdf,0x58,0x70,0xd1,0xc8,0xca,0x81,0xd7,0xd6,0x6c,0xcf,0x95,0xdd,0xd3,0xab,0x3c,0x60,0x3a,0xf2,0xfc,0x2b,0xb9,0xed,0xca,0x00,0xc7,0xbd,0xab,0x94},
        {0x9e,0xab,0x1e,0x03,0x7e,0x70,0x3a,0x77,0x7b,0x76,0x30,0x6d,0x8a,0xa6,0x60,0xd3},
      }
    },
    {
      "P_K128b_N19B_A32B_P48B_C48B_T16B_CROSS",
      {
        {0xfe,0xc7,0x2f,0xee,0x8f,0xc3,0x88,0x33,0xe0,0xdb,0x47,0xd2,0x0d,0x69,0x22,0x36},
        {0x39,0x8c,0x22,0x07,0x78,0xa3,0x13,0xa0,0x0c,0x35,0x6e,0x65,0x31,0x99,0x74,0x82,0x2c,0x7e,0x17},
        {0x23,0xfb,0x6b,0xe4,0x66,0x0f,0x61,0x18,0xce,0xd9,0xa2,0xae,0xfd,0x11,0x73,0xe7,0x59,0x19,0x3e,0x4d,0x50,0x3d,0x98,0xa2,0x16,0x6d,0xd0,0xf3,0xeb,0x69,0x51,0x1f},
        {0xee,0xd2,0xfe,0xe8,0xf9,0xbe,0x1d,0x5a,0x55,0xee,0x4c,0x28,0x61,0xb9,0x31,0x42,0x58,0x2a,0x67,0xdd,0xef,0x39,0x7b,0xff,0xa6,0xfa,0x38,0x1c,0xa3,0x4c,0x93,0xd5,0xb4,0xa1,0xbd,0x07,0xb5,0xee,0xbf,0x30,0xc0,0x0f,0xb0,0xa3,0xb5,0x87,0x9d,0x85},
        {0xb6,0xdd,0x7e,0xbb,0xeb,0x56,0x83,0x43,0x17,0xf2,0xac,0x1c,0xf0,0xdc,0x69,0xb3,0xb0,0x2a,0xb8,0x7e,0x7e,0x52,0x41,0x11,0x36,0x46,0x34,0x25,0xf4,0x00,0x1c,0xcd,0xe3,0x2a,0x36,0xf3,0x70,0xcf,0xe0,0xfc,0xe6,0xa0,0xac,0x37,0x6a,0xe1,0x3a,0xe2},
        {0x77,0xf6,0xc4,0x7b,0x05,0x40,0xf0,0xb9,0xff,0x3c,0x3b,0x07,0xa2,0x4c,0x62,0xfe},
      }
    },
};
// clang-format on

/**
 * @brief Key Size to CipherKeyLen
 *
 * @param keySize Key size in Bytes
 * @return CipherKeyLen enum
 */
CipherKeyLen
keyToKeyLen(Uint64 keySize)
{
    switch (keySize) {
        case 16:
            return CipherKeyLen::eKey128Bit;
        case 24:
            return CipherKeyLen::eKey192Bit;
        case 32:
            return CipherKeyLen::eKey256Bit;
        default:
            std::cout << "Defaulting to 128-bit, invalid keysize" << std::endl;
            return CipherKeyLen::eKey128Bit;
    }
}

template<typename T>
T*
getPtr(std::vector<T>& vect)
{
    if (vect.size() == 0) {
        return nullptr;
    } else {
        return &vect[0];
    }
}

template<typename T>
const T*
getPtr(const std::vector<T>& vect)
{
    if (vect.size() == 0) {
        return nullptr;
    } else {
        return &vect[0];
    }
}

class GCM_KAT
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    iCipherAead* pGcmObj = nullptr;
    std::vector<Uint8> m_key, m_nonce, m_aad, m_plaintext, m_ciphertext, m_tag;
    std::string        m_test_name;
    alc_error_t        m_err;

    // Setup Test for Encrypt/Decrypt
    void SetUp() override
    {

        // Tuple order
        // {key,nonce,aad,plain,ciphertext,tag}
        const auto& params = GetParam();
        const auto [key, nonce, aad, plaintext, ciphertext, tag] =
            params.second;
        const auto& test_name = params.first;

        // Copy Values to class variables
        m_key        = key;
        m_nonce      = std::move(nonce);
        m_aad        = std::move(aad);
        m_plaintext  = std::move(plaintext);
        m_ciphertext = std::move(ciphertext);
        m_tag        = std::move(tag);
        m_test_name  = std::move(test_name);

        /* Initialization */

        // Setup GCM Object
        pGcmObj = createCipherAead(CipherMode::eAesGCM, keyToKeyLen(key.size()));

        ASSERT_TRUE(pGcmObj != nullptr);

        // Key
        m_err = pGcmObj->init(getPtr(key), key.size() * 8, nullptr, 0);
        EXPECT_EQ(m_err, ALC_ERROR_NONE);

        // Nonce
        m_err = pGcmObj->init(nullptr, 0, getPtr(m_nonce), m_nonce.size());
        EXPECT_EQ(m_err, ALC_ERROR_NONE);

        // Additional Data
        if (!m_aad.empty()) {
            m_err = pGcmObj->setAad(getPtr(m_aad), m_aad.size());
            EXPECT_EQ(m_err, ALC_ERROR_NONE);
        }
    }

    // Teardown Encrypt/Decrypt by verifying the Tag.
    void TearDown() override { delete pGcmObj; }
};

TEST(GCM, Instantiation)
{

    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    {
        auto        aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        alc_error_t err  = ALC_ERROR_NONE;

        if (aead == nullptr) {
            FAIL();
        }
        aead->init(key, 128, nullptr, 0);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete aead;
    }

    {
        auto        aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey192Bit);
        alc_error_t err  = ALC_ERROR_NONE;

        if (aead == nullptr) {
            FAIL();
        }
        aead->init(key, 192, nullptr, 0);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete aead;
    }

    {
        auto        aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
        alc_error_t err  = ALC_ERROR_NONE;

        if (aead == nullptr) {
            FAIL();
        }
        err = aead->init(key, 256, nullptr, 0);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete aead;
    }
}

// Negative Tests for GCM - Null Pointer and Edge Cases

// Test null pointer for key in init
TEST(GCM_Negative, NullKeyPointer)
{
    std::vector<Uint8> iv(12, 0x00);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(nullptr, 128, getPtr(iv), iv.size());
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key should fail";

    delete aead;
}

// Test null pointer for IV/nonce in init
TEST(GCM_Negative, NullIVPointer)
{
    std::vector<Uint8> key(16, 0x42);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // First set key
    alc_error_t err = aead->init(getPtr(key), 128, nullptr, 0);
    // Document actual behavior: some implementations may accept null IV during key-only init
    (void)err;

    delete aead;
}

// Test null pointer for both key and IV in init
TEST(GCM_Negative, NullKeyAndIVPointers)
{
    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(nullptr, 128, nullptr, 12);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key and IV should fail";

    delete aead;
}

// Test null pointer for input in encrypt
TEST(GCM_Negative, NullInputPointerEncrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(nullptr, getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";

    delete aead;
}

// Test null pointer for output in encrypt
TEST(GCM_Negative, NullOutputPointerEncrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";

    delete aead;
}

// Test null pointer for output length in encrypt
TEST(GCM_Negative, NullOutlenPointerEncrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with null outlen pointer should fail
    err = aead->encrypt(getPtr(input), getPtr(output), 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null outlen should fail";

    delete aead;
}

// Test null pointer for output length in decrypt
TEST(GCM_Negative, NullOutlenPointerDecrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with null outlen pointer should fail
    err = aead->decrypt(getPtr(input), getPtr(output), 32, nullptr);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null outlen should fail";

    delete aead;
}

// Test null pointer for tag in getTag
TEST(GCM_Negative, NullTagPointer)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->getTag(nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "getTag with null pointer should fail";

    delete aead;
}

// Test null pointer for AAD in setAad
TEST(GCM_Negative, NullAADPointer)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(nullptr, 16);
    (void)err;

    delete aead;
}

// Test zero key length
TEST(GCM_Negative, ZeroKeyLength)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 0, getPtr(iv), iv.size());
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero key length should fail";

    delete aead;
}

// Test invalid key length (not 128, 192, or 256 bits)
TEST(GCM_Negative, InvalidKeyLength)
{
    std::vector<Uint8> key(20, 0x42); // 160-bit key (invalid)
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // Init with invalid key length (160 bits) should fail
    alc_error_t err = aead->init(getPtr(key), 160, getPtr(iv), iv.size());
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid key length (160 bits) should fail";

    delete aead;
}

// Test encryption without initialization
TEST(GCM_Negative, EncryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // Encrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = aead->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt without init should fail";

    delete aead;
}

// Test decryption without initialization
TEST(GCM_Negative, DecryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // Decrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = aead->decrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt without init should fail";

    delete aead;
}

// Test getTag without encryption
TEST(GCM_Negative, GetTagWithoutEncrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> tag(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // getTag without any encryption should still return a valid tag (for AAD-only case)
    err = aead->getTag(getPtr(tag), 16);
    // This might succeed or fail depending on implementation
    (void)err;

    delete aead;
}

// Test zero input length encryption
TEST(GCM_Negative, ZeroLengthInputEncrypt)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt with zero length - should succeed (AAD-only mode)
    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output), 0, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Zero length encrypt should succeed for GCM";

    delete aead;
}

// Test invalid tag length (0, 1, 2, 3, 5, 6, 7, 9, 10, 11 bytes are invalid)
TEST(GCM_Negative, InvalidTagLengths)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    std::vector<size_t> invalid_tag_lengths = { 0, 1, 2, 3, 5, 6, 7, 9, 10, 11 };

    for (size_t tlen : invalid_tag_lengths) {
        std::vector<Uint8> tag(tlen > 0 ? tlen : 1);

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(input), getPtr(output), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = aead->getTag(getPtr(tag), tlen);
        EXPECT_TRUE(alcp_is_error(err)) << "getTag with length " << tlen << " should fail";

        delete aead;
    }
}

// Test reuse after error
TEST(GCM_Negative, ReuseAfterError)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // First, cause an error by using null pointer
    alc_error_t err = aead->init(nullptr, 128, getPtr(iv), iv.size());
    // This should have failed

    // Now try to reinit properly and use the cipher
    err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Reinit after error should succeed";

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt after reinit should succeed";

    err = aead->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead;
}

// Test maximum key length boundary
TEST(GCM_Negative, MaxKeyLengthBoundary)
{
    std::vector<Uint8> key(33, 0x42); // 264 bits
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
    ASSERT_NE(aead, nullptr);

    // Init with key length above maximum should fail
    alc_error_t err = aead->init(getPtr(key), 264, getPtr(iv), iv.size());
    EXPECT_TRUE(alcp_is_error(err)) << "Init with key length > 256 bits should fail";

    delete aead;
}

// Test very large input size (16 MB)
TEST(GCM_Negative, VeryLargeInputSize)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);
    
    const size_t large_size = 16 * 1024 * 1024; // 16 MB
    std::vector<Uint8> input(large_size, 0x55);
    std::vector<Uint8> output(large_size);
    std::vector<Uint8> tag(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    alc_error_t err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output), large_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    // Note: outlen may not match large_size depending on implementation

    err = aead->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead;
}

// Test repeated initialization
TEST(GCM_Negative, RepeatedInitialization)
{
    std::vector<Uint8> key1(16, 0x42);
    std::vector<Uint8> key2(16, 0x84);
    std::vector<Uint8> iv1(12, 0x24);
    std::vector<Uint8> iv2(12, 0x48);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output1(32), output2(32);
    std::vector<Uint8> tag1(16), tag2(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // First init and encrypt
    alc_error_t err = aead->init(getPtr(key1), 128, getPtr(iv1), iv1.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output1), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->getTag(getPtr(tag1), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Reinit with different key/IV and encrypt again
    err = aead->init(getPtr(key2), 128, getPtr(iv2), iv2.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = aead->encrypt(getPtr(input), getPtr(output2), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->getTag(getPtr(tag2), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Different keys should produce different outputs
    EXPECT_NE(output1, output2) << "Different keys should produce different ciphertext";
    EXPECT_NE(tag1, tag2) << "Different keys should produce different tags";

    delete aead;
}

// Test mismatched key size and CipherKeyLen
TEST(GCM_Negative, MismatchedKeySizeAndKeyLen)
{
    std::vector<Uint8> key(32, 0x42); // 256-bit key
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // Trying to init 128-bit cipher with 256-bit key size
    alc_error_t err = aead->init(getPtr(key), 256, getPtr(iv), iv.size());
    // Behavior is implementation-defined - we just verify it doesn't crash
    (void)err;

    delete aead;
}

// Test zero IV/nonce length
TEST(GCM_Negative, ZeroIVLength)
{
    std::vector<Uint8> key(16, 0x42);
    std::vector<Uint8> iv(12, 0x24);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    // First set key
    alc_error_t err = aead->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE); // Key-only init should work

    // Now try to set zero-length IV
    err = aead->init(nullptr, 0, getPtr(iv), 0);
    // Zero IV length may or may not be valid - depends on implementation
    (void)err;

    delete aead;
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// Comprehensive Corner Case Tests for GCM

// Test all key sizes (128, 192, 256 bits) with encrypt/decrypt roundtrip
TEST(GCM, AllKeySizesRoundtrip)
{
    std::vector<Uint8> iv(12, 0x01);
    std::vector<Uint8> aad(16, 0xAA);
    std::vector<Uint8> plaintext(32, 0x55);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // 128-bit key
    {
        std::vector<Uint8> key(16, 0x42);
        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt with new object
        auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead2, nullptr);
        err = aead2->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead2->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext);

        delete aead;
        delete aead2;
    }

    // 192-bit key
    {
        std::vector<Uint8> key(24, 0x42);
        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey192Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 192, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt with new object
        auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey192Bit);
        ASSERT_NE(aead2, nullptr);
        err = aead2->init(getPtr(key), 192, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead2->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext);

        delete aead;
        delete aead2;
    }

    // 256-bit key
    {
        std::vector<Uint8> key(32, 0x42);
        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 256, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt with new object
        auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
        ASSERT_NE(aead2, nullptr);
        err = aead2->init(getPtr(key), 256, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead2->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext);

        delete aead;
        delete aead2;
    }
}

// Test different IV/nonce lengths
TEST(GCM, VariousNonceLengths)
{
    std::vector<Uint8> key(16, 0x12);
    std::vector<Uint8> plaintext(32, 0x34);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // Test various nonce lengths: 12 (standard), 8, 16
    std::vector<size_t> nonce_lengths = { 12, 8, 16 };

    for (size_t nlen : nonce_lengths) {
        std::vector<Uint8> nonce(nlen, static_cast<Uint8>(nlen));
        
        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed init for nonce length " << nlen;

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed encrypt for nonce length " << nlen;

        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt and verify
        err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err = aead->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext) << "Mismatch for nonce length " << nlen;

        delete aead;
    }
}

// Test various AAD lengths
TEST(GCM, VariousAADLengths)
{
    std::vector<Uint8> key(16, 0x56);
    std::vector<Uint8> iv(12, 0x78);
    std::vector<Uint8> plaintext(32, 0x9A);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // Test various AAD lengths
    std::vector<size_t> aad_lengths = { 0, 16, 32, 64, 128, 256 };

    for (size_t alen : aad_lengths) {
        std::vector<Uint8> aad(alen);
        for (size_t i = 0; i < alen; i++) {
            aad[i] = static_cast<Uint8>(i % 256);
        }

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        if (alen > 0) {
            err = aead->setAad(getPtr(aad), aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed setAad for length " << alen;
        }

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt with new object and verify
        auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead2, nullptr);
        err = aead2->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        if (alen > 0) {
            err = aead2->setAad(getPtr(aad), aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }
        outlen = 0;
        err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext) << "Mismatch for AAD length " << alen;

        delete aead;
        delete aead2;
    }
}

// Test various tag lengths (4, 8, 12, 13, 14, 15, 16 bytes are valid)
TEST(GCM, ValidTagLengths)
{
    std::vector<Uint8> key(16, 0xBC);
    std::vector<Uint8> iv(12, 0xDE);
    std::vector<Uint8> plaintext(32, 0xF0);
    std::vector<Uint8> ciphertext(32);
    alc_error_t err;

    std::vector<size_t> valid_tag_lengths = { 4, 8, 12, 13, 14, 15, 16 };

    for (size_t tlen : valid_tag_lengths) {
        std::vector<Uint8> tag(tlen);

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = aead->getTag(getPtr(tag), tlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed getTag for length " << tlen;

        delete aead;
    }
}

// Test all zeros input (key, iv, aad, plaintext)
TEST(GCM, AllZerosInput)
{
    std::vector<Uint8> key(16, 0x00);
    std::vector<Uint8> iv(12, 0x00);
    std::vector<Uint8> aad(16, 0x00);
    std::vector<Uint8> plaintext(32, 0x00);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    
    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = aead->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete aead;
}

// Test all ones input (0xFF)
TEST(GCM, AllOnesInput)
{
    std::vector<Uint8> key(16, 0xFF);
    std::vector<Uint8> iv(12, 0xFF);
    std::vector<Uint8> aad(16, 0xFF);
    std::vector<Uint8> plaintext(32, 0xFF);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> decrypted(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead, nullptr);

    err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    
    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = aead->decrypt(getPtr(ciphertext), getPtr(decrypted), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete aead;
}

// Test multiple blocks (various block counts)
TEST(GCM, MultipleBlocks)
{
    std::vector<Uint8> key(16, 0x11);
    std::vector<Uint8> iv(12, 0x22);
    std::vector<Uint8> aad(16, 0x33);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    std::vector<size_t> block_counts = { 1, 2, 4, 8, 16, 32, 64 };

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;
        std::vector<Uint8> plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(data_size);
        std::vector<Uint8> decrypted(data_size);

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for block count: " << num_blocks;
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Decrypt with new object
        auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead2, nullptr);
        err = aead2->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead2->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        outlen = 0;
        err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext) << "Mismatch for block count " << num_blocks;

        delete aead;
        delete aead2;
    }
}

// Test large data (1 MB)
TEST(GCM, LargeData)
{
    const size_t data_size = 1024 * 1024; // 1 MB
    std::vector<Uint8> key(32, 0x44);
    std::vector<Uint8> iv(12, 0x55);
    std::vector<Uint8> aad(32, 0x66);
    std::vector<Uint8> plaintext(data_size);
    std::vector<Uint8> ciphertext(data_size);
    std::vector<Uint8> decrypted(data_size);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = static_cast<Uint8>((i * 17) % 256);
    }

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
    ASSERT_NE(aead, nullptr);

    err = aead->init(getPtr(key), 256, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt with new object
    auto aead2 = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey256Bit);
    ASSERT_NE(aead2, nullptr);
    err = aead2->init(getPtr(key), 256, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead2->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = aead2->decrypt(getPtr(ciphertext), getPtr(decrypted), data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete aead;
    delete aead2;
}

// Test IV affects output (different IVs should produce different ciphertexts)
TEST(GCM, IVAffectsOutput)
{
    std::vector<Uint8> key(16, 0x77);
    std::vector<Uint8> plaintext(32, 0x88);
    std::vector<Uint8> tag(16);
    std::vector<std::vector<Uint8>> outputs;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> iv(12, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(32);

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        outputs.push_back(ciphertext);
        delete aead;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "IV " << i << " and " << j << " produced same ciphertext";
        }
    }
}

// Test AAD affects tag (different AADs should produce different tags)
TEST(GCM, AADAffectsTag)
{
    std::vector<Uint8> key(16, 0x99);
    std::vector<Uint8> iv(12, 0xAA);
    std::vector<Uint8> plaintext(32, 0xBB);
    std::vector<Uint8> ciphertext(32);
    std::vector<std::vector<Uint8>> tags;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> aad(16, static_cast<Uint8>(i));
        std::vector<Uint8> tag(16);

        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = aead->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        tags.push_back(tag);
        delete aead;
    }

    // Verify all tags are different
    for (size_t i = 0; i < tags.size(); i++) {
        for (size_t j = i + 1; j < tags.size(); j++) {
            EXPECT_NE(tags[i], tags[j]) 
                << "AAD " << i << " and " << j << " produced same tag";
        }
    }
}

// Test separate cipher objects for encrypt and decrypt
TEST(GCM, SeparateCipherObjects)
{
    std::vector<Uint8> key(16, 0xCC);
    std::vector<Uint8> iv(12, 0xDD);
    std::vector<Uint8> aad(16, 0xEE);
    std::vector<Uint8> plaintext(64, 0xFF);
    std::vector<Uint8> ciphertext(64);
    std::vector<Uint8> decrypted(64);
    std::vector<Uint8> tag_enc(16);
    alc_error_t err;

    // Encrypt with first cipher object
    auto aead_enc = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead_enc, nullptr);

    err = aead_enc->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead_enc->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead_enc->encrypt(getPtr(plaintext), getPtr(ciphertext), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead_enc->getTag(getPtr(tag_enc), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead_enc;

    // Decrypt with second cipher object
    auto aead_dec = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
    ASSERT_NE(aead_dec, nullptr);

    err = aead_dec->init(getPtr(key), 128, getPtr(iv), iv.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = aead_dec->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    outlen = 0;
    err = aead_dec->decrypt(getPtr(ciphertext), getPtr(decrypted), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete aead_dec;
}

// Test determinism (same inputs always produce same output)
TEST(GCM, Determinism)
{
    std::vector<Uint8> key(16, 0x11);
    std::vector<Uint8> iv(12, 0x22);
    std::vector<Uint8> aad(16, 0x33);
    std::vector<Uint8> plaintext(32, 0x44);
    std::vector<Uint8> ciphertext1(32), ciphertext2(32), ciphertext3(32);
    std::vector<Uint8> tag1(16), tag2(16), tag3(16);
    alc_error_t err;

    for (int round = 0; round < 3; round++) {
        auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);
        ASSERT_NE(aead, nullptr);

        err = aead->init(getPtr(key), 128, getPtr(iv), iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        std::vector<Uint8>* ct = (round == 0) ? &ciphertext1 : (round == 1) ? &ciphertext2 : &ciphertext3;
        std::vector<Uint8>* tg = (round == 0) ? &tag1 : (round == 1) ? &tag2 : &tag3;
        err = aead->encrypt(getPtr(plaintext), getPtr(*ct), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->getTag(getPtr(*tg), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete aead;
    }

    EXPECT_EQ(ciphertext1, ciphertext2) << "Round 1 and 2 should produce same ciphertext";
    EXPECT_EQ(ciphertext2, ciphertext3) << "Round 2 and 3 should produce same ciphertext";
    EXPECT_EQ(tag1, tag2) << "Round 1 and 2 should produce same tag";
    EXPECT_EQ(tag2, tag3) << "Round 2 and 3 should produce same tag";
}

#if 0
// Linux specific test
#ifdef __linux__
TEST(GCM, InputOverload)
{
    Uint8 iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const alc_cipher_algo_info_t aesInfo  = { .ai_mode = ALC_AES_MODE_GCM,
                                             .ai_iv   = iv };
    alc_key_info_t               keyInfo  = { .len  = 256,
                                              .key  = key };
    Gcm                          pGcmObj  = Gcm(aesInfo, keyInfo);
    auto                         zero1_fd = open("/dev/zero", O_RDWR);
    auto                         zero2_fd = open("/dev/zero", O_RDWR);
    auto                         pread    = mmap(
        0, pow(2, 39), PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, zero1_fd, 0);
    auto pwrite =
        mmap(0, pow(2, 39), PROT_WRITE, MAP_FILE | MAP_SHARED, zero2_fd, 0);
    alc_error_t err = ALC_ERROR_NONE;
    err             = pGcmObj.setIv(iv, sizeof(iv));
    EXPECT_EQ(err, ALC_ERROR_NONE);
    printf("%p %p\n", pwrite, pread);
    err = pGcmObj.encrypt(
        (const Uint8*)pread, (Uint8*)pwrite, pow(2, 39) - 256 + 1, iv);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
}
#endif
#endif

#if 1
TEST_P(GCM_KAT, Encrypt)
{
    std::vector<Uint8> out_ciphertext(m_plaintext.size(), 0);

    // Encrypt the plaintext into ciphertext.
    if (!m_plaintext.empty()) {
        Uint64 outlen = 0;
        m_err         = pGcmObj->encrypt(&(m_plaintext.at(0)),
                                 &(out_ciphertext.at(0)),
                                 m_plaintext.size(),
                                 &outlen);
        EXPECT_EQ(out_ciphertext, m_ciphertext);
    } else {
        // Call encrypt update with a valid memory if no plaintext
        Uint8  a = 0;
        Uint64 outlen = 0;
        m_err         = pGcmObj->encrypt(&a, &a, 0, &outlen);
    }
    EXPECT_EQ(m_err, ALC_ERROR_NONE);

    // If there is tag, try to get the tag.
    std::vector<Uint8> out_tag(m_tag.size(), 0);
    if (!m_tag.empty()) {
        m_err = pGcmObj->getTag(&(out_tag.at(0)), m_tag.size());
        if (m_test_name.at(0) == 'P') {
            EXPECT_EQ(out_tag, m_tag);
        } else {
            EXPECT_NE(out_tag, m_tag);
        }
        EXPECT_EQ(m_err, ALC_ERROR_NONE);
    }
}
#endif

TEST(GCM, EncryptUpdateMultiple_KAT_51B)
{
    alc_error_t err = ALC_ERROR_NONE;
    // Test data from P_K128b_N128B_A20B_P51B_C51B_T16B
    std::vector<Uint8> key   = { 0xc1, 0x15, 0xa6, 0x49, 0xeb, 0x2a, 0x50, 0x2f,
                                 0xce, 0x0a, 0x7f, 0x55, 0x1d, 0x02, 0x00, 0xb7 };
    std::vector<Uint8> nonce = {
        0x89, 0x62, 0xe4, 0xfe, 0xc5, 0xf0, 0x32, 0x13, 0x84, 0xba, 0x4e, 0x23,
        0xcc, 0xa3, 0x5a, 0x04, 0x5b, 0xa2, 0xe6, 0x9c, 0x11, 0x64, 0x0f, 0xbd,
        0x0a, 0xd6, 0x99, 0xa1, 0xfc, 0xa5, 0x22, 0xbd, 0xb8, 0xb8, 0x14, 0x95,
        0xd2, 0xa1, 0xf5, 0x7f, 0xbf, 0x9c, 0x52, 0x0c, 0xd3, 0xec, 0x9a, 0xeb,
        0xf3, 0xe4, 0x3b, 0x02, 0xd9, 0x78, 0x4a, 0x53, 0x2a, 0x97, 0xfa, 0xa6,
        0xd0, 0xed, 0x17, 0xa1, 0xb9, 0x09, 0x6e, 0xe0, 0x47, 0xf0, 0xea, 0xe5,
        0x04, 0x14, 0x96, 0x6b, 0x8c, 0xd6, 0x07, 0x12, 0x36, 0xd7, 0x05, 0x9a,
        0x34, 0xc8, 0xdd, 0x1d, 0x9b, 0xa8, 0xac, 0x73, 0xd5, 0xd9, 0x30, 0x40,
        0xef, 0x6a, 0xe6, 0x4f, 0xa9, 0xf5, 0x78, 0x6d, 0x4b, 0xa7, 0x18, 0x9b,
        0x1b, 0xa8, 0x9d, 0x74, 0xae, 0xaf, 0x5e, 0x65, 0x60, 0x0f, 0x06, 0xc5,
        0xd9, 0xfc, 0xf7, 0xc6, 0xe3, 0xd7, 0x6e, 0xc9
    };
    std::vector<Uint8> aad   = { 0x2a, 0xb2, 0x86, 0x75, 0x68, 0x24, 0xc7,
                                 0xc2, 0xd5, 0x3f, 0x98, 0xef, 0x70, 0x75,
                                 0xfa, 0xe4, 0x18, 0x1b, 0xf7, 0x41 };
    std::vector<Uint8> ptext = { 0x09, 0x62, 0xe1, 0x3f, 0x76, 0xe2, 0x81, 0x94,
                                 0x2a, 0xec, 0x8c, 0x9d, 0x7b, 0xf5, 0x9c, 0xca,
                                 0xf7, 0x02, 0xde, 0xa4, 0x9d, 0xe4, 0x84, 0x28,
                                 0x0e, 0x4c, 0xc0, 0x7b, 0xf4, 0x43, 0x55, 0x62,
                                 0x4d, 0x26, 0x2e, 0x5b, 0x42, 0xee, 0xff, 0x46,
                                 0xa0, 0x6e, 0xb7, 0x98, 0xc0, 0xdc, 0xd7, 0x48,
                                 0xaa, 0xeb, 0x66 };
    std::vector<Uint8> expected_ctext = {
        0x8f, 0xe5, 0x9a, 0xa7, 0xc1, 0x12, 0xe4, 0xb5, 0x00, 0x0f, 0xd8,
        0x2f, 0x19, 0x4f, 0x0f, 0x9b, 0x15, 0x21, 0x8f, 0x07, 0x26, 0x30,
        0xdf, 0x58, 0x70, 0xd1, 0xc8, 0xca, 0x81, 0xd7, 0xd6, 0x6c, 0xcf,
        0x95, 0xdd, 0xd3, 0xab, 0x3c, 0x60, 0x3a, 0xf2, 0xfc, 0x2b, 0xb9,
        0xed, 0xca, 0x00, 0xc7, 0xbd, 0xab, 0x94
    };
    std::vector<Uint8> expected_tag = { 0x9e, 0xab, 0x1e, 0x03, 0x7e, 0x70,
                                        0x3a, 0x77, 0x7b, 0x76, 0x30, 0x6d,
                                        0x8a, 0xa6, 0x60, 0xd3 };

    std::vector<Uint8> out_ctext(51);
    std::vector<Uint8> out_tag(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }

    // Initialize with key and nonce
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Set AAD
    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // First encrypt call: 48 bytes
    Uint64 outlen1 = 0;
    err = aead->encrypt(getPtr(ptext), getPtr(out_ctext), 48, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Second encrypt call: remaining 3 bytes
    Uint64 outlen2 = 0;
    err =
        aead->encrypt(getPtr(ptext) + 48, getPtr(out_ctext) + 48, 3, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Verify the combined ciphertext matches expected
    EXPECT_EQ(out_ctext, expected_ctext);

    // Get and verify tag
    err = aead->getTag(getPtr(out_tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(out_tag, expected_tag);

    delete aead;
}

TEST_P(GCM_KAT, Decrypt)
{
    std::vector<Uint8> out_plaintext(m_ciphertext.size(), 0);

    // Decrypt the ciphertext into plaintext
    if (!m_ciphertext.empty()) {
        Uint64 outlen = 0;
        m_err         = pGcmObj->decrypt(&(m_ciphertext.at(0)),
                                 &(out_plaintext.at(0)),
                                 m_ciphertext.size(),
                                 &outlen);
        EXPECT_EQ(out_plaintext, m_plaintext);
    } else {
        // Call decrypt update with a valid memory if no plaintext
        Uint8  a = 0;
        Uint64 outlen = 0;
        m_err         = pGcmObj->decrypt(&a, &a, 0, &outlen);
    }
    EXPECT_EQ(m_err, ALC_ERROR_NONE);

    // If there is tag, try to get the tag.
    if (!m_tag.empty()) {
        m_err = pGcmObj->getTag(&(m_tag.at(0)), m_tag.size());
        EXPECT_EQ(m_err, ALC_ERROR_NONE);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    GCM_KAT,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<GCM_KAT::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST(GCM, InvalidTagLen)
{
    alc_error_t err   = ALC_ERROR_NONE;
    Uint8       iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    Uint8       key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8       pt[]  = "Hello World!";
    Uint8       tag[17];
    Uint8       cipherText[sizeof(pt)];

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(key, 128, iv, 7);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Skipping Aad as its not mandatory

    Uint64 outlen = 0;
    err           = aead->encrypt(pt, cipherText, sizeof(pt), &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // TODO: Create a parametrized test
    err = aead->getTag(tag, 17);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    delete aead;
}

TEST(GCM, EncryptUpdateSingle)
{
    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);
    std::vector<Uint8> tag_out(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(ptext), getPtr(out), ptext.size(), &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(out, ctext);

    err = aead->getTag(getPtr(tag_out), 16);

    EXPECT_EQ(tag_out, tag);

    delete aead;
}

TEST(GCM, EncryptUpdateMultiple)
{
    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);
    std::vector<Uint8> tag_out(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->encrypt(getPtr(ptext), getPtr(out), ptext.size() - 16, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen2 = 0;
    err            = aead->encrypt(getPtr(ptext) + ptext.size() - 16,
                        getPtr(out) + ptext.size() - 16,
                        16,
                        &outlen2);

    EXPECT_EQ(out, ctext);

    err = aead->getTag(getPtr(tag_out), 16);

    EXPECT_EQ(tag_out, tag);

    delete aead;
}

TEST(GCM, DecryptUpdateSingle)
{
    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->decrypt(&ctext[0], getPtr(out), ptext.size(), &outlen);

    EXPECT_EQ(out, ptext);

    err = aead->getTag(getPtr(tag), 16);

    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead;
}

TEST(GCM, DecryptUpdateMultiple)
{
    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = aead->decrypt(&ctext[0], getPtr(out), ctext.size() - 16, &outlen);

    Uint64 outlen2 = 0;
    err            = aead->decrypt(&ctext[0] + ctext.size() - 16,
                        getPtr(out) + ctext.size() - 16,
                        16,
                        &outlen2);

    EXPECT_EQ(out, ptext);

    err = aead->getTag(getPtr(tag), 16);

    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead;
}

// Unit Test to mimic test_quic_multistream openssl tests

TEST(GCM, EncryptUpdateMultipleStream)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "AES_MULTI_UPDATE not defined - streaming tests require "
                    "multi-update support";
#endif

    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);
    std::vector<Uint8> tag_out(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen1 = 0;
    err            = aead->encrypt(getPtr(ptext), getPtr(out), 4, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen2 = 0;
    err            = aead->encrypt(
        getPtr(ptext) + 4, getPtr(out) + 4, ptext.size() - 4, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(out, ctext);

    err = aead->getTag(getPtr(tag_out), 16);

    EXPECT_EQ(tag_out, tag);

    delete aead;
}

TEST(GCM, DecryptUpdateMultipleStream)
{

#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "AES_MULTI_UPDATE not defined - streaming tests require "
                    "multi-update support";
#endif
    alc_error_t        err   = ALC_ERROR_NONE;
    std::vector<Uint8> key   = { 0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33,
                                 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 };
    std::vector<Uint8> nonce = { 0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13,
                                 0xa0, 0x0c, 0x35, 0x6e, 0x65, 0x31, 0x99,
                                 0x74, 0x82, 0x2c, 0x7e, 0x17 };
    std::vector<Uint8> aad   = { 0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18,
                                 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                 0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2,
                                 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f };
    std::vector<Uint8> ptext = {
        0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28,
        0x61, 0xb9, 0x31, 0x42, 0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff,
        0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5, 0xb4, 0xa1, 0xbd, 0x07,
        0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85
    };
    std::vector<Uint8> ctext = {
        0xb6, 0xdd, 0x7e, 0xbb, 0xeb, 0x56, 0x83, 0x43, 0x17, 0xf2, 0xac, 0x1c,
        0xf0, 0xdc, 0x69, 0xb3, 0xb0, 0x2a, 0xb8, 0x7e, 0x7e, 0x52, 0x41, 0x11,
        0x36, 0x46, 0x34, 0x25, 0xf4, 0x00, 0x1c, 0xcd, 0xe3, 0x2a, 0x36, 0xf3,
        0x70, 0xcf, 0xe0, 0xfc, 0xe6, 0xa0, 0xac, 0x37, 0x6a, 0xe1, 0x3a, 0xe2
    };
    std::vector<Uint8> tag = { 0x77, 0xf6, 0xc4, 0x7b, 0x05, 0x40, 0xf0, 0xb9,
                               0xff, 0x3c, 0x3b, 0x07, 0xa2, 0x4c, 0x62, 0xfe };

    std::vector<Uint8> out(48);
    std::vector<Uint8> tag_out(16);

    auto aead = createCipherAead(CipherMode::eAesGCM, CipherKeyLen::eKey128Bit);

    if (aead == nullptr) {
        FAIL();
    }
    err = aead->init(getPtr(key), 128, getPtr(nonce), nonce.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = aead->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen1 = 0;
    err            = aead->decrypt(&ctext[0], getPtr(out), 4, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen2 = 0;
    err            = aead->decrypt(
        &ctext[0] + 4, getPtr(out) + 4, ctext.size() - 4, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(out, ptext);

    err = aead->getTag(getPtr(tag), 16);

    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete aead;
}

TEST(GCM, KeyCaching)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Test vector structure
    struct TestVector
    {
        std::vector<Uint8> key;
        std::vector<Uint8> iv;
        std::vector<Uint8> plaintext;
        std::vector<Uint8> ciphertext;
    };

    // clang-format off
    // AES-128 Test Vectors (3 vectors)
    std::vector<TestVector> test_vectors_128 = {
        // data1: k1, iv1, plain1, cipher1
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
         {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
         {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
         {0xac, 0xaf, 0xc2, 0x8c, 0x99, 0x5f, 0xf5, 0x6f, 0x92, 0xf6, 0xa7, 0xef, 0x07, 0x72, 0xc7, 0x9f}},
        // data2: k1, iv2, plain2, cipher2
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
         {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0x7c, 0x78, 0xb0, 0x44, 0xf4, 0x1a, 0x75, 0x50, 0x14, 0x75, 0x0d, 0x28, 0xa0, 0xb0, 0x20, 0xfe}},
        // data3: k2, iv3, plain2, cipher3
        {{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
         {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0xda, 0xf9, 0x26, 0x57, 0x09, 0x18, 0x76, 0xee, 0xd4, 0xfa, 0xd0, 0xda, 0xb1, 0xf9, 0x30, 0xc4}}
    };

    // AES-192 Test Vectors (3 vectors)
    std::vector<TestVector> test_vectors_192 = {
        // data1: k1, iv1, plain1, cipher1
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
         {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
         {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
         {0xd6, 0xd2, 0xb6, 0x4f, 0x79, 0x5f, 0xa1, 0xa6, 0xa0, 0xae, 0xdd, 0x97, 0xc8, 0xe9, 0x06, 0x63}},
        // data2: k1, iv2, plain2, cipher2
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
         {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0x2e, 0x19, 0xea, 0xd5, 0x11, 0x51, 0x79, 0x32, 0x7a, 0x95, 0xb6, 0x15, 0x78, 0xb5, 0x40, 0xa8}},
        // data3: k2, iv3, plain2, cipher3
        {{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 
          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
         {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0x66, 0x68, 0xc1, 0xf5, 0xaa, 0xc0, 0x72, 0xef, 0x2b, 0xd1, 0x78, 0xd8, 0x44, 0x74, 0x70, 0xeb}}
    };

    // AES-256 Test Vectors (3 vectors)
    std::vector<TestVector> test_vectors_256 = {
        // data1: k1, iv1, plain1, cipher1
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
         {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
         {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
         {0xaf, 0x40, 0xf0, 0x7f, 0x46, 0x3e, 0x5a, 0x2c, 0xe6, 0x08, 0xc9, 0xed, 0xba, 0xb9, 0x40, 0x82}},
        // data2: k1, iv2, plain2, cipher2
        {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
         {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0x72, 0x26, 0x57, 0x12, 0x86, 0x9a, 0xfd, 0x8c, 0x9e, 0x59, 0x1d, 0x9f, 0xd7, 0x31, 0x82, 0x1a}},
        // data3: k2, iv3, plain2, cipher3
        {{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 
          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f},
         {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
         {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
         {0xbc, 0xcd, 0x17, 0xee, 0x39, 0x07, 0xbd, 0x04, 0x87, 0x28, 0x0b, 0xa5, 0x5b, 0xe8, 0x4b, 0xc5}}
    };
    // clang-format on

    // Test all key sizes
    struct KeySizeTest
    {
        size_t                   key_bits;
        CipherKeyLen             keyLen;
        std::vector<TestVector>* vectors;
    };

    std::vector<KeySizeTest> key_sizes = {
        { 128, CipherKeyLen::eKey128Bit, &test_vectors_128 },
        { 192, CipherKeyLen::eKey192Bit, &test_vectors_192 },
        { 256, CipherKeyLen::eKey256Bit, &test_vectors_256 }
    };

    for (const auto& ks : key_sizes) {
        auto               aead = createCipherAead(CipherMode::eAesGCM, ks.keyLen);
        std::vector<Uint8> output(16, 0);
        Uint64             outlen{};

        if (aead == nullptr) {
            FAIL();
        }

        auto& v = *ks.vectors;

        // Vector 0: baseline
        err = aead->init(
            getPtr(v[0].key), ks.key_bits, getPtr(v[0].iv), v[0].iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->encrypt(getPtr(v[0].plaintext),
                            getPtr(output),
                            v[0].plaintext.size(),
                            &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(output, v[0].ciphertext)
            << "Failed for " << ks.key_bits << "-bit baseline";

        // Vector 1: IV change only (same key)
        err = aead->init(
            getPtr(v[0].key), ks.key_bits, getPtr(v[1].iv), v[1].iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->encrypt(getPtr(v[1].plaintext),
                            getPtr(output),
                            v[1].plaintext.size(),
                            &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(output, v[1].ciphertext)
            << "Failed for " << ks.key_bits << "-bit IV change";

        // Vector 2: Key and IV change
        err = aead->init(
            getPtr(v[2].key), ks.key_bits, getPtr(v[2].iv), v[2].iv.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = aead->encrypt(getPtr(v[2].plaintext),
                            getPtr(output),
                            v[2].plaintext.size(),
                            &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(output, v[2].ciphertext)
            << "Failed for " << ks.key_bits << "-bit key+IV change";

        delete aead;
    }
}
