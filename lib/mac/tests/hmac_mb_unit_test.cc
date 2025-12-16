/*
 * Copyright (C) 2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/mac/hmac.hh"
#include "alcp/mac/hmac_mb.hh"
#include "alcp/types.h"
#include "gtest/gtest.h"
#include <iomanip>
#include <sstream>

using alcp::mac::Hmac;
using alcp::mac::HmacMB;
using namespace alcp::digest;
using namespace alcp::base;

// Helper function to convert bytes to hex string
std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        il << std::hex << charRep;
        std::string ilStr = il.str();
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    return ss.str();
}

inline std::string
parseBytesToHexStr(std::vector<Uint8> bytes)
{
    return parseBytesToHexStr(&(bytes.at(0)), bytes.size());
}

Uint8
parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';
    return 0;
}

std::vector<Uint8>
parseHexStrToBin(const std::string in)
{
    std::vector<Uint8> vector;
    int                len = in.size();
    int                ind = 0;

    for (int i = 0; i < len; i += 2) {
        Uint8 val =
            parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
        vector.push_back(val);
        ind += 2;
    }
    return vector;
}

typedef std::tuple<std::string, // key
                   std::string, // message
                   std::string  // mac
                   >
                                                 param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

// clang-format off
// Known Answer Test data for HMAC-SHA2-256 and HMAC-SHA2-224
known_answer_map_t KAT_HmacMBDataset {
    {
        "SHA2_256_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"
        }
    },
    {
        "SHA2_256_KEYLEN_LT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E",
            "A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790"
        }
    },
    {
        "SHA2_256_KEYLEN_GT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
            "3132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D"
        }
    },
    {
        "SHA2_224_KEYLEN_LT_B",
        {
            "cf127579d6b2b0b3a607a6314bf8733061c32a043593195527544f8753c65c7a70d05874f718275b88d0fa288bd3199813f0",
            "fa7e18cc5443981f22c0a5aba2117915f89c7781c34f61f9f429cb13e0fcd0ce947103be684ca869d7f125f08d27b3f2c21d59adc7ab1b66ded96f0b4fa5f018b80156b7a51ca62b60e2a66e0bc69419ebbf178507907630f24d0862e51bec101037f900323af82e689b116f427584541c8a9a51ac89da1ed78c7f5ec9e52a7f",
            "354f87e98d276446836ea0430ce4529272a017c290039a9dfea4349b"
        }
    },
    {
        "SHA2_224_KEYLEN_EQ_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "C7405E3AE058E8CD30B08B4140248581ED174CB34E1224BCC1EFC81B"
        }
    },
    {
        "SHA2_224_KEYLEN_GT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "91C52509E5AF8531601AE6230099D90BEF88AAEFB961F4080ABC014D"
        }
    }
};
// clang-format on

class HmacMBTestFixture
    : public ::testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8>      m_message;
    std::vector<Uint8>      m_expected_mac;
    std::vector<Uint8>      m_key;
    std::unique_ptr<HmacMB> m_hmac_mb = std::make_unique<HmacMB>();
    alc_digest_mode_t       m_digest_mode;

  public:
    void setUp(const ParamType& params)
    {
        auto tuple_values = params.second;
        m_key             = parseHexStrToBin(std::get<0>(tuple_values));
        m_message         = parseHexStrToBin(std::get<1>(tuple_values));
        m_expected_mac    = parseHexStrToBin(std::get<2>(tuple_values));
    }

    void setUpDigestMode(std::string test_name)
    {
        size_t      type_index = test_name.find("_");
        std::string sha_type   = test_name.substr(0, type_index);
        size_t      algo_index = test_name.find("_", type_index + 1);
        std::string hash_name =
            test_name.substr(type_index + 1, algo_index - type_index - 1);

        if (sha_type == "SHA2") {
            if (hash_name == "256") {
                m_digest_mode = ALC_MB_SHA2_256;
            } else if (hash_name == "224") {
                m_digest_mode = ALC_MB_SHA2_224;
            }
        }
    }
};

// Test: Basic multibuffer functionality with multiple buffers
TEST_P(HmacMBTestFixture, MultibufferBasicFunctionality)
{
    const auto& cParams = GetParam();
    setUp(cParams);
    setUpDigestMode(cParams.first);

    const Uint64 numBuffers = 8;

    // Prepare input buffers - all with same message
    std::vector<const Uint8*>       pp_msg_buf(numBuffers);
    std::vector<std::vector<Uint8>> output_macs(numBuffers);
    std::vector<Uint8*>             pp_dst_buf(numBuffers);

    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_msg_buf[i] = &m_message[0];
        output_macs[i].resize(m_expected_mac.size());
        pp_dst_buf[i] = &output_macs[i][0];
    }

    // Initialize HMAC-MB
    m_hmac_mb->init(&m_key[0], m_key.size(), m_digest_mode);

    // Flush and dequeue
    ASSERT_EQ(m_hmac_mb->flush(&pp_msg_buf[0], numBuffers, m_message.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(m_hmac_mb->dequeue(&pp_dst_buf[0], numBuffers), ALC_ERROR_NONE);

    // Verify all outputs match expected MAC
    for (Uint64 i = 0; i < numBuffers; i++) {
        EXPECT_EQ(output_macs[i], m_expected_mac)
            << "Buffer " << i << " MAC mismatch";
    }
}

// Test: Multibuffer vs Single buffer - verify outputs are identical
TEST_P(HmacMBTestFixture, MultibufferVsSingleBuffer)
{
    const auto& cParams = GetParam();
    setUp(cParams);
    setUpDigestMode(cParams.first);

    const Uint64 numBuffers = 6;

    // Single buffer HMAC
    std::unique_ptr<Hmac>    hmac_sb = std::make_unique<Hmac>();
    std::unique_ptr<IDigest> digest;

    if (m_digest_mode == ALC_MB_SHA2_256) {
        digest = std::make_unique<Sha256>();
    } else if (m_digest_mode == ALC_MB_SHA2_224) {
        digest = std::make_unique<Sha224>();
    }

    std::vector<Uint8> sb_mac(m_expected_mac.size());
    hmac_sb->init(&m_key[0], m_key.size(), digest.get());
    hmac_sb->update(&m_message[0], m_message.size());
    hmac_sb->finalize(&sb_mac[0], sb_mac.size());

    // Multibuffer HMAC
    std::vector<const Uint8*>       pp_msg_buf(numBuffers);
    std::vector<std::vector<Uint8>> output_macs(numBuffers);
    std::vector<Uint8*>             pp_dst_buf(numBuffers);

    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_msg_buf[i] = &m_message[0];
        output_macs[i].resize(m_expected_mac.size());
        pp_dst_buf[i] = &output_macs[i][0];
    }

    m_hmac_mb->init(&m_key[0], m_key.size(), m_digest_mode);
    ASSERT_EQ(m_hmac_mb->flush(&pp_msg_buf[0], numBuffers, m_message.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(m_hmac_mb->dequeue(&pp_dst_buf[0], numBuffers), ALC_ERROR_NONE);

    // Verify multibuffer outputs match single buffer output
    for (Uint64 i = 0; i < numBuffers; i++) {
        EXPECT_EQ(output_macs[i], sb_mac)
            << "Buffer " << i << " does not match single buffer HMAC";
    }
}

TEST_P(HmacMBTestFixture, VariousBufferCounts)
{
    const auto& cParams = GetParam();
    setUp(cParams);
    setUpDigestMode(cParams.first);

    std::vector<Uint64> buffer_counts = { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
                                          11, 12, 13, 14, 15, 16, 32, 48, 64 };

    for (auto numBuffers : buffer_counts) {
        std::vector<const Uint8*>       pp_msg_buf(numBuffers);
        std::vector<std::vector<Uint8>> output_macs(numBuffers);
        std::vector<Uint8*>             pp_dst_buf(numBuffers);

        for (Uint64 i = 0; i < numBuffers; i++) {
            pp_msg_buf[i] = &m_message[0];
            output_macs[i].resize(m_expected_mac.size());
            pp_dst_buf[i] = &output_macs[i][0];
        }

        m_hmac_mb->init(&m_key[0], m_key.size(), m_digest_mode);
        ASSERT_EQ(
            m_hmac_mb->flush(&pp_msg_buf[0], numBuffers, m_message.size()),
            ALC_ERROR_NONE)
            << "Failed for buffer count: " << numBuffers;
        ASSERT_EQ(m_hmac_mb->dequeue(&pp_dst_buf[0], numBuffers),
                  ALC_ERROR_NONE)
            << "Failed for buffer count: " << numBuffers;

        for (Uint64 i = 0; i < numBuffers; i++) {
            EXPECT_EQ(output_macs[i], m_expected_mac)
                << "Buffer count: " << numBuffers << ", Buffer " << i
                << " MAC mismatch";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    HmacMBTest,
    HmacMBTestFixture,
    testing::ValuesIn(KAT_HmacMBDataset),
    [](const testing::TestParamInfo<HmacMBTestFixture::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

// Error handling tests

TEST(HmacMBRobustnessTest, FlushWithZeroBuffers)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    const Uint64              numBuffers = 0;
    std::vector<const Uint8*> pp_msg_buf(1, &message[0]);

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    EXPECT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, message.size()),
              ALC_ERROR_INVALID_ARG);
}

TEST(HmacMBRobustnessTest, FlushWithNullMessageBuffer)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    EXPECT_EQ(hmac_mb.flush(nullptr, 8, message.size()),
              ALC_ERROR_INVALID_DATA);
}

TEST(HmacMBRobustnessTest, FlushWithNullIndividualBuffer)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    const Uint64              numBuffers = 8;
    std::vector<const Uint8*> pp_msg_buf(numBuffers);

    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_msg_buf[i] = nullptr; // All null
    }

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    EXPECT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, message.size()),
              ALC_ERROR_INVALID_DATA);
}

TEST(HmacMBRobustnessTest, DequeueWithNullOutputBuffer)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    const Uint64              numBuffers = 8;
    std::vector<const Uint8*> pp_msg_buf(numBuffers, &message[0]);

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    ASSERT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, message.size()),
              ALC_ERROR_NONE);

    EXPECT_EQ(hmac_mb.dequeue(nullptr, numBuffers), ALC_ERROR_INVALID_DATA);
}

TEST(HmacMBRobustnessTest, DequeueWithNullIndividualOutputBuffer)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    const Uint64              numBuffers = 8;
    std::vector<const Uint8*> pp_msg_buf(numBuffers, &message[0]);
    std::vector<Uint8*>       pp_dst_buf(numBuffers, nullptr);

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    ASSERT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, message.size()),
              ALC_ERROR_NONE);

    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], numBuffers),
              ALC_ERROR_INVALID_DATA);
}

TEST(HmacMBRobustnessTest, DequeueWithoutFlush)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data         = pos->second;
    auto        key          = parseHexStrToBin(std::get<0>(data));
    auto        expected_mac = parseHexStrToBin(std::get<2>(data));

    const Uint64                    numBuffers = 8;
    std::vector<std::vector<Uint8>> output_macs(
        numBuffers, std::vector<Uint8>(expected_mac.size()));
    std::vector<Uint8*> pp_dst_buf(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_dst_buf[i] = &output_macs[i][0];
    }

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], numBuffers),
              ALC_ERROR_INVALID_ARG);
}

TEST(HmacMBRobustnessTest, DequeueBufferCountMismatch)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data         = pos->second;
    auto        key          = parseHexStrToBin(std::get<0>(data));
    auto        message      = parseHexStrToBin(std::get<1>(data));
    auto        expected_mac = parseHexStrToBin(std::get<2>(data));

    const Uint64              flushBuffers = 8;
    std::vector<const Uint8*> pp_msg_buf(flushBuffers, &message[0]);

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    ASSERT_EQ(hmac_mb.flush(&pp_msg_buf[0], flushBuffers, message.size()),
              ALC_ERROR_NONE);

    std::vector<std::vector<Uint8>> output_macs(
        16, std::vector<Uint8>(expected_mac.size()));
    std::vector<Uint8*> pp_dst_buf(16);
    for (Uint64 i = 0; i < 16; i++) {
        pp_dst_buf[i] = &output_macs[i][0];
    }

    // Try to dequeue 0 buffers - should fail
    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], 0), ALC_ERROR_INVALID_ARG);

    // Try to dequeue more buffers than flushed
    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], 16), ALC_ERROR_INVALID_ARG);

    // Dequeue correct amount should work
    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], flushBuffers), ALC_ERROR_NONE);
}

TEST(HmacMBRobustnessTest, MaxInputSize)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data    = pos->second;
    auto        key     = parseHexStrToBin(std::get<0>(data));
    auto        message = parseHexStrToBin(std::get<1>(data));

    const Uint64              numBuffers = 8;
    std::vector<const Uint8*> pp_msg_buf(numBuffers, &message[0]);

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    // Message length >= UINT64_MAX/8 should fail
    EXPECT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, UINT64_MAX / 8),
              ALC_ERROR_INVALID_ARG);

    EXPECT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, UINT64_MAX / 8 + 64),
              ALC_ERROR_INVALID_ARG);
}

TEST(HmacMBRobustnessTest, EmptyMessage)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data = pos->second;
    auto        key  = parseHexStrToBin(std::get<0>(data));

    const Uint64                    numBuffers  = 8;
    const Uint8                     empty_msg[] = "";
    std::vector<const Uint8*>       pp_msg_buf(numBuffers, empty_msg);
    std::vector<std::vector<Uint8>> output_macs(numBuffers,
                                                std::vector<Uint8>(32));
    std::vector<Uint8*>             pp_dst_buf(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_dst_buf[i] = &output_macs[i][0];
    }

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    EXPECT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, 0), ALC_ERROR_NONE);
    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], numBuffers), ALC_ERROR_NONE);
}

TEST(HmacMBRobustnessTest, PartialDequeue)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_256_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data         = pos->second;
    auto        key          = parseHexStrToBin(std::get<0>(data));
    auto        message      = parseHexStrToBin(std::get<1>(data));
    auto        expected_mac = parseHexStrToBin(std::get<2>(data));

    const Uint64                    flushBuffers = 16;
    std::vector<const Uint8*>       pp_msg_buf(flushBuffers, &message[0]);
    std::vector<std::vector<Uint8>> output_macs(
        flushBuffers, std::vector<Uint8>(expected_mac.size()));
    std::vector<Uint8*> pp_dst_buf(flushBuffers);
    for (Uint64 i = 0; i < flushBuffers; i++) {
        pp_dst_buf[i] = &output_macs[i][0];
    }

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_256);

    ASSERT_EQ(hmac_mb.flush(&pp_msg_buf[0], flushBuffers, message.size()),
              ALC_ERROR_NONE);

    // Dequeue only 8 out of 16 buffers
    EXPECT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], 8), ALC_ERROR_NONE);

    // Verify the 8 dequeued MACs
    for (Uint64 i = 0; i < 8; i++) {
        EXPECT_EQ(output_macs[i], expected_mac)
            << "Partial dequeue buffer " << i << " MAC mismatch";
    }
}

// NOTE: Test for different messages per buffer is not included because
// the current HMAC multibuffer implementation requires all buffers to have
// the same message content and length. This is a known limitation of the
// current implementation that processes all buffers with a single message
// length.

// Test SHA2-224 support
TEST(HmacMBFunctionalTest, SHA224Support)
{
    auto pos = KAT_HmacMBDataset.find("SHA2_224_KEYLEN_EQ_B");
    ASSERT_NE(pos, KAT_HmacMBDataset.end());

    param_tuple data         = pos->second;
    auto        key          = parseHexStrToBin(std::get<0>(data));
    auto        message      = parseHexStrToBin(std::get<1>(data));
    auto        expected_mac = parseHexStrToBin(std::get<2>(data));

    const Uint64                    numBuffers = 8;
    std::vector<const Uint8*>       pp_msg_buf(numBuffers, &message[0]);
    std::vector<std::vector<Uint8>> output_macs(
        numBuffers, std::vector<Uint8>(expected_mac.size()));
    std::vector<Uint8*> pp_dst_buf(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        pp_dst_buf[i] = &output_macs[i][0];
    }

    HmacMB hmac_mb;
    hmac_mb.init(&key[0], key.size(), ALC_MB_SHA2_224);

    ASSERT_EQ(hmac_mb.flush(&pp_msg_buf[0], numBuffers, message.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(hmac_mb.dequeue(&pp_dst_buf[0], numBuffers), ALC_ERROR_NONE);

    for (Uint64 i = 0; i < numBuffers; i++) {
        EXPECT_EQ(output_macs[i], expected_mac)
            << "SHA2-224 Buffer " << i << " MAC mismatch";
    }
}
