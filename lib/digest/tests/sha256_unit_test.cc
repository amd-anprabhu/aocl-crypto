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

#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha2_mb.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 32;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 64;
// IV array size where every element is 4 bytes

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} },
    { "Symbols", 
            { "!@#$",
                "1296bfb42b244aa5811e4098497329f3845ca6a3715c1da844d1999acc5cdfdd"} },
    { "All_Char",
            { "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"} },
    { "All_Num",
            { "123", 
                "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"}}
};

// clang-format on
class Sha256Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha256Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    Uint8                   hash[DigestSize];
    std::stringstream       ss;

    sha256->init();
    ASSERT_EQ(sha256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(sha256->finalize(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha256Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha256Test::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST(Sha256Test, invalid_input_update_test)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256->update(nullptr, 0));
}

TEST(Sha256Test, zero_size_update_test)
{
    std::unique_ptr<Sha256> sha256          = std::make_unique<Sha256>();
    const Uint8             src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha256->update(src, 0));
}

TEST(Sha256Test, invalid_output_copy_hash_test)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256->finalize(nullptr, DigestSize));
}

TEST(Sha256Test, zero_size_hash_copy_test)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    Uint8                   hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256->finalize(hash, 0));
}

TEST(Sha256Test, over_size_hash_copy_test)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    Uint8                   hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256->finalize(hash, DigestSize + 1));
}

TEST(Sha256Test, call_finalize_twice_test)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    Uint8                   hash[DigestSize];
    // calling finalize multiple times should not result in error
    EXPECT_EQ(ALC_ERROR_NONE, sha256->finalize(hash, DigestSize));
    EXPECT_EQ(ALC_ERROR_NONE, sha256->finalize(hash, DigestSize));
}

TEST(Sha256Test, getInputBlockSizeTest)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    EXPECT_EQ(sha256->getInputBlockSize(), InputBlockSize);
}
TEST(Sha256Test, getHashSizeTest)
{
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    EXPECT_EQ(sha256->getHashSize(), DigestSize);
}

TEST(Sha256Test, object_copy_test)
{
    string                  plaintext("1111");
    std::unique_ptr<Sha256> sha256 = std::make_unique<Sha256>();
    Uint8                   hash[DigestSize], hash_dup[DigestSize];
    std::stringstream       ss, ss_dup;

    sha256->init();
    ASSERT_EQ(sha256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);

    std::unique_ptr<Sha256> sha256_dup = std::make_unique<Sha256>(*sha256);

    ASSERT_EQ(sha256->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha256_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    ss_dup << std::hex << std::setfill('0');

    for (Uint16 i = 0; i < DigestSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
        ss_dup << std::setw(2) << static_cast<unsigned>(hash_dup[i]);
    }
    std::string hash_string = ss.str(), hash_string_dup = ss_dup.str();
    EXPECT_TRUE(hash_string == hash_string_dup);
}

TEST_P(Sha256Test, multibuffer_digest_generate)
{
    const auto [plaintext, digest]   = GetParam().second;
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();
    Uint8                     hash[DigestSize];
    std::stringstream         ss;

    const Uint8* pp_src[16];
    Uint8*       pp_dst[16];
    std::fill_n(pp_src, 16, (const Uint8*)plaintext.c_str());
    std::fill_n(pp_dst, 16, (Uint8*)hash);

    sha256->init();
    ASSERT_EQ(sha256->flush(pp_src, 16, plaintext.size()), ALC_ERROR_NONE);
    ASSERT_EQ(sha256->dequeue(pp_dst, 16, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

TEST(Sha256Test, multibuffer_zero_size_update)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* empty = reinterpret_cast<const Uint8*>("");
    Uint8        hash[DigestSize]{};
    const Uint8* pp_src[16];
    Uint8*       pp_dst[16];

    std::fill_n(pp_src, 16, empty);
    std::fill_n(pp_dst, 16, (Uint8*)hash);

    sha256->init();
    EXPECT_EQ(sha256->flush(pp_src, 16, 0), ALC_ERROR_NONE);
    EXPECT_EQ(sha256->dequeue(pp_dst, 16, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_NONE);
}

TEST(Sha256Test, multibuffer_dequeue_without_flush)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    Uint8  hash[DigestSize]{};
    Uint8* pp_dst[16];
    std::fill_n(pp_dst, 16, (Uint8*)hash);

    sha256->init();
    EXPECT_EQ(sha256->dequeue(pp_dst, 16, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_INVALID_ARG);
}

TEST(Sha256Test, multibuffer_invalid_input)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* pp_src[16];
    std::fill_n(pp_src, 16, nullptr);

    sha256->init();
    EXPECT_EQ(sha256->flush(pp_src, 16, 0), ALC_ERROR_INVALID_DATA);
}

TEST(Sha256Test, multibuffer_invalid_digest_length)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* msg = reinterpret_cast<const Uint8*>("abc");
    const Uint8* pp_src[16];
    Uint8        hash[DigestSize]{};
    Uint8*       pp_dst[16];

    std::fill_n(pp_src, 16, msg);
    std::fill_n(pp_dst, 16, (Uint8*)hash);

    auto wrong_digest_len = ALC_DIGEST_LEN_160 / 8;

    sha256->init();
    EXPECT_EQ(sha256->flush(
                  pp_src, 16, std::strlen(reinterpret_cast<const char*>(msg))),
              ALC_ERROR_NONE);
    EXPECT_EQ(sha256->dequeue(pp_dst, 16, wrong_digest_len),
              ALC_ERROR_INVALID_ARG);
}

TEST(Sha256Test, multibuffer_buffers_missmatch)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* msg = reinterpret_cast<const Uint8*>("abc");
    const Uint8* pp_src[16];
    Uint8        hash[DigestSize]{};
    Uint8*       pp_dst[32];

    std::fill_n(pp_src, 16, msg);
    std::fill_n(pp_dst, 32, (Uint8*)hash);

    sha256->init();
    EXPECT_EQ(sha256->flush(
                  pp_src, 16, std::strlen(reinterpret_cast<const char*>(msg))),
              ALC_ERROR_NONE);
    EXPECT_EQ(sha256->dequeue(pp_dst, 0, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_INVALID_ARG);
    EXPECT_EQ(sha256->dequeue(pp_dst, 32, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_INVALID_ARG);
    EXPECT_EQ(sha256->dequeue(pp_dst, 8, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_NONE);
}

TEST(Sha256Test, multibuffer_invalid_digest)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* msg = reinterpret_cast<const Uint8*>("abc");
    const Uint8* pp_src[16];
    Uint8*       pp_dst[32];

    std::fill_n(pp_src, 16, msg);
    std::fill_n(pp_dst, 32, nullptr);

    sha256->init();
    EXPECT_EQ(sha256->flush(
                  pp_src, 16, std::strlen(reinterpret_cast<const char*>(msg))),
              ALC_ERROR_NONE);
    EXPECT_EQ(sha256->dequeue(pp_dst, 16, ALC_DIGEST_LEN_256 / 8),
              ALC_ERROR_INVALID_DATA);
}

TEST(Sha256Test, multibuffer_max_input_size)
{
    std::unique_ptr<Sha256MB> sha256 = std::make_unique<Sha256MB>();

    const Uint8* msg = reinterpret_cast<const Uint8*>("abc");
    const Uint8* pp_src[16];
    std::fill_n(pp_src, 16, msg);

    sha256->init();
    EXPECT_EQ(sha256->flush(pp_src, 16, UINT64_MAX / 8), ALC_ERROR_INVALID_ARG);
    EXPECT_EQ(sha256->flush(pp_src, 16, UINT64_MAX / 8 + 64),
              ALC_ERROR_INVALID_ARG);
}

} // namespace
