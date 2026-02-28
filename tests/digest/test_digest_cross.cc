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
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "digest/gtest_base_digest.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <exception>
#include <iostream>
#include <string.h>

/* SHA3 SHAKE Cross */
TEST(DIGEST_SHA3, CROSS_SHAKE128)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(128, ALC_SHAKE_128, false);
}
TEST(DIGEST_SHA3, CROSS_SHAKE128_CTX_COPY)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(128, ALC_SHAKE_128, true);
}

TEST(DIGEST_SHA3, CROSS_SHAKE256)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(256, ALC_SHAKE_256, false);
}

/* SHA2 cross tests */
TEST(DIGEST_SHA2, CROSS_224)
{
    Digest_Cross(224, ALC_SHA2_224, false);
}
TEST(DIGEST_SHA2, CROSS_224_CTX_COPY)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "Ctx copy tests are not yet enabled for ipp";
    Digest_Cross(224, ALC_SHA2_224, true);
}

TEST(DIGEST_SHA2, CROSS_256)
{
    Digest_Cross(256, ALC_SHA2_256, false);
}
TEST(DIGEST_SHA2, CROSS_384)
{
    Digest_Cross(384, ALC_SHA2_384, false);
}
TEST(DIGEST_SHA2, CROSS_512)
{
    Digest_Cross(512, ALC_SHA2_512, false);
}
/* truncated sha512 variants */
TEST(DIGEST_SHA2, CROSS_512_224)
{
    Digest_Cross(224, ALC_SHA2_512_224, false);
}
TEST(DIGEST_SHA2, CROSS_512_256)
{
    Digest_Cross(256, ALC_SHA2_512_256, false);
}

/* SHA3 cross tests */
/* NOTE: IPPCP doesnt support SHA3 as of now,
 SHA3 tests will be skipped for IPPCP */
TEST(DIGEST_SHA3, CROSS_224)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(224, ALC_SHA3_224, false);
}
TEST(DIGEST_SHA3, CROSS_224_CTX_COPY)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(224, ALC_SHA3_224, true);
}

TEST(DIGEST_SHA3, CROSS_256)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(256, ALC_SHA3_256, false);
}
TEST(DIGEST_SHA3, CROSS_384)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_Cross(384, ALC_SHA3_384, false);
}
TEST(DIGEST_SHA3, CROSS_512)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_Cross(512, ALC_SHA3_512, false);
}

TEST(DIGEST_SHA1, CROSS_160)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA1 implemented yet";
    Digest_Cross(160, ALC_SHA1, false);
}

TEST(DIGEST_SHA2_MB, CROSS_224)
{
    if (useipp || useossl || oa_override)
        GTEST_SKIP()
            << "IPP/OSSL doesnt have SHA224 multibuffer implemented yet";
    Digest_Multibuffer_Cross(224, ALC_SHA2_224);
}

TEST(DIGEST_SHA2_MB, CROSS_256)
{
    if (useipp || useossl || oa_override)
        GTEST_SKIP()
            << "IPP/OSSL doesnt have SHA256 multibuffer implemented yet";
    Digest_Multibuffer_Cross(256, ALC_SHA2_256);
}

int
main(int argc, char** argv)
{
    try {
        ::testing::InitGoogleTest(&argc, argv);
        parseTestArgs(argc, argv);
#ifndef USE_IPP
        if (useipp)
            printErrors("IPP is not available");
#endif
#ifndef USE_OSSL
        if (useossl)
            printErrors("OpenSSL is not available");
#endif
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