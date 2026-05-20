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

#include <alcp/digest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIGEST_SIZE 28
#define NUM_MSGS    16

struct mb_test_vector
{
    const char* input;
    const char* expected_digest;
};

static const struct mb_test_vector MB_TEST_VECTORS[NUM_MSGS] = {
    { "In 2024, the global technology landscape continues to evolve rapidly, "
      "driven by ",
      "a6c2a3376e57ea50281cb338a89c8c3ebf64505485363c28283a6a88" },
    { "The quick brown fox jumps over the lazy dog while simultaneously "
      "calculating the",
      "00ab26fedcd464cfe69a21126db78e92d1709fed0e2521f335923c78" },
    { "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor i",
      "4fceca5865271aae31eef5ff737ae539f351fe9bfc0bc9a29a5bf4c6" },
    { "RandomData: "
      "9a8b7c6d5e4f3g2h1i0j7k6l5m4n3o2p1q0r9s8t7u6v5w4x3y2z1A2B3C4D5E6F7G8H",
      "fd02fcefeda3ec1117fd2790d40653e580183d2f51bd6068b191b23a" },
    { "The rain in Spain stays mainly in the plain, according to the famous "
      "musical lyr",
      "efaa3e2f30d49504b6f42648f6ef1d4079ea4b6cceeb6d748da854f2" },
    { "A watched pot never boils, but patience is a virtue in both cooking and "
      "programm",
      "8d21e0bde0a42f284939b4d5546465cd5e29f8cc28c1926f2f74650f" },
    { "Security is not a product, but a process that requires continuous "
      "improvement an",
      "f4337de335e03951205a4805c4824c87cb3e906808818fc32705a247" },
    { "RandomString: "
      "!@#$$%^&*()_+{}|:\"<>?[];',./`~qazwsxedcrfvtgbyhnujmikolp1234567890",
      "f080d183569e7531fc956601a444a70bd08f347e4f15a5c2044a3b4c" },
    { "The best way to predict the future is to invent it, as said by computer "
      "pioneer ",
      "993742b80ad85de6455b8e3aef93935d8d827f15a478c4a8b9841c08" },
    { "In cryptography, hashing algorithms are used to ensure data integrity "
      "and securi",
      "1b3f1407d5222b2fc12adeadca4eb179306cb53c197258e7649c06fc" },
    { "To be or not to be, that is the question asked by Hamlet in "
      "Shakespeare's famous",
      "8df8cdd1259143118138d70ee1f70e03282b3ba3e51b452ed4d1336f" },
    { "RandomBlock: "
      "0xDEADBEEFCAFEBABE1234567890ABCDEF0987654321FEDCBA0987abcdef6543210",
      "5ad6ece28ee8f4bb12c59a050f20780778f4802a97f703e5ceff45d3" },
    { "Always validate user input to prevent security vulnerabilities in "
      "software desig",
      "9d8ca13069d0174f6d3c479b18277fbbc140e684693f17690ddb09be" },
    { "A journey of a thousand miles begins with a single step, according to "
      "ancient wi",
      "d344824a19d2fe34d1ac0b1ce6c3b7dee633c45f79fd561bbe1a2508" },
    { "RandomPhrase: "
      "pL0k9j8h7g6f5d4s3a2z1x0c9v8b7n6m5q4w3e2r1t0y9u8i7o6p5l4k3j2h1g0f9d",
      "594659d10ce22652ded5787a1fcc672746a69ae9596feb9edef6ec45" },
    { "The quick brown fox jumps over the lazy dog while the sun sets behind "
      "the mounta",
      "67c06ce630263a94476ecfff608c9ea36dcec796f2aadb9b0016ad5d" }
};

static alc_digest_handle_t s_dg_handle;

static void
digest_to_hex(char* out, const Uint8* digest, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
    out[len * 2] = '\0';
}

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;
    Uint64      size    = alcp_digest_context_size();
    s_dg_handle.context = malloc(size);

    if (!s_dg_handle.context) {
        return ALC_ERROR_NO_MEMORY;
    }

    err = alcp_digest_request(ALC_MB_SHA2_224, &s_dg_handle);

    if (alcp_is_error(err)) {
        printf("alcp_digest_request failed");
        return err;
    }

    err = alcp_digest_init(&s_dg_handle);

    if (alcp_is_error(err)) {
        printf("alcp_digest_init failed");
        return err;
    }

    return err;
}

int
main(void)
{
    alc_error_t err = create_demo_session();
    if (alcp_is_error(err)) {
        return -1;
    }

    int failed = 0;

    const Uint8* src[NUM_MSGS];
    Uint64       msg_len = strlen(MB_TEST_VECTORS[0].input);
    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        src[i] = (const Uint8*)MB_TEST_VECTORS[i].input;
        if (strlen(MB_TEST_VECTORS[i].input) != msg_len) {
            printf("All messages must have the same length for multibuffer "
                   "SHA2-224\n");
            return -1;
        }
    }

    Uint8* dst[NUM_MSGS];
    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        dst[i] = malloc(DIGEST_SIZE);
        if (!dst[i]) {
            printf("Memory allocation failed\n");
            for (int j = 0; j < i; j++)
                free(dst[j]);
            return -1;
        }
    }

    err = alcp_digest_flush(&s_dg_handle, src, NUM_MSGS, msg_len);
    if (alcp_is_error(err)) {
        printf("alcp_digest_flush failed\n");
        goto cleanup;
    }
    err = alcp_digest_dequeue(&s_dg_handle, dst, NUM_MSGS, DIGEST_SIZE);
    if (alcp_is_error(err)) {
        printf("alcp_digest_dequeue failed\n");
        goto cleanup;
    }

    char hex_output[DIGEST_SIZE * 2 + 1];
    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        digest_to_hex(hex_output, dst[i], DIGEST_SIZE);
        printf("Input[%llu]: %s\n",
               (unsigned long long)i,
               MB_TEST_VECTORS[i].input);
        printf("Output[%llu]: %s\n", (unsigned long long)i, hex_output);
        if (strcmp(hex_output, MB_TEST_VECTORS[i].expected_digest) != 0) {
            printf("=== FAILED ===\nExpected: %s\n",
                   MB_TEST_VECTORS[i].expected_digest);
            failed = 1;
        } else {
            printf("=== Passed ===\n");
        }
        printf("\n");
    }

cleanup:
    alcp_digest_finish(&s_dg_handle);
    for (int i = 0; i < NUM_MSGS; i++) {
        free(dst[i]);
    }
    free(s_dg_handle.context);
    return failed ? -1 : 0;
}
