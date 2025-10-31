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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <alcp/digest.h>
static alc_digest_handle_t s_dg_handle;

#define DIGEST_SIZE 32
#define NUM_MSGS    16

struct mb_test_vector
{
    const char* input;
    const char* expected_digest;
};

static const struct mb_test_vector MB_TEST_VECTORS[NUM_MSGS] = {
    { "Security is not a product, but a process that requires continuous "
      "improvement an",
      "c85d76480f5e6201cf1470fc5d4513355a583296028b372564228a0156cd562c" },
    { "The best way to predict the future is to invent it, as said by computer "
      "pioneer ",
      "9143fd979454a2cf0ad1295a8f2c73f5fec85441de81e780c6fd7ff006ba1629" },
    { "RandomString1: "
      "a8f3k2l9w0x7v6b5n4m3q2p1o0z9y8t7r6e5d4c3b2a1s0f9g8h7j6k5l4m3n2b1v",
      "943b730e436f14d6046abad5e755cdf6a6b4ff805d00905ecda91c9ca3e77fe6" },
    { "RandomString5: "
      "MNBVCXZLKJHGFDSAPOIUYTREWQmnbvcxzlkjhgfdsapoiuytrewq0987654321   ",
      "178a8d8740423cab08924c122a2b2c68f3fe95f6294b0554c2b2e6690b8c0920" },
    { "RandomString3: "
      "9z8x7c6v5b4n3m2a1s0d9f8g7h6j5k4l3q2w1e0r9t8y7u6i5o4p3z2x1c0v9b8n7",
      "047cb8fef19f7ed042b4ca41089df78a9c642c8911e70c7eb5aefab5fe3c4a86" },
    { "A journey of a thousand miles begins with a single step, according to "
      "ancient wi",
      "39e97c71ec49efe03fedacf00d14c47b34689aedfe7260652d03efe59558430a" },
    { "Always validate user input to prevent security vulnerabilities in "
      "software desig",
      "af41c32c39aa53d5f8222b9c6f93ec5d75a86dce6475a68f6ac873c70e3d5a1b" },
    { "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor. ",
      "0fe8997cfece9295f0d47510882b79d4543d956b5190c4012fc395e3bc7c3e54" },
    { "The rain in Spain stays mainly in the plain, according to the famous "
      "musical lyr",
      "c1f3f4a77b90fc8cab112c04faba009d4d6f6e09c3d43277209d108aaed56664" },
    { "RandomString2: "
      "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@#",
      "6c16d6b46bbaea01d697a4058baa48c3b2715a965b9cd6a3a0e6ecf4504b3573" },
    { "A watched pot never boils, but patience is a virtue in both cooking and "
      "programm",
      "a6c57821ae1603aa2b73de632b32adc9a9367625d77cd021492ca141e766840f" },
    { "RandomString4: "
      "!@#$$%^&*()_+{}|:\"<>?[];',./`~qazwsxedcrfvtgbyhnujmikolp123456789",
      "2d12b2c833a38bbfa4d5b471e69c001417440b657c2124503781bf4c09b7e742" },
    { "To be or not to be, that is the question asked by Hamlet in "
      "Shakespeare's famous",
      "ac653755d9b88cc8551f71219054539fd81b8fae1d6b8ee94bb0be370995b968" },
    { "The quick brown fox jumps over the lazy dog while the sun sets behind "
      "the mounta",
      "480a224432bdf4308bc84c6d5ec53a6d64cc690b451f4a5fe6a4df8949731043" },
    { "In cryptography, hashing algorithms are used to ensure data integrity "
      "and securi",
      "fb26c1e76ac67ff25bdb3a8c40de632932f3a89cda13d7720449856e6cfa3c63" },
    { "RandomString6: "
      "1q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0z1x2c3v4b5n6m7q8w9e0r1t2y3",
      "e732a52b5c87a510e3bd66241828323a5bcd1664e0b30a263339c4abdbc99226" }
};

// Helper to convert digest to hex string
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

    Uint64 size         = alcp_digest_context_size();
    s_dg_handle.context = malloc(size);

    if (!s_dg_handle.context) {
        return ALC_ERROR_NO_MEMORY;
    }

    err = alcp_digest_request(ALC_MB_SHA2_256, &s_dg_handle);

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

    // Prepare input pointers and output buffers
    const Uint8* src[NUM_MSGS];
    Uint64       msg_len = strlen(MB_TEST_VECTORS[0].input);
    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        src[i] = (const Uint8*)MB_TEST_VECTORS[i].input;
        // Ensure all messages are same length
        if (strlen(MB_TEST_VECTORS[i].input) != msg_len) {
            printf("All messages must have the same length for multibuffer "
                   "SHA256\n");
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
