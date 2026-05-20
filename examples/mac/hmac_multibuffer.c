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

#include <alcp/mac.h>

static alc_mac_handle_t s_mac_handle;

#define MAC_SIZE 32
#define NUM_MSGS 8
#define KEY_SIZE 64

struct mb_test_vector
{
    const char* input;
    const char* expected_hmac;
};

static const struct mb_test_vector MB_TEST_VECTORS[NUM_MSGS] = {
    { "Security is not a product, but a process that requires continuous "
      "improvement an",
      "a7cd354c57e117590530d4ad28486af4df921cd0f1f8f271c14af4627f0dc6b5" },
    { "The best way to predict the future is to invent it, as said by computer "
      "pioneer ",
      "fcafc940343b6daf07edc1d75fb7e89bb4c5cf09b612d67dc6c42f3da446d28d" },
    { "RandomString1: "
      "a8f3k2l9w0x7v6b5n4m3q2p1o0z9y8t7r6e5d4c3b2a1s0f9g8h7j6k5l4m3n2b1v",
      "84afee62ce72c3230129e758b36d9653176a195e61b7e62b010ff589153ad2b4" },
    { "RandomString5: "
      "MNBVCXZLKJHGFDSAPOIUYTREWQmnbvcxzlkjhgfdsapoiuytrewq0987654321   ",
      "fc55555bb965c087e8aa1576253cb306c22ade6dd8e6440a541b5b1ff967d818" },
    { "RandomString3: "
      "9z8x7c6v5b4n3m2a1s0d9f8g7h6j5k4l3q2w1e0r9t8y7u6i5o4p3z2x1c0v9b8n7",
      "b6e934ef05f5ae2b35a2d9818402af6dd2a991a01bc51c81fea12f1dc579b68c" },
    { "A journey of a thousand miles begins with a single step, according to "
      "ancient wi",
      "297c6c897f26d80e1646265e24e831f1007163711e45aa2a2fc2604f12b4dc72" },
    { "Always validate user input to prevent security vulnerabilities in "
      "software desig",
      "39e1ca7e72908b9fe75a410306ddf571be29a7bb73a46cc8e94025f08fe89ceb" },
    { "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor. ",
      "1e9ded3677e9a20dfff607e67d9de79226da0316bd6ee1883d92469b1a45be0e" }
};

// Helper to convert MAC to hex string
static void
mac_to_hex(char* out, const Uint8* mac, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", mac[i]);
    }
    out[len * 2] = '\0';
}

static alc_error_t
create_demo_session(const Uint8* key, Uint64 key_size)
{
    alc_error_t err;

    Uint64 size             = alcp_mac_context_size();
    s_mac_handle.ch_context = malloc(size);

    if (!s_mac_handle.ch_context) {
        return ALC_ERROR_NO_MEMORY;
    }

    err = alcp_mac_request(&s_mac_handle, ALC_MB_MAC_HMAC);

    if (alcp_is_error(err)) {
        printf("alcp_mac_request failed\n");
        return err;
    }

    alc_mac_info_t mac_info;
    mac_info.hmac.digest_mode = ALC_SHA2_256;

    err = alcp_mac_init(&s_mac_handle, key, key_size, &mac_info);

    if (alcp_is_error(err)) {
        printf("alcp_mac_init failed\n");
        return err;
    }

    return err;
}

int
main(void)
{
    // Key from dataset_HMAC_SHA2_256.csv (64 bytes: 0x00 to 0x3f)
    Uint8 key[KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };

    alc_error_t err = create_demo_session(key, KEY_SIZE);
    if (alcp_is_error(err)) {
        return -1;
    }

    Uint8* dst[NUM_MSGS];
    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        dst[i] = malloc(MAC_SIZE);
        if (!dst[i]) {
            printf("Memory allocation failed\n");
            for (int j = 0; j < i; j++)
                free(dst[j]);
            return -1;
        }
    }

    int failed = 0;

    // Prepare all message pointers for multibuffer processing
    const Uint8* src[NUM_MSGS];
    Uint64       msg_len = strlen(MB_TEST_VECTORS[0].input);

    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        src[i] = (const Uint8*)MB_TEST_VECTORS[i].input;
    }

    // Call flush once with all messages
    err = alcp_mac_flush(&s_mac_handle, src, NUM_MSGS, msg_len);
    if (alcp_is_error(err)) {
        printf("alcp_mac_flush failed\n");
        goto cleanup;
    }

    // Call dequeue once to get all results
    err = alcp_mac_dequeue(&s_mac_handle, dst, NUM_MSGS);
    if (alcp_is_error(err)) {
        printf("alcp_mac_dequeue failed\n");
        goto cleanup;
    }

    char hex_output[MAC_SIZE * 2 + 1];
    printf("HMAC-SHA256 Multibuffer Example\n");
    printf("================================\n\n");

    for (Uint64 i = 0; i < NUM_MSGS; i++) {
        mac_to_hex(hex_output, dst[i], MAC_SIZE);
        printf("Input[%llu]: %s\n",
               (unsigned long long)i,
               MB_TEST_VECTORS[i].input);
        printf("Computed: %s ", hex_output);

        if (strcmp(hex_output, MB_TEST_VECTORS[i].expected_hmac) == 0) {
            printf("\n=== Passed ===\n\n");
        } else {
            printf("\n=== Failed ===\n\n");
            failed = 1;
        }
    }

    if (failed) {
        printf("=== FAILED: Some HMACs did not match expected values ===\n");
    } else {
        printf("=== SUCCESS: All %d HMACs Verified Correctly ===\n", NUM_MSGS);
    }

cleanup:
    alcp_mac_finish(&s_mac_handle);
    for (int i = 0; i < NUM_MSGS; i++) {
        free(dst[i]);
    }
    free(s_mac_handle.ch_context);
    return failed ? -1 : 0;
}