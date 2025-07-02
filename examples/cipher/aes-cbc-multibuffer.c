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

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/time.h>
#elif WIN32
#include <windows.h>
#endif

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;

// #define DEBUG_P /* Enable for debugging only */

// debug prints to be print input, cipher, iv and decrypted output
#if 0
static inline void
printText(Uint8* I, Uint64 len, char* s)
{
    printf("\n %s ", s);
    for (int x = 0; x < len; x++) {
        if ((x % (16 * 4) == 0)) {
            printf("\n");
        }
        if (x % 16 == 0) {
            printf("   ");
        }
        printf(" %2x", *(I + x));
    }
}
#endif


void
getinput(Uint8* output, int inputLen)
{
    for (int i = 0; i < inputLen; i++) {
        Uint64 x = i + 20 + (i * 3); // simple equation to get generate input
        *output  = (Uint8)x;
        output++;
    }
}

int
create_aes_multibuffer_session(Uint8* key, Uint8* iv, const Uint32 key_len, const alc_cipher_mode_t mode)
{
    alc_error_t err = ALC_ERROR_NONE;
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size());
    if (!handle.ch_context) {
        printf("Error: context allocation failed \n");
        goto out;
    }
    /* Request a context with mode and key length */
    err = alcp_cipher_request(mode, key_len, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        goto out;
    }
    err = alcp_cipher_init(&handle, key, key_len, iv, 16);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: Unable to init \n");
        goto out;
    }
    const Uint8 *iv_list[4] = {iv, iv, iv, iv};
    err = alcp_multibuffer_init(&handle, NULL, 0, &iv_list[0], 16, 4);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: Unable to init multibuffer \n");
        goto out;
    }
    return 0;

    // Incase of error, program execution will come here
out:
    return -1;
}

void
end_aes_session()
{
    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);
    free(handle.ch_context);
}

/* AES modes: Encryption Demo */
void
alcp_aes_multibuffer_encrypt_demo(
    const Uint8* plaintxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt)
{
    alc_error_t err;
    // flush the plaintext to the internal buffer
    const Uint8 *p_plaintxt[4] = {plaintxt, plaintxt, plaintxt, plaintxt};
    err = alcp_flush(&handle, p_plaintxt, 4, len);
    if (alcp_is_error(err)) {
        printf("Error: unable to flush plaintext \n");
        return;
    }
    // dequeue the ciphertext from the internal buffer
    Uint8 *p_ciphertxt[4];
    // allocate memory for ciphertext
    for (int i = 0; i < 4; i++) {
        p_ciphertxt[i] = malloc(len);
        if (!p_ciphertxt[i]) {
            printf("Error: unable to allocate memory for ciphertext\n");
            return;
        }
    }
    err = alcp_dequeue(&handle, p_ciphertxt, 4, len);
    if (alcp_is_error(err)) {
        printf("Error: unable to dequeue ciphertext \n");
        return;
    }
    else    
    {
        printf("Dequeue done\n");
    }

    memcpy(ciphertxt, p_ciphertxt[1], len);
    // free the allocated memory for ciphertext
    for (int i = 0; i < 4; i++) {
        if (p_ciphertxt[i]) {
            free(p_ciphertxt[i]);
            p_ciphertxt[i] = NULL;
        }
    }
    return;
}

void
alcp_aes_multibuffer_decrypt_demo(
    const Uint8* ciphertxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       plaintxt)
{
    alc_error_t err;

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        return;
    }
}

/*
    Demo application for complete path:
    input->encrypt->cipher->decrypt->output.
    input and output is matched for comparison.
*/
void
multibuffer_encrypt_decrypt_demo(Uint8* inputText,  // plaintext
                                Uint32 inputLen,   // input length
                                Uint8* cipherText, // ciphertext output
                                alc_cipher_mode_t m,
                                int i)
{
    unsigned int keybits;
    Uint8        key[32];
    memset(key, 0, 32);

    Uint8* outputText;
    outputText = malloc(inputLen);

    Uint8* iv;
    iv = malloc(128 * 4);
    memset(iv, 10, 128 * 4);

    Uint8* ref;
    ref = malloc(inputLen);

    keybits = 128 + i * 64;
    printf(" keybits %d \n", keybits);
    memset(key, 120, 32);

    // Sample plaintext (32 bytes / 2 blocks)
    memset(cipherText, 0, inputLen);
    memset(ref, 0, inputLen);
    memset(outputText, 0, inputLen);
    //printText(key, 16, "key      ");
    //printText(inputText, inputLen, "inputText");

    create_aes_multibuffer_session(key, iv, keybits, m);
    alcp_aes_multibuffer_encrypt_demo(inputText, inputLen, cipherText);
    //printText(cipherText, inputLen, "cipherTxt");

    end_aes_session();

    create_aes_multibuffer_session(key, iv, keybits, m);
    alcp_aes_multibuffer_decrypt_demo(
            cipherText,  // pointer to the PLAINTEXT
            inputLen,    // text length in bytes
            outputText); // pointer to the CIPHERTEXT buffer

    //printText(outputText, inputLen, "outputTxt");
    end_aes_session();

    if (outputText) {
        free(outputText);
    }
    if (iv) {
        free(iv);
    }
    if (ref) {
        free(ref);
    }
}

/* FIXME */
#define MAX_TEST_CASE 1

int
main(void)
{
    Uint8* inputText;
    Uint8* cipherText;

    /*
     * Demo application to demonstrate speed of different AES Cipher modes.
     */

    printf("\n AOCL-CRYPTO: AES Cipher Speed test application ");
    alc_cipher_mode_t m = ALC_AES_MODE_CBC;

    // keep length multiple of 128bit (16x8)
    int testblkSizes[MAX_TEST_CASE] = { 16 };

    int keySizeItr = 0;
    //int keySizeItr = 0; // 0:128, 1:192, 2:256
    for (int i = 0; i < MAX_TEST_CASE; i++) {
        int inputLen = testblkSizes[i];
        printf("Input length: %d\n", inputLen);

        // allocate inputText and cipherText memory
        inputText = malloc(inputLen);
        if (inputText == NULL) {
            return -1;
        }
        cipherText = malloc(inputLen);
        if (cipherText == NULL) {
            if (inputText) {
                free(inputText);
            }
            return -1;
        }

        // run full path demo for specific aes mode
        multibuffer_encrypt_decrypt_demo(
            inputText,
            inputLen, /* len of both 'plaintxt' and 'ciphertxt' */
            cipherText,
            m,
            keySizeItr);

        if (inputText) {
            free(inputText);
        }
        if (cipherText) {
            free(cipherText);
        }
    }
    printf(" \n");

    return 0;
}