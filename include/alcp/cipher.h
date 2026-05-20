/*
 * Copyright (C) 2021-2026, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_CIPHER_H_
#define _ALCP_CIPHER_H_ 2

#include <stddef.h>

#include "alcp/error.h"
#include "alcp/key.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @defgroup cipher Cipher API
 * @brief
 * Cipher is a cryptographic technique used to
 * secure information by transforming a message into a cryptic form that can
 * only be read by those with the key to decipher it.
 *  @{
 */

/**
 * @brief Specify which mode to be used for encrypt and decrypt.
 *
 * @enum alc_cipher_mode
 */
typedef enum alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0, /**< No cipher mode selected */

    // aes ciphers
    ALC_AES_MODE_ECB, /**< AES Electronic Codebook mode */
    ALC_AES_MODE_CBC, /**< AES Cipher Block Chaining mode */
    ALC_AES_MODE_OFB, /**< AES Output Feedback mode */
    ALC_AES_MODE_CTR, /**< AES Counter mode */
    ALC_AES_MODE_CFB, /**< AES Cipher Feedback mode */
    ALC_AES_MODE_XTS, /**< AES XEX-based Tweaked-codebook mode with ciphertext Stealing */
    // non-aes ciphers
    ALC_CHACHA20, /**< ChaCha20 stream cipher */
    // aes AEAD ciphers
    ALC_AES_MODE_GCM, /**< AES Galois/Counter Mode (AEAD) */
    ALC_AES_MODE_CCM, /**< AES Counter with CBC-MAC (AEAD) */
    ALC_AES_MODE_SIV, /**< AES Synthetic Initialization Vector (AEAD) */
    // non-aes aead ciphers
    ALC_CHACHA20_POLY1305, /**< ChaCha20-Poly1305 authenticated encryption (AEAD) */

    ALC_AES_MODE_MAX, /**< Sentinel value for mode enumeration */

} alc_cipher_mode_t;

typedef struct _alc_cipher_state
{
    __attribute__((aligned(64))) Uint64 alcp_exp_enc_key[64];
    __attribute__((aligned(64))) Uint64 alcp_exp_dec_key[64];
    __attribute__((aligned(64))) Uint64 alcp_precomputed_table[64];
    Uint32                              alcp_keyLen_in_bytes;

} alc_cipher_state_t;

/**
 * @brief  Opaque type of a cipher context, comes from the library.
 *
 * @typedef void alc_cipher_context_t
 */
typedef void                  alc_cipher_context_t;
typedef alc_cipher_context_t* alc_cipher_context_p;

/**
 *
 * @brief Handle for maintaining session.
 *
 * @param alc_cipher_context_p pointer to the user allocated context of the
 * cipher
 *
 * @struct alc_cipher_handle_t
 *
 */
typedef struct _alc_cipher_handle
{
    alc_cipher_context_p ch_context;
} alc_cipher_handle_t, *alc_cipher_handle_p;

/**
 * @brief       Gets the size of the context for a session
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_cipher_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 * @return      Size of context in bytes
 */
ALCP_API_EXPORT Uint64
alcp_cipher_context_size(void);

/**
 * @brief    Request for populating handle with algorithm specified by
 * cipher mode and key Length.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_context_size is called </b>
 * @endparblock
 * @note     Error needs to be checked for each call.
 *           Valid only if @ref alcp_is_error (ret) is false
 * @param [in]    cipherMode       cipher mode to be set
 * @param [in]    keyLen           key length in bits
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_request(const alc_cipher_mode_t cipherMode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle);

/**
 * @brief  Cipher init.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is
 * called.</b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param[in] pKey  Key
 * @param[in] keyLen  key Length in bits
 * @param[in] pIv  IV/Nonce
 * @param[in] ivLen  IV length in bytes
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
                 const Uint8*              pKey,
                 Uint64                    keyLen,
                 const Uint8*              pIv,
                 Uint64                    ivLen);

/**
 * @brief       Initialize multi-buffer cipher operation with key and per-buffer IVs.
 *
 * @parblock <br> &nbsp;
 * <b>This API prepares a multi-buffer cipher session for parallel encryption
 * of multiple independent buffers. It must be called after
 * @ref alcp_cipher_request and before @ref alcp_flush.</b>
 *
 * Multi-buffer mode processes up to 127 independent plaintext buffers in
 * parallel using AVX-512 instructions. Each buffer uses its own IV for
 * independent encryption streams.
 *
 * Supported cipher modes: AES-CBC, AES-CFB.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @note     Requires AVX-512 capable CPU. Otherwise falls back to single buffer implementation.
 *
 * @param[in] pCipherHandle  Session handle from @ref alcp_cipher_request
 * @param[in] pKey           Encryption key (NULL to reuse key from request)
 * @param[in] keyLen         Key length in bits (0 if pKey is NULL)
 * @param[in] pIv            Array of pointers to IV buffers, one per buffer
 * @param[in] ivLen          Length of each IV in bytes (e.g., 16 for AES)
 * @param[in] numBuffers     Number of buffers to process (max 127)
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_multibuffer_init(const alc_cipher_handle_p pCipherHandle,
                      const Uint8*              pKey,
                      Uint64                    keyLen,
                      const Uint8**             pIv,
                      Uint64                    ivLen,
                      Uint64                    numBuffers);
/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request and before @ref
 * alcp_cipher_finish</b> <b>API is meant to be used with CBC,CTR,CFB,OFB,XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pCipherHandle Session handle for future encrypt/decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    datalen           Length of cipher/plain text
 * @param[out]   outlen        Pointer to store actual bytes written to
 * pCipherText
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    datalen,
                    Uint64*                   outlen);

/**
 * @brief    Decrypt the cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request and before @ref
 * alcp_cipher_finish</b> <b>API is meant to be used with CBC,CTR,CFB,OFB,XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pCipherText   Pointer to Cipher Text
 * @param[out]   pPlainText    Pointer to Plain Text
 * @param[in]    datalen           Length of cipher/plain text
 * @param[out]   outlen        Pointer to store actual bytes written to
 * pPlainText
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    datalen,
                    Uint64*                   outlen);

/**
 * @brief       Release resources allocated by alcp_cipher_request.
 * @parblock <br> &nbsp;
 * <b>This API is called to free the session resources</b>
 * @endparblock
 * @note       alcp_cipher_finish has to be called at the end of the
 * transaction. Context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt/decrypt
 *                         operation
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

/**
 * @brief Copy a cipher context from source to destination
 *
 * @parblock <br> &nbsp;
 * <b>This API allows copying all state information from one cipher context to
 * another. Both source and destination must be initialized with the same cipher
 * mode and key length.</b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @param[in]  src  Source cipher handle containing the context to copy from
 * @param[out] dst  Destination cipher handle where the context will be copied
 * to
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_context_copy(const alc_cipher_handle_p src,
                         alc_cipher_handle_p       dst);

/**
 * @brief       Enqueue multiple plaintext buffers for parallel encryption.
 *
 * @parblock <br> &nbsp;
 * <b>Stages a batch of plaintext buffers for parallel SIMD encryption.
 * Each buffer can have a different length (variable-length multi-buffer).
 * Call @ref alcp_dequeue to retrieve the encrypted results.</b>
 *
 * This API must be called after @ref alcp_multibuffer_init. The buffers
 * are not encrypted immediately — actual processing happens during
 * @ref alcp_dequeue.
 *
 * Supported cipher modes: AES-CBC, AES-CFB.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @note     Requires AVX-512 capable CPU for SIMD multi-buffer execution.
 *           On platforms without AVX-512, falls back to single-buffer
 *           processing.
 *
 * @pre      @ref alcp_multibuffer_init must be called before this API.
 *
 * @param[in] pCipherHandle  Session handle for cipher operation
 * @param[in] pPlainText     Array of pointers to plaintext buffers
 * @param[in] pLengths       Array of per-buffer lengths in bytes
 * @param[in] numBuffers     Number of buffers in the batch (max 127)
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_flush(const alc_cipher_handle_p pCipherHandle,
                   const Uint8**             pPlainText,
                   const Uint64*             pLengths,
                   Uint64                    numBuffers);

/**
 * @brief       Retrieve encrypted ciphertext from multi-buffer operation.
 *
 * @parblock <br> &nbsp;
 * <b>Performs the actual parallel encryption of buffers staged via
 * @ref alcp_flush and writes results to the provided output buffers.
 * Uses the Iterative MinLen algorithm for maximum SIMD parallelism across
 * variable-length buffers.</b>
 *
 * Each output buffer must be pre-allocated by the caller with at least
 * the corresponding length from pLengths.
 *
 * Supported cipher modes: AES-CBC, AES-CFB.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @note     On platforms without AVX-512, falls back to single-buffer
 *           processing.
 *
 * @pre      @ref alcp_flush must be called before this API.
 *
 * @param[in]  pCipherHandle  Session handle for cipher operation
 * @param[out] pCipherText    Array of pointers to pre-allocated output buffers
 * @param[in]  numBuffers     Number of buffers to dequeue
 * @param[in]  pLengths       Array of per-buffer lengths in bytes
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_dequeue(const alc_cipher_handle_p pCipherHandle,
                     Uint8**                   pCipherText,
                     Uint64                    numBuffers,
                     const Uint64*             pLengths);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */

/**
 * @}
 */
