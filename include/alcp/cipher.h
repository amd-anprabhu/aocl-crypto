/*
 * Copyright (C) 2021-2025, Advanced Micro Devices. All rights reserved.
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
 * @typedef enum  alc_cipher_mode_t
 */
typedef enum _alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0,

    // aes ciphers
    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTS,
    // non-aes ciphers
    ALC_CHACHA20,
    // aes AEAD ciphers
    ALC_AES_MODE_GCM,
    ALC_AES_MODE_CCM,
    ALC_AES_MODE_SIV,
    // non-aes aead ciphers
    ALC_CHACHA20_POLY1305,

    ALC_AES_MODE_MAX,

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
 * @return   &nbsp; Error Code for the API called.
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
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param[in] pKey  Key
 * @param[in] keyLen  key Length in bits
 * @param[in] pIv  IV/Nonce
 * @param[in] ivLen  IV length in bytes
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then an error has occurred and handle will be invalid
 * for future operations
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
                 const Uint8*              pKey,
                 Uint64                    keyLen,
                 const Uint8*              pIv,
                 Uint64                    ivLen);

/**
 * @brief  Initialize a cipher session for multi-buffer processing.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request. It prepares the
 * session to process multiple buffers in parallel by accepting an array of IVs
 * (one IV per buffer) for modes that support parallel buffers</b>
 * @endparblock
 * @param [in] pCipherHandle  Session handle for cipher operation
 * @param [in] pKey           Key
 * @param [in] keyLen         Key length in bits
 * @param [in] pIv            Array of pointers to IV/Nonce values (one per
 *                            buffer)
 * @param [in] ivLen          IV length in bytes (applies to every buffer)
 * @param [in] numBuffers     Number of buffers to be processed in parallel
 * @return   &nbsp; Error Code for the API called. If alc_error_t is not
 * ALC_ERROR_NONE then an error has occurred and handle will be invalid for
 * future operations
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
 * @return   &nbsp; Error Code for the API called.
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
 * @return   &nbsp; Error Code for the API called.
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
 *
 * @param[in]  src  Source cipher handle containing the context to copy from
 * @param[in]  dst  Destination cipher handle where the context will be copied
 * to
 *
 * @return Error code:
 *         - ALC_ERROR_NONE          Success
 *         - ALC_ERROR_BAD_STATE     Either src or dst is in an invalid state
 *         - ALC_ERROR_INVALID_ARG   Source and destination context types don't
 * match
 *         - ALC_ERROR_GENERIC       Generic error during copy operation
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_context_copy(const alc_cipher_handle_p src,
                         alc_cipher_handle_p       dst);

/**
 * @brief Submit multiple plaintext buffers for encryption (multi-buffer API)
 *
 * @parblock <br> &nbsp;
 * <b>Enqueues a batch of buffers for parallel SIMD processing. Each buffer
 * can have a different length. Call alcp_dequeue() to retrieve results.</b>
 * @endparblock
 *
 * @param[in] pCipherHandle Session handle for cipher operation
 * @param[in] pPlainText    Array of pointers to plaintext buffers
 * @param[in] pLengths      Array of per-buffer lengths in bytes
 * @param[in] numBuffers    Number of buffers in the batch (max 127)
 * @return Error code:
 *         - ALC_ERROR_NONE          Success
 *         - ALC_ERROR_INVALID_ARG   Invalid parameters
 *         - ALC_ERROR_BAD_STATE     Cipher not initialized
 */
ALCP_API_EXPORT alc_error_t
alcp_flush(const alc_cipher_handle_p pCipherHandle,
                   const Uint8**             pPlainText,
                   const Uint64*             pLengths,
                   Uint64                    numBuffers);

/**
 * @brief Dequeue processed ciphertext buffers (multi-buffer API)
 *
 * @parblock <br> &nbsp;
 * <b>Retrieves encrypted outputs for buffers submitted via alcp_flush().
 * Uses the Iterative MinLen algorithm for maximum SIMD parallelism.</b>
 * @endparblock
 *
 * @param[in]  pCipherHandle Session handle for cipher operation
 * @param[out] pCipherText   Array of pointers to ciphertext buffers (outputs)
 * @param[in]  numBuffers    Number of buffers to dequeue
 * @param[in]  pLengths      Array of per-buffer lengths in bytes
 * @return Error code:
 *         - ALC_ERROR_NONE          Success
 *         - ALC_ERROR_BAD_STATE     Invalid state
 *         - ALC_ERROR_NO_FALLBACK   AVX512 not available
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
