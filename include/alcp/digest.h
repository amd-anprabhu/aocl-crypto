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

#ifndef _ALCP_DIGEST_H
#define _ALCP_DIGEST_H 2

#include <stdint.h>

#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

/**
 * @defgroup digest Digest API
 * @brief
 * A digest is a one-way cryptographic function by which a message of any length
 * can be mapped into a fixed-length output. It can be used for verifying
 * integrity or passwords.
 * @{
 */

/**
 * @brief Stores info about digest length used for digest
 *
 * @typedef enum alc_digest_len_t
 */
typedef enum alc_digest_len
{
    ALC_DIGEST_LEN_128              = 128, /**< 128-bit digest length (MD5) */
    ALC_DIGEST_LEN_192              = 192, /**< 192-bit digest length */
    ALC_DIGEST_LEN_160              = 160, /**< 160-bit digest length (SHA-1) */
    ALC_DIGEST_LEN_288              = 288, /**< 288-bit digest length (MD5+SHA1) */
    ALC_DIGEST_LEN_224              = 224, /**< 224-bit digest length (SHA-224, SHA-512/224) */
    ALC_DIGEST_LEN_256              = 256, /**< 256-bit digest length (SHA-256, SHA-512/256) */
    ALC_DIGEST_LEN_384              = 384, /**< 384-bit digest length (SHA-384) */
    ALC_DIGEST_LEN_512              = 512, /**< 512-bit digest length (SHA-512) */
    ALC_DIGEST_LEN_CUSTOM_SHAKE_128 = 17,  /**< Custom length for SHAKE-128 */
    ALC_DIGEST_LEN_CUSTOM_SHAKE_256 = 18,  /**< Custom length for SHAKE-256 */
} alc_digest_len_t;

/**
 * @brief Stores info about block size used for digest
 *
 * @enum alc_digest_block_size_t
 */
typedef enum alc_digest_block_size
{
    ALC_DIGEST_BLOCK_SIZE_MD5       = 512, /**< MD5 block size (512 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA1      = 512, /**< SHA-1 block size (512 bits) */
    ALC_DIGEST_BLOCK_SIZE_MD5_SHA1  = ALC_DIGEST_BLOCK_SIZE_SHA1, /**< MD5+SHA1 block size (512 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA2_256  = 512, /**< SHA-2 256 block size (512 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA2_512  = 1024, /**< SHA-2 512 block size (1024 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA3_224  = 1152, /**< SHA-3 224 block size (1152 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA3_256  = 1088, /**< SHA-3 256 block size (1088 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA3_384  = 832, /**< SHA-3 384 block size (832 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHA3_512  = 576, /**< SHA-3 512 block size (576 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHAKE_128 = 1344, /**< SHAKE-128 block size (1344 bits) */
    ALC_DIGEST_BLOCK_SIZE_SHAKE_256 = 1088 /**< SHAKE-256 block size (1088 bits) */
} alc_digest_block_size_t;

/**
 * @brief Stores info about digest mode to be used
 *
 * @typedef enum alc_digest_mode_t
 */
typedef enum alc_digest_mode
{
    ALC_MD5, /**< MD5 message digest (128-bit) */
    ALC_SHA1, /**< SHA-1 message digest (160-bit) */
    ALC_MD5_SHA1, /**< Combined MD5+SHA1 digest (288-bit, used in TLS) */
    ALC_SHA2_224, /**< SHA-2 224-bit digest */
    ALC_SHA2_256, /**< SHA-2 256-bit digest */
    ALC_SHA2_384, /**< SHA-2 384-bit digest */
    ALC_SHA2_512, /**< SHA-2 512-bit digest */
    ALC_SHA2_512_224, /**< SHA-2 512/224-bit truncated digest */
    ALC_SHA2_512_256, /**< SHA-2 512/256-bit truncated digest */
    ALC_SHA3_224, /**< SHA-3 224-bit digest */
    ALC_SHA3_256, /**< SHA-3 256-bit digest */
    ALC_SHA3_384, /**< SHA-3 384-bit digest */
    ALC_SHA3_512, /**< SHA-3 512-bit digest */
    ALC_SHAKE_128, /**< SHAKE128 extendable-output function */
    ALC_SHAKE_256, /**< SHAKE256 extendable-output function */
    ALC_MB_SHA2_224, /**< Multi-buffer SHA-2 224-bit digest */
    ALC_MB_SHA2_256, /**< Multi-buffer SHA-2 256-bit digest */
} alc_digest_mode_t,
    *alc_digest_mode_p;

/**
 * @brief Store Context for the future operation of digest
 *
 */
typedef void                  alc_digest_context_t;
typedef alc_digest_context_t* alc_digest_context_p;

/**
 * @brief Handle for maintaining session.
 *
 * @param context pointer to the context of the digest
 *
 * @struct alc_digest_handle_t
 */
typedef struct _alc_digest_handle
{
    alc_digest_context_p context;
} alc_digest_handle_t, *alc_digest_handle_p, AlcDigestHandle, *AlcDigestHandleP;

/**
 * @brief  Returns the digest context size
 *
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_digest_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 *
 *
 * @return Size of context in bytes
 */
ALCP_API_EXPORT Uint64
alcp_digest_context_size(void);

/**
 * @brief        Request a handle for digest for a configuration
 *               as pointed by alc_digest_mode_t
 *
 * @param [in]   mode             Description of the requested digest session
 *
 * @param [out]  p_digest_handle  Library populated session handle for future
 * digest operations.
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_request(alc_digest_mode_t   mode,
                    alc_digest_handle_p p_digest_handle);

/**
 * @brief       Initializes the digest handle
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_request and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]  p_digest_handle  Library populated session handle
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_init(alc_digest_handle_p p_digest_handle);

/**
 * @brief       Computes digest for the buffer pointed by buf for size
 *              as mentioned by size in bytes.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_init and before @ref
 * alcp_digest_finalize</b>
 * @endparblock
 *
 * @note        repeated calls to this are allowed and the handle will
 *              contain the latest state; the digest is available after
 *              @ref alcp_digest_finalize.
 *
 * @param [in]  p_digest_handle  Handle created by @ref alcp_digest_request
 *
 * @param [in]  buf              Input buffer
 *
 * @param [in]  size             Input buffer size in bytes.
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_update(const alc_digest_handle_p p_digest_handle,
                   const Uint8*              buf,
                   Uint64                    size);

/**
 * @brief       Finalize the digest and copy the result into the output buffer.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_update and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]   p_digest_handle  Handle created by @ref alcp_digest_request
 *
 * @param [out]  buf              Destination buffer to which digest will be
 *                                copied
 *
 * @param [in]   size             Destination buffer size in bytes, should be
 *                                big enough to hold the digest
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_finalize(const alc_digest_handle_p p_digest_handle,
                     Uint8*                    buf,
                     Uint64                    size);

/**
 *
 * @brief       Performs any cleanup actions
 *
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 *
 * @note        Must be called to ensure memory allotted (if any) is cleaned.
 *
 * @param [in]  p_digest_handle  Handle created by @ref alcp_digest_request.
 *                               Once this function is called, the handle will
 *                               not be valid for future calls
 *
 * @return      None
 */
ALCP_API_EXPORT void
alcp_digest_finish(const alc_digest_handle_p p_digest_handle);

/**
 * @brief        Copies the context from source to destination
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_init and before @ref
 * alcp_digest_finish</b> on pSrcHandle
 * @endparblock
 *
 * @param [in]   pSrcHandle   source digest handle
 * @param [out]  pDestHandle  destination digest handle
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_context_copy(const alc_digest_handle_p pSrcHandle,
                         const alc_digest_handle_p pDestHandle);

/**
 * @brief        Valid only for SHAKE algorithm for squeezing the digest out.
 *               It can be called multiple times. It should not be called with
 * @ref alcp_digest_finalize
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_digest_update and before @ref
 * alcp_digest_finish</b>
 * @endparblock
 *
 * @param [in]   pDigestHandle  Handle created by @ref alcp_digest_request
 * @param [out]  pBuff          Destination Buffer for digest out
 * @param [in]   size           size of data to be squeezed out
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_shake_squeeze(const alc_digest_handle_p pDigestHandle,
                          Uint8*                    pBuff,
                          Uint64                    size);

/**
 * @brief       Stage multiple input buffers for multi-buffer digest computation.
 *
 * @parblock <br> &nbsp;
 * <b>This API stages multiple message buffers for parallel digest computation.
 * It must be called after @ref alcp_digest_init and before
 * @ref alcp_digest_dequeue.</b>
 *
 * This function does not perform digest computation itself -- it only
 * records the buffer addresses and parameters. The actual computation
 * is performed by @ref alcp_digest_dequeue.
 *
 * All input buffers must be the same size (msgLen bytes). For variable-length
 * buffers, use separate single-buffer digest calls instead.
 *
 * Supported modes: ALC_MB_SHA2_224, ALC_MB_SHA2_256.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @pre      @ref alcp_digest_request must be called with an ALC_MB_SHA2_*
 *           mode, followed by @ref alcp_digest_init.
 *
 * @param[in] pDigestHandle  Handle created by @ref alcp_digest_request
 * @param[in] ppMsgBuf       Array of pointers to input message buffers
 * @param[in] numBuffers     Number of input buffers
 * @param[in] msgLen         Length of each input message buffer in bytes;
 *                           all buffers must be exactly this size
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_flush(const alc_digest_handle_p pDigestHandle,
                  const Uint8**             ppMsgBuf,
                  const Uint64              numBuffers,
                  const Uint64              msgLen);

/**
 * @brief       Compute digests for buffers staged via alcp_digest_flush.
 *
 * @parblock <br> &nbsp;
 * <b>Performs parallel digest computation for all buffers previously staged
 * by @ref alcp_digest_flush and writes each result to the corresponding
 * entry in ppDstBuf.</b>
 *
 * Each output buffer must be pre-allocated with at least digestLen bytes.
 * The digest size depends on the algorithm:
 *   - ALC_MB_SHA2_224: 28 bytes
 *   - ALC_MB_SHA2_256: 32 bytes
 *
 * This API must be called after @ref alcp_digest_flush and before
 * @ref alcp_digest_finish.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @pre      @ref alcp_digest_flush must be called before this API with
 *           the same number of buffers.
 *
 * @param[in]  pDigestHandle  Handle created by @ref alcp_digest_request
 * @param[out] ppDstBuf       Array of pointers to output digest buffers;
 *                            each must have space for digestLen bytes
 * @param[in]  numBuffers     Number of output buffers (must match the count
 *                            provided to @ref alcp_digest_flush)
 * @param[in]  digestLen      Length of each digest in bytes (28 for SHA-224,
 *                            32 for SHA-256)
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_digest_dequeue(const alc_digest_handle_p pDigestHandle,
                    Uint8**                   ppDstBuf,
                    const Uint64              numBuffers,
                    const Uint64              digestLen);
EXTERN_C_END

#endif /* _ALCP_DIGEST_H */
       /**
        * @}
        */
