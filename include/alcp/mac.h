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

#ifndef _ALCP_MAC_H_
#define _ALCP_MAC_H_ 2

#include "alcp/cipher.h"
#include "alcp/digest.h"
#include "alcp/key.h"

EXTERN_C_BEGIN

/**
 * @defgroup mac MAC API
 * @brief
 * A Message Authentication Code (MAC) is a cryptographic technique used to
 * verify the authenticity and integrity of a message, ensuring that it has not
 * been tampered with during transmission.
 * @{
 */

/**
 * @brief Stores info regarding the type of MAC used
 *
 * @enum alc_mac_type
 *
 */
typedef enum alc_mac_type
{
    ALC_MAC_HMAC, /**< HMAC (Hash-based Message Authentication Code) */
    ALC_MAC_CMAC, /**< CMAC (Cipher-based Message Authentication Code) */
    ALC_MAC_POLY1305, /**< Poly1305 one-time authenticator */
    ALC_MB_MAC_HMAC, /**< Multi-buffer HMAC for parallel processing */
} alc_mac_type_t;

/**
 * @brief Stores details of HMAC
 *
 * @param  digest_mode Digest algorithm used for HMAC
 *
 * @struct alc_hmac_info_t
 *
 */
typedef struct _alc_hmac_info
{
    // Info about the hash function to be used in HMAC
    alc_digest_mode_t digest_mode;
    // Other specific info about HMAC

} alc_hmac_info_t, *alc_hmac_info_p;

/**
 * @brief Stores details of CMAC
 *
 * @param  cmac_cipher Store info of cipher used for CMAC
 *
 * @struct alc_cmac_info_t
 *
 */
// NOTE: Mode is currently used for validation, only AES-based CMAC is
// supported.
typedef struct _alc_cmac_info
{
    alc_cipher_mode_t ci_mode; /*! Cipher mode (ALC_AES_MODE_CBC) */
    // Other specific info about CMAC
} alc_cmac_info_t, *alc_cmac_info_p;

/**
 * @brief Stores details for algo info for mac
 *
 * @param hmac Stores the hmac info in case MAC to be used is HMAC
 * @param cmac Stores the cmac info in case MAC to be used is CMAC
 *
 * @union alc_mac_info_t
 */
typedef union _mac_info
{
    alc_hmac_info_t hmac;
    alc_cmac_info_t cmac;
} alc_mac_info_t;

typedef void               alc_mac_context_t;
typedef alc_mac_context_t* alc_mac_context_p;

/**
 *
 * @brief  Handle for maintaining session.
 *
 * @param ch_context pointer to the context of the mac
 *
 * @struct alc_mac_handle_t
 *
 */
typedef struct alc_mac_handle
{
    alc_mac_context_p ch_context;
} alc_mac_handle_t, *alc_mac_handle_p, AlcMacHandle;

/**
 * @brief       Gets the size of the MAC context to be allocated before calling
 *              @ref alcp_mac_request
 *
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_mac_request to identify the
 * memory to be allocated for the context.</b>
 * @endparblock
 *
 * @return      Size of context in bytes
 */
ALCP_API_EXPORT Uint64
alcp_mac_context_size(void);

/**
 * @brief    Request a MAC handle for the specified MAC type
 * @parblock <br> &nbsp;
 * <b>This API must be called before making any other API call</b>
 * @endparblock
 * @note     Error needs to be checked after each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [out]  pMacHandle  Library populated session handle for future
 * mac operations.
 * @param  [in]  macType     MAC type to use
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_request(alc_mac_handle_p pMacHandle, alc_mac_type_t macType);

/**
 * @brief    Set key and initialize MAC session
 * @parblock <br> &nbsp;
 * <b>This API must be called only after @ref alcp_mac_request</b>
 * @endparblock
 * @note     Error needs to be checked after each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pMacHandle Session handle for MAC operations
 * @param [in]   key  Pointer to key for MAC operations
 * @param [in]   size Size of key in bytes
 * @param [in]   info MAC info populated based on the selected MAC type

 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_init(alc_mac_handle_p pMacHandle,
              const Uint8*     key,
              Uint64           size,
              alc_mac_info_t*  info);

/**
 * @brief    Update MAC with a chunk of data to be authenticated
 * @parblock <br> &nbsp;
 * <b>This API is called to update data to be authenticated. So should be called
 * after @ref alcp_mac_request  and before the end of session call, @ref
 * alcp_mac_finish</b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pMacHandle  Session handle for MAC operation
 * @param [in]   buff       The chunk of the message to be updated
 * @param [in]   size       Length of input buffer in bytes
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_update(alc_mac_handle_p pMacHandle, const Uint8* buff, Uint64 size);

/**
 * @brief               Finalize the MAC and copy the result
 * @parblock <br> &nbsp;
 * <b>This API is called to finalize mac so should be called after @ref
 * alcp_mac_init and before @ref alcp_mac_finish</b>
 * @endparblock
 * @note
 *                      - Error needs to be checked for each call,
 *                        valid only if @ref alcp_is_error (ret) is false.
 *
 * @param [in]   pMacHandle  Session handle for MAC operation
 * @param [out]   buff        Output buffer for the MAC
 * @param [in]   size        MAC size in bytes
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_finalize(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size);

/**
 *
 * @brief               Free resources that were allocated by @ref
 *                      alcp_mac_request
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note                alcp_mac_request() must be called before to allocate
 *                      the handle.
 *
 * @param [in]   pMacHandle Session handle used for the MAC operations
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_finish(alc_mac_handle_p pMacHandle);

/**
 *
 * @brief               Reset the data given during @ref alcp_mac_update
 * or @ref alcp_mac_finalize
 * @parblock <br> &nbsp;
 * <b>This API is called to reset data so should be called after @ref
 * alcp_mac_request  and before @ref alcp_mac_finish</b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 * @param [in]   pMacHandle Session handle for MAC operation
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_reset(alc_mac_handle_p pMacHandle);

/**
 * @brief        Copy the context from source to destination
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called only after @ref alcp_mac_init and before @ref
 * alcp_mac_finish  on pSrcHandle</b>
 * @endparblock
 *
 * @param [in]   pSrcHandle   source mac handle
 * @param [out]  pDestHandle  destination mac handle
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_context_copy(const alc_mac_handle_p pSrcHandle,
                      const alc_mac_handle_p pDestHandle);

/**
 * @brief       Stage multiple message buffers for multi-buffer MAC computation.
 *
 * @parblock <br> &nbsp;
 * <b>This API stages multiple message buffers for parallel HMAC computation.
 * It must be called after @ref alcp_mac_init and before
 * @ref alcp_mac_dequeue.</b>
 *
 * All input buffers must be the same size (msgLen bytes). This function
 * records the buffer addresses for later processing by
 * @ref alcp_mac_dequeue.
 *
 * Supported mode: ALC_MB_MAC_HMAC only.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @pre      @ref alcp_mac_request must be called with ALC_MB_MAC_HMAC,
 *           followed by @ref alcp_mac_init with the key and HMAC info.
 *
 * @param[in] pMacHandle   Session handle for MAC operation
 * @param[in] ppMsgBuf     Array of pointers to input message buffers
 * @param[in] numBuffers   Number of input buffers
 * @param[in] msgLen       Length of each message buffer in bytes;
 *                         all buffers must be exactly this size
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_flush(alc_mac_handle_p pMacHandle,
               const Uint8**    ppMsgBuf,
               Uint64           numBuffers,
               Uint64           msgLen);

/**
 * @brief       Compute MACs for buffers staged via alcp_mac_flush.
 *
 * @parblock <br> &nbsp;
 * <b>Performs parallel HMAC computation for all buffers previously staged
 * by @ref alcp_mac_flush and writes each MAC to the corresponding entry
 * in ppDstBuf.</b>
 *
 * Each output buffer must be pre-allocated with sufficient space for the
 * MAC output. The MAC size is determined by the digest algorithm configured
 * during @ref alcp_mac_init (e.g., 32 bytes for HMAC-SHA256).
 *
 * This API must be called after @ref alcp_mac_flush and before
 * @ref alcp_mac_finish.
 * @endparblock
 *
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false
 *
 * @pre      @ref alcp_mac_flush must be called before this API.
 * @pre      @ref alcp_mac_init must be called with ALC_MB_MAC_HMAC before
 *           using this API, and numBuffers must be greater than 0.
 *
 * @param[in]  pMacHandle   Session handle for MAC operation
 * @param[out] ppDstBuf     Array of pointers to pre-allocated output buffers
 *                          for computed MACs
 * @param[in]  numBuffers   Number of output buffers (must match the count
 *                          provided to @ref alcp_mac_flush)
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_mac_dequeue(alc_mac_handle_p pMacHandle,
                 Uint8**          ppDstBuf,
                 Uint64           numBuffers);

EXTERN_C_END

#endif /* _ALCP_MAC_H_ */
       /**
        * @}
        */
