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
#ifndef _ALCP_ERROR_H_
#define _ALCP_ERROR_H_ 2

#include <assert.h>

#include "alcp/macros.h"
#include "alcp/types.h"

/**
 * @defgroup error Error API
 * @brief
 * Error APIs are used to report failures caused by other API calls.
 * @{
 *
 */

EXTERN_C_BEGIN

/**
 * @brief Provide the Error Code for the error occurred if any
 * @enum alc_error_generic
 */
typedef enum alc_error_generic
{
    /*
     * All is well
     */
    ALC_ERROR_NONE = 0UL, /**< No error, operation succeeded */

    /*
     * An Error,
     *    but cant be categorized correctly
     */
    ALC_ERROR_GENERIC, /**< Unclassified error */

    /*
     * Not Supported,
     *  Any of Feature, configuration,  Algorithm or  Keysize not supported
     */
    ALC_ERROR_NOT_SUPPORTED, /**< Feature, algorithm, or key size not supported */

    /*
     * Not Permitted,
     *  Operation supported but not permitted by this module/user etc.
     *  Kind of permission Denied situation, could be from the OS
     */
    ALC_ERROR_NOT_PERMITTED, /**< Operation not permitted */

    /*
     * Exists,
     *  Something that is already exists is requested to register or replace
     */
    ALC_ERROR_EXISTS, /**< Resource already exists */

    /*
     * Does not Exist,
     *   Requested configuration/algorithm/module/feature  does not exists
     */
    ALC_ERROR_NOT_EXISTS, /**< Resource does not exist */

    /*
     * Invalid argument
     */
    ALC_ERROR_INVALID_ARG, /**< Invalid argument provided */

    /*
     * Bad Internal State,
     *   Algorithm/context is in bad state due to internal Error
     */
    ALC_ERROR_BAD_STATE, /**< Handle or context in invalid state */

    /*
     * No Memory,
     *  Not enough free space available, Unable to allocate memory
     */
    ALC_ERROR_NO_MEMORY, /**< Memory allocation failed */

    /*
     * Data validation failure,
     *   Invalid pointer / Sent data is invalid
     */
    ALC_ERROR_INVALID_DATA, /**< Invalid or corrupt data */

    /*
     * Size Error,
     *   Data/Key size is invalid
     */
    ALC_ERROR_INVALID_SIZE, /**< Invalid size parameter */

    /*
     * Hardware Error,
     *   not in sane state, or failed during operation
     */
    ALC_ERROR_HARDWARE_FAILURE, /**< Hardware operation failed */

    /* There is not enough entropy for RNG
        retry needed with more entropy */
    ALC_ERROR_NO_ENTROPY, /**< Insufficient entropy available */

    /*
     *The Tweak key and Encryption is same
     *for AES-XTS mode
     */
    ALC_ERROR_DUPLICATE_KEY, /**< Duplicate key detected */

    /*
     * Mismatch is tag observed in Decrypt
     */
    ALC_ERROR_TAG_MISMATCH, /**< Authentication tag mismatch */

    /*
     * Algorithm is implemented for specific hardware only
     * and no fallback implementation is available
     */
    ALC_ERROR_NO_FALLBACK, /**< Algorithm requires specific hardware with no software fallback */

} alc_error_generic_t;

/**
 * @brief Used to Provide the Error Code for the error occurred if any
 * @typedef Uint64 alc_error_t
 */
typedef Uint64 alc_error_t;

/**
 * @brief        Returns true if an error has occurred
 * @parblock <br> &nbsp;
 * <b>This API should be called to check if error has occurred or not</b>
 * @endparblock
 * @note        This is the only way to check if an error has occurred in the
 *               previous call.
 *
 * @param [in] err    Actual Error
 * @return   Non-zero if an error has occurred, 0 otherwise
 */
ALCP_API_EXPORT Uint8
alcp_is_error(alc_error_t err);

EXTERN_C_END

#endif /* _ALCP_ERROR_H_ */

/**
 * @}
 */
