/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/compare.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

#define DEBUG_PROV_GCM_INIT 0

namespace alcp::cipher {


// init implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Validate and set key -- let KeyManager reject null/bad length
    if (keyLen != 0 || pKey != nullptr) {
        err = m_keyManager.setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_stateManager.onKeySet();
        m_gcm_ctx.m_update_counter = 0; // reset counter
    }

    // Validate and set IV -- let IvManager reject null/bad length
    if (pIv != nullptr) {
        err = m_ivManager.setIv(pIv, ivLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_stateManager.onIvSet();
        m_gcm_ctx.m_update_counter = 0; // reset counter
    }

    // In init call, we generate HashSubKey, partial tag data.
    if (m_stateManager.isReady()) {
        m_gcm_ctx.m_gHash_128       = _mm_setzero_si128();
        m_gcm_ctx.m_hash_subKey_128 = _mm_setzero_si128();
        m_gcm_ctx.m_dataLen         = 0;
        err = aesni::InitGcm(m_keyManager.getCipherKeyData().m_enc_key,
                             m_keyManager.getRounds(),
                             m_ivManager.getIv(),
                             m_ivManager.getIvLen(),
                             m_gcm_ctx.m_hash_subKey_128,
                             m_gcm_ctx.m_tag_128,
                             m_gcm_ctx.m_counter_128,
                             m_gcm_ctx.m_reverse_mask_128);
    }

    #ifdef AES_MULTI_UPDATE
    // Initialize streaming fields
    m_partialBuffer.clear();
    // Initialize AAD buffering fields
    m_gcm_ctx.m_aad_buffer.clear();
    m_gcm_ctx.m_aad_processed = false;
    #endif

    return err;
}

// Helper function to process buffered AAD data
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
inline alc_error_t
GcmT<keyLenBits, arch>::processBufferedAad()
{
    alc_error_t err = ALC_ERROR_NONE;

    // If AAD has already been processed or there's no buffered AAD, nothing to do
    if (m_gcm_ctx.m_aad_processed || m_gcm_ctx.m_aad_buffer.empty()) {
        m_gcm_ctx.m_aad_processed = true;
        return ALC_ERROR_NONE;
    }

#if DEBUG_PROV_GCM_INIT
    printf("processBufferedAad: processing %zu bytes of buffered AAD\n", m_gcm_ctx.m_aad_buffer.size());
#endif

    // Process all buffered AAD data at once
    err = aesni::processAdditionalDataGcm(m_gcm_ctx.m_aad_buffer.data(),
                                          m_gcm_ctx.m_aad_buffer.size(),
                                          m_gcm_ctx.m_gHash_128,
                                          m_gcm_ctx.m_hash_subKey_128,
                                          m_gcm_ctx.m_reverse_mask_128);

    // Mark AAD as processed
    m_gcm_ctx.m_aad_processed = true;

    return err;
}

// Internal tag matching is disable for ipp compat support
#define INTERNAL_TAG_MATCH 1

// setAad implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::setAad(const Uint8* pInput, Uint64 aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* iv is not initialized means wrong order, we
     * will return its a bad state to call setAad*/
    if (!m_ivManager.isIvSet()) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    
    if (pInput == nullptr && aadLen > 0) {
        return ALC_ERROR_INVALID_ARG;
    }

    // Skip processing if no AAD data provided
    if (pInput == nullptr || aadLen == 0) {
        return ALC_ERROR_NONE;
    }

#ifdef AES_MULTI_UPDATE
    // Check if AAD has already been processed (encrypt/decrypt called)
    if (m_gcm_ctx.m_aad_processed) {
        return ALC_ERROR_BAD_STATE; // Cannot add more AAD after processing starts
    }
    
    // Append the new AAD data to the vector - much simpler!
    m_gcm_ctx.m_aad_buffer.insert(m_gcm_ctx.m_aad_buffer.end(), pInput, pInput + aadLen);
    
    // Update total AAD length
    m_gcm_ctx.m_additionalDataLen = m_gcm_ctx.m_aad_buffer.size();
    
#if DEBUG_PROV_GCM_INIT
    printf("setAad: buffered %ld bytes, total AAD len %ld \n", aadLen, m_gcm_ctx.m_additionalDataLen);
#endif
#else
    m_gcm_ctx.m_additionalDataLen = aadLen;
    err = aesni::processAdditionalDataGcm(pInput,
                                          m_gcm_ctx.m_additionalDataLen,
                                          m_gcm_ctx.m_gHash_128,
                                          m_gcm_ctx.m_hash_subKey_128,
                                          m_gcm_ctx.m_reverse_mask_128);
#endif 

    return err;
}

// setTagLength implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::setTagLength(Uint64 tagLength)
{
    // GCM tag length must be between 4 and 16 bytes (32-128 bits)
    // Per NIST SP 800-38D, valid tag lengths are 128, 120, 112, 104, 96 bits
    // For maximum security, 96-128 bits (12-16 bytes) is recommended
    if (tagLength < 4 || tagLength > 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    m_gcm_ctx.m_tagLength = tagLength;
    return ALC_ERROR_NONE;
}

// decrypt implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::decrypt(const Uint8* pInput,
                               Uint8*       pOutput,
                               Uint64       len,
                               Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_gcm_ctx.m_isEncrypt = false;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    if (!m_stateManager.isReady()) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
#ifdef AES_MULTI_UPDATE
    // Process any buffered AAD data before decrypting
    err = processBufferedAad();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
#endif 

    m_gcm_ctx.m_dataLen += len;

#if DEBUG_PROV_GCM_INIT
    printf("decrypt len %ld \n", len);
#endif

#ifndef AES_MULTI_UPDATE
    // Multi-update disabled: use direct block-based decryption without streaming logic
    // This bypasses all the partial buffering and streaming code below
    m_gcm_ctx.m_update_counter = 1; // Start from block 1
    err = decryptBlock(pInput, pOutput, len);
    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
#endif // !AES_MULTI_UPDATE

    Uint64 input_offset = 0;
    Uint64 output_offset = 0;
    
    // Check if we have partial data from previous call
    if (m_partialBuffer.size() > 0) {
        // This is the second call - combine buffered data with new input
        Uint64 bytes_needed = 16 - m_partialBuffer.size();
        Uint64 bytes_to_take = (len >= bytes_needed) ? bytes_needed : len;
        
        // Create a combined 16-byte buffer
        Uint8 combined_block[16];
        memcpy(combined_block, m_partialBuffer.data(), m_partialBuffer.size());
        memcpy(combined_block + m_partialBuffer.size(), pInput, bytes_to_take);
        
        // If we have a complete 16-byte block, process it
        if (m_partialBuffer.size() + bytes_to_take >= 16) {
            Uint8 temp_output[16];
            
            // Set counter to 1 (this is the FIRST complete block in the stream)
            m_gcm_ctx.m_update_counter = 1;
            
            // decrypt the combined 16-byte block
            err = decryptBlock(combined_block, temp_output, 16);
            if (err != ALC_ERROR_NONE) return err;
            
            // Return only the NEW bytes (skip the buffered part)
            memcpy(pOutput + output_offset, temp_output + m_partialBuffer.size(), bytes_to_take);
            output_offset += bytes_to_take;
            input_offset += bytes_to_take;
            
            // Clear partial buffer
            m_partialBuffer.clear();
        }
    }
    
    // Process remaining complete 16-byte blocks
    Uint64 remaining_len = len - input_offset;
    if (remaining_len >= 16) {
        Uint64 complete_blocks = remaining_len / 16;
        Uint64 complete_bytes = complete_blocks * 16;
        
        // Increment counter for the remaining blocks
        m_gcm_ctx.m_update_counter++;
        
        err = decryptBlock(pInput + input_offset, pOutput + output_offset, complete_bytes);
        if (err != ALC_ERROR_NONE) return err;
        
        input_offset += complete_bytes;
        output_offset += complete_bytes;
        remaining_len = len - input_offset;
    }
    
    // Handle final partial block (if any)
    if (remaining_len > 0 && remaining_len < 16) {
        
        Uint8 temp_output[16];
        // TEMPORARY increment counter just for this decryption
        Uint64 saved_counter = m_gcm_ctx.m_update_counter;
        m_gcm_ctx.m_update_counter++;
        // Buffer the original input for next call
        Uint32 temp_offset = m_partialBuffer.size();
        m_partialBuffer.append(pInput + input_offset, remaining_len);

        // Save only the critical state fields that decryptBlock modifies
        // This is much faster than copying the entire context (which includes std::vector)
        __m128i saved_gHash = m_gcm_ctx.m_gHash_128;
        __m128i saved_counter_128 = m_gcm_ctx.m_counter_128;

        err = decryptBlock(m_partialBuffer.data(), temp_output, 16);

        // Restore only the modified state
        m_gcm_ctx.m_gHash_128 = saved_gHash;
        m_gcm_ctx.m_counter_128 = saved_counter_128;
        m_gcm_ctx.m_update_counter = saved_counter;

        if (err != ALC_ERROR_NONE) return err;

        // Return the correct bytes to user
        memcpy(pOutput + output_offset, temp_output + temp_offset, remaining_len);
    }

    return ALC_ERROR_NONE;
}

// Helper function to call the appropriate decryption backend
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::decryptBlock(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;

    if constexpr (arch == CpuArchLevel::eZen4) {
        if constexpr (keyLenBits == CipherKeyLen::eKey128Bit) {
            err = vaes512::decryptGcm128(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey192Bit) {
            err = vaes512::decryptGcm192(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey256Bit) {
            err = vaes512::decryptGcm256(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuArchLevel::eZen3) {
        if constexpr (keyLenBits == CipherKeyLen::eKey128Bit) {
            err = vaes::decryptGcm128(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey192Bit) {
            err = vaes::decryptGcm192(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey256Bit) {
            err = vaes::decryptGcm256(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::CryptGcm(pInput,
                              pOutput,
                              len,
                              m_keyManager.getCipherKeyData().m_enc_key,
                              m_keyManager.getRounds(),
                              &m_gcm_ctx,
                              false);
        return err;
    }

    return ALC_ERROR_NOT_SUPPORTED;
}

// encrypt implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::encrypt(const Uint8* pInput,
                               Uint8*       pOutput,
                               Uint64       len,
                               Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_gcm_ctx.m_isEncrypt = true;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    if (!m_stateManager.isReady()) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }

#ifdef AES_MULTI_UPDATE
    // Process any buffered AAD data before encrypting
    err = processBufferedAad();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
#endif
    m_gcm_ctx.m_dataLen += len;

#if DEBUG_PROV_GCM_INIT
    printf("encrypt len %ld \n", len);
#endif

#ifndef AES_MULTI_UPDATE
    // Multi-update disabled: use direct block-based encryption without streaming logic
    // This bypasses all the partial buffering and streaming code below
    m_gcm_ctx.m_update_counter = 1; // Start from block 1
    err = encryptBlock(pInput, pOutput, len);
    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
#endif // !AES_MULTI_UPDATE

    Uint64 input_offset = 0;
    Uint64 output_offset = 0;
    
    // Check if we have partial data from previous call
    if (m_partialBuffer.size() > 0) {
        // This is the second call - combine buffered data with new input
        Uint64 bytes_needed = 16 - m_partialBuffer.size();
        Uint64 bytes_to_take = (len >= bytes_needed) ? bytes_needed : len;
        
        // Create a combined 16-byte buffer
        Uint8 combined_block[16];
        memcpy(combined_block, m_partialBuffer.data(), m_partialBuffer.size());
        memcpy(combined_block + m_partialBuffer.size(), pInput, bytes_to_take);
        
        // If we have a complete 16-byte block, process it
        if (m_partialBuffer.size() + bytes_to_take >= 16) {
            Uint8 temp_output[16];
            
            // this is the FIRST complete block in the stream
            m_gcm_ctx.m_update_counter = 1;
            
            // Encrypt the combined 16-byte block
            err = encryptBlock(combined_block, temp_output, 16);
            if (err != ALC_ERROR_NONE) return err;
            
            // Return only the NEW bytes (skip the buffered part)
            memcpy(pOutput + output_offset, temp_output + m_partialBuffer.size(), bytes_to_take);
            output_offset += bytes_to_take;
            input_offset += bytes_to_take;
            
            // Clear partial buffer
            m_partialBuffer.clear();
        }
    }
    
    // Process remaining complete 16-byte blocks
    Uint64 remaining_len = len - input_offset;
    if (remaining_len >= 16) {
        Uint64 complete_blocks = remaining_len / 16;
        Uint64 complete_bytes = complete_blocks * 16;
        
        // Increment counter for the remaining blocks
        m_gcm_ctx.m_update_counter++;
        
        err = encryptBlock(pInput + input_offset, pOutput + output_offset, complete_bytes);
        if (err != ALC_ERROR_NONE) return err;
        
        input_offset += complete_bytes;
        output_offset += complete_bytes;
        remaining_len = len - input_offset;
    }
    
    // Handle final partial block (if any)
    if (remaining_len > 0 && remaining_len < 16) {
        
        Uint8 temp_output[16];
        // TEMPORARY increment counter just for this encryption
        Uint64 saved_counter = m_gcm_ctx.m_update_counter;
        m_gcm_ctx.m_update_counter++;
        // Buffer the original input for next call
        Uint32 temp_offset = m_partialBuffer.size();
        m_partialBuffer.append(pInput + input_offset, remaining_len);

        // Save only the critical state fields that encryptBlock modifies
        // This is much faster than copying the entire context (which includes std::vector)
        __m128i saved_gHash = m_gcm_ctx.m_gHash_128;
        __m128i saved_counter_128 = m_gcm_ctx.m_counter_128;

        err = encryptBlock(m_partialBuffer.data(), temp_output, 16);

        // Restore only the modified state
        m_gcm_ctx.m_gHash_128 = saved_gHash;
        m_gcm_ctx.m_counter_128 = saved_counter_128;
        m_gcm_ctx.m_update_counter = saved_counter;

        if (err != ALC_ERROR_NONE) return err;

        // Return the correct bytes to user
        memcpy(pOutput + output_offset, temp_output + temp_offset, remaining_len);
    }
    
    return ALC_ERROR_NONE;
}


// Helper function to call the appropriate encryption backend
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::encryptBlock(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;

    if constexpr (arch == CpuArchLevel::eZen4) {
        if constexpr (keyLenBits == CipherKeyLen::eKey128Bit) {
            err = vaes512::encryptGcm128(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey192Bit) {
            err = vaes512::encryptGcm192(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey256Bit) {
            err = vaes512::encryptGcm256(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_keyManager.getCipherKeyData().m_enc_key,
                                         m_keyManager.getRounds(),
                                         &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuArchLevel::eZen3) {
        if constexpr (keyLenBits == CipherKeyLen::eKey128Bit) {
            err = vaes::encryptGcm128(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey192Bit) {
            err = vaes::encryptGcm192(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits == CipherKeyLen::eKey256Bit) {
            err = vaes::encryptGcm256(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_keyManager.getCipherKeyData().m_enc_key,
                                      m_keyManager.getRounds(),
                                      &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::CryptGcm(pInput,
                              pOutput,
                              len,
                              m_keyManager.getCipherKeyData().m_enc_key,
                              m_keyManager.getRounds(),
                              &m_gcm_ctx,
                              true);
        return err;
    }

    return ALC_ERROR_NOT_SUPPORTED;
}

// getTag implementation
template<CipherKeyLen keyLenBits, CpuArchLevel arch>
alc_error_t
GcmT<keyLenBits, arch>::getTag(Uint8* ptag, Uint64 tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (ptag == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (!m_ivManager.isIvSet()) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    } else if (tagLen == 0 || tagLen > m_gcm_ctx.m_tagLength
               || (tagLen < 4)
               || (tagLen > 4 && tagLen < 8)
               || (tagLen > 8 && tagLen < 12)) {
        // Per NIST SP 800-38D, valid tag lengths are: 4, 8, 12, 13, 14, 15, 16
        return ALC_ERROR_INVALID_SIZE;
    }
#if DEBUG_PROV_GCM_INIT
    printf("GcmT::getTag taglen %ld \n\n", tagLen);
#endif
#ifdef AES_MULTI_UPDATE
    // If no data has been processed yet, ensure buffered AAD is processed
    if (m_gcm_ctx.m_dataLen == 0) {
        err = processBufferedAad();
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }
#endif
#ifdef AES_MULTI_UPDATE
    // Process any remaining buffered data using appropriate block function
    if (m_partialBuffer.size() > 0) {
        // Call the appropriate block method based on encryption/decryption mode
        // This ensures proper template dispatch and all buffering logic
        Uint8 temp_output[16];  // We just need the GCM state update
        // FIXME: Separate out the tag calculation and the crypt logic within the kernels, then we can remove calling encrypt and decrypt fully.
        
        if (m_gcm_ctx.m_isEncrypt) {
            // Encryption mode - call encryptBlock
            err = encryptBlock(m_partialBuffer.data(), temp_output, m_partialBuffer.size());
        } else {
            // Decryption mode - call decryptBlock
            err = decryptBlock(m_partialBuffer.data(), temp_output, m_partialBuffer.size());
        }
        
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        
        // Clear the partial buffer
        m_partialBuffer.clear();
    }
#endif

#if INTERNAL_TAG_MATCH
    // During decrypt, tag generated should be compared with
    // input Tag.
    Uint8 tagInput[ALCP_GCM_TAG_MAX_SIZE];
    if (!m_gcm_ctx.m_isEncrypt) {
        // create a copy of input
        memcpy(tagInput, ptag, tagLen);
    }
#endif

    err = aesni::GetTagGcm(tagLen,
                           m_gcm_ctx.m_dataLen,
                           m_gcm_ctx.m_additionalDataLen,
                           m_gcm_ctx.m_gHash_128,
                           m_gcm_ctx.m_tag_128,
                           m_gcm_ctx.m_hash_subKey_128,
                           m_gcm_ctx.m_reverse_mask_128,
                           ptag);

#if INTERNAL_TAG_MATCH
    // During decrypt, tag generated should be compared with
    // input Tag.
    if (!m_gcm_ctx.m_isEncrypt) {
        if (utils::CompareConstTime(ptag, tagInput, tagLen) == 0) {
            // clear data
            memset(ptag, 0, tagLen);
            memset(tagInput, 0, tagLen);
            return ALC_ERROR_TAG_MISMATCH;
        }
    }
#endif

    return err;
}

// Explicit template instantiations for GcmT
template class GcmT<CipherKeyLen::eKey128Bit, CpuArchLevel::eZen4>;
template class GcmT<CipherKeyLen::eKey192Bit, CpuArchLevel::eZen4>;
template class GcmT<CipherKeyLen::eKey256Bit, CpuArchLevel::eZen4>;

template class GcmT<CipherKeyLen::eKey128Bit, CpuArchLevel::eZen3>;
template class GcmT<CipherKeyLen::eKey192Bit, CpuArchLevel::eZen3>;
template class GcmT<CipherKeyLen::eKey256Bit, CpuArchLevel::eZen3>;

template class GcmT<CipherKeyLen::eKey128Bit, CpuArchLevel::eZen>;
template class GcmT<CipherKeyLen::eKey192Bit, CpuArchLevel::eZen>;
template class GcmT<CipherKeyLen::eKey256Bit, CpuArchLevel::eZen>;

} // namespace alcp::cipher
