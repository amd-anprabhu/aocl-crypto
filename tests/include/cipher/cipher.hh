/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#pragma once
#include "file.hh"
#include "utils.hh"
#include <alcp/alcp.h>
#include <cstring>
#include <iostream>
#include <vector>

namespace alcp::testing {
using alcp::testing::utils::isPathExist;
using alcp::testing::utils::parseHexStrToBin;

/* to check cipher type is AES */
bool
isNonAESCipherType(alc_cipher_mode_t mode);

/* to check if cipher mode is AEAD */
bool
CheckCipherIsAEAD(alc_cipher_mode_t mode);

/* to get cipher mode as a string */
std::string
GetModeSTR(alc_cipher_mode_t mode);

// alcp_data_cipher_ex_t
struct alcp_dc_ex_t
{
     Uint8* m_in;
    Uint64       m_inl;
    Uint8*       m_out;
    Uint64       m_outl;
    const Uint8* m_iv;
    Uint64       m_ivl;
    Uint8*       m_tkey;  // tweak key
    Uint64       m_tkeyl; // tweak key len
    Uint64       m_block_size;

    const Uint8* m_ad;
    Uint64       m_adl;
    Uint8*       m_tag; // Probably const but openssl expects non const
    Uint64       m_tagl;
    bool         m_isTagValid;

    Uint8* m_tagBuff; // Place to store tag buffer
    // Initialize everything to 0
    alcp_dc_ex_t()
    {
        m_in         = {};
        m_inl        = {};
        m_out        = {};
        m_outl       = {};
        m_iv         = {};
        m_ivl        = {};
        m_tkey       = {};
        m_tkeyl      = {};
        m_block_size = {};
        m_ad         = {};
        m_adl        = {};
        m_tag        = {};
        m_tagl       = {};
        m_tagBuff    = {};
        m_isTagValid = true;
    }
};

typedef enum
{
    SMALL_DEC = 0,
    SMALL_ENC,
    BIG_DEC,
    BIG_ENC,
} record_t;

/**
 * @brief CipherBase is a wrapper for which library to use
 *
 */
class CipherBase
{
  public:
    virtual bool init(const Uint8* iv,
                      const Uint32 iv_len,
                      const Uint8* key,
                      const Uint32 key_len,
                      const Uint8* tkey,
                      const Uint64 block_size)                = 0;
    virtual bool init(const Uint8* key, const Uint32 key_len) = 0;
    virtual bool encrypt(alcp_dc_ex_t& data)                  = 0;
    virtual bool decrypt(alcp_dc_ex_t& data)                  = 0;
    virtual bool reset()                                      = 0;
    virtual bool context_copy()                               = 0;

    /**
     * @brief Multi-buffer flush API
     * Enqueues plaintext buffers with per-buffer lengths for processing
     */
    virtual bool flush(const Uint8**  pPlainText,
                       const Uint64*  pLengths,
                       Uint64         numBuffers)                    = 0;

    /**
     * @brief Multi-buffer dequeue API
     * Retrieves encrypted ciphertext buffers
     */
    virtual bool dequeue(Uint8**       pCipherText,
                         Uint64        numBuffers,
                         const Uint64* pLengths)                     = 0;
    virtual bool multibufferInit(const Uint8*  pKey,
                                 Uint64        keyLen,
                                 const Uint8** pIv,
                                 Uint64        ivLen,
                                 Uint64        numBuffers)           = 0;

    virtual ~CipherBase() = default;
};

class CipherAeadBase : public CipherBase
{
  public:
    virtual ~CipherAeadBase() = default;
    static bool isAead(const alc_cipher_mode_t& mode);
};

class CipherTesting
{
  private:
    CipherBase* cb = nullptr;

  public:
    CipherTesting() {}
    CipherTesting(CipherBase* impl);

    /**
     * @brief Encrypts data and puts in data.out, expects data.out to already
     * have valid memory pointer with appropriate size
     *
     * @param data - Everything that should go in or out of the cipher except
     * the key
     * @param key - Key used to encrypt, should be std::vector
     * @return true
     * @return false
     */
    bool testingEncrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key);

    /**
     * @brief Tests the encryption operation with context copying capability.
     *
     * @param data - Structure containing input/output buffers, IVs, and other
     *              cipher-specific parameters required for encryption
     * @param key - Key used for encryption, provided as a vector of bytes
     * @return true - If encryption with context copying succeeds
     * @return false - If encryption or context copying fails
     */
    bool testingEncryptCtxCopy(alcp_dc_ex_t&            data,
                               const std::vector<Uint8> key);

    /**
     * @brief Tests the decryption operation with context copying capability.
     *
     * @param data - Structure containing input/output buffers, IVs, tags, and
     * other cipher-specific parameters required for decryption
     * @param key - Key used for decryption, provided as a vector of bytes
     * @return true - If decryption with context copying succeeds
     * @return false - If decryption or context copying fails
     */
    bool testingDecryptCtxCopy(alcp_dc_ex_t&            data,
                               const std::vector<Uint8> key);

    /**
     * @brief Decrypts data and puts in data.out, expects data.out to already
     * have valid memory point with appropriate size
     *
     * @param data - Everything that should go in or out of the cipher except
     * the key
     * @param key - Key used to decrypt, should be std::vector
     * @return true
     * @return false
     */
    bool testingDecrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key);

    /**
     * @brief Set CipherBase pimpl
     *
     * @param impl - Object of class extended from CipherBase
     */
    void setcb(CipherBase* impl);

    /**
     * @brief Initializes multi-buffer cipher operation.
     *
     * @param key - Pointer to the key used for encryption/decryption
     * @param keySize - Size of the key in bits
     * @param ivPointers - Array of pointers to IVs for each buffer
     * @param ivSize - Size of each IV in bytes
     * @param numBuffers - Number of buffers for multi-buffer operation
     * @return true - If initialization succeeds
     * @return false - If initialization fails
     */
    bool multibufferInit(const Uint8*  key,
                         size_t        keySize,
                         const Uint8** ivPointers,
                         size_t        ivSize,
                         int           numBuffers);

    /**
     * @brief Enqueue input buffers for encryption/decryption.
     *
     * @param inputPointers - Array of pointers to input buffers
     * @param lengths - Array of per-buffer lengths in bytes
     * @param numBuffers - Number of buffers
     * @return true - If flush succeeds
     * @return false - If flush fails
     */
    bool flush(const Uint8** inputPointers, const Uint64* lengths, int numBuffers);

    /**
     * @brief Retrieve processed output buffers.
     *
     * @param outputPointers - Array of pointers to output buffers
     * @param numBuffers - Number of buffers
     * @param lengths - Array of per-buffer lengths in bytes
     * @return true - If dequeue succeeds
     * @return false - If dequeue fails
     */
    bool dequeue(Uint8** outputPointers, int numBuffers, const Uint64* lengths);
};

} // namespace alcp::testing
