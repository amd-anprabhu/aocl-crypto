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

#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/utils/compare.hh"
#include <string.h>

namespace alcp::cipher {

// Helper methods
template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::setKeys(const Uint8 key1[], Uint64 length)
{

    if (key1 == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    // Block all unknown keysizes
    switch (length) {
        case 128:
        case 192:
        case 256:
            break;
        default:
            return ALC_ERROR_INVALID_SIZE;
    }

    alc_error_t err = m_cmac.init(m_key1, length / 8);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err       = ALC_ERROR_NONE;
    Uint64      keyLength = keyLen;

    // Store synthetic IV (for decrypt, the IV is the tag from encrypt)
    if (pIv != nullptr && ivLen != 0) {
        if (ivLen != 16) {
            return ALC_ERROR_INVALID_SIZE;
        }
        utils::CopyBytes(m_syntheticIv, pIv, 16);
    }

    // Set keys - SIV uses double-key: first half for S2V, second half for CTR
    if (pKey != nullptr && keyLen != 0) {
        err = utils::SecureCopy<Uint8>(m_key1, 32, pKey, keyLength / 8);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = utils::SecureCopy<Uint8>(
            m_key2, 32, pKey + (keyLength / 8), keyLength / 8);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = setKeys(m_key1, keyLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::cmacWrapper(const Uint8 data[], Uint64 size, Uint8 mac[], Uint64 macSize)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (data == nullptr || mac == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    err = m_cmac.update(data, size);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.finalize(mac, macSize);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.reset();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::cmacWrapperMultiData(const Uint8 data1[],
                                            Uint64      size1,
                                            const Uint8 data2[],
                                            Uint64      size2,
                                            Uint8       mac[],
                                            Uint64      macSize)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (data1 == nullptr || data2 == nullptr || mac == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    err = m_cmac.update(data1, size1);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.update(data2, size2);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.finalize(mac, macSize);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.reset();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::addAdditionalInput(const Uint8* pAad, Uint64 aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pAad == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    // Extend size of additonalDataProcessed Vector in case of overflow
    if ((m_additionalDataProcessedSize + 1)
        == m_additionalDataProcessed.size()) {
        m_additionalDataProcessed.resize(m_additionalDataProcessed.size() + 10);
    }

    // Allocate memory for additonal data processed vector
    m_additionalDataProcessed.at(m_additionalDataProcessedSize) =
        std::vector<Uint8>(SIZE_CMAC);

    // Do cmac for additional data and set it to the proceed data.
    err = cmacWrapper(
        pAad,
        aadLen,
        &((m_additionalDataProcessed.at(m_additionalDataProcessedSize)).at(0)),
        SIZE_CMAC);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Increment the size of Data Processed if no errors
    m_additionalDataProcessedSize += 1;
    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    alc_error_t err = ALC_ERROR_NONE;

    if (plainText == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    std::vector<Uint8> zero = std::vector<Uint8>(SIZE_CMAC, 0);

    // Do a cmac of Zero Vector, first additonal data.
    err = cmacWrapper(&(zero.at(0)), zero.size(), m_cmacTemp, SIZE_CMAC);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    avx2::processAad(
        m_cmacTemp, m_additionalDataProcessed, m_additionalDataProcessedSize);

    // If the size of plaintext is lower there is special case
    if (size >= SIZE_CMAC) {

        // Take out last block
        if (CpuId::cpuIsZen3()) {
            zen3::xor_a_b((plainText + size - SIZE_CMAC),
                          m_cmacTemp,
                          m_cmacTemp,
                          SIZE_CMAC);
        } else {
            xor_a_b((plainText + size - SIZE_CMAC),
                    m_cmacTemp,
                    m_cmacTemp,
                    SIZE_CMAC);
        }

        err = cmacWrapperMultiData(plainText,
                                   (size - SIZE_CMAC),
                                   m_cmacTemp,
                                   SIZE_CMAC,
                                   m_cmacTemp,
                                   SIZE_CMAC);
    } else {
        Uint8 temp_bytes[16] = {};
        // Padding Hack
        temp_bytes[0] = 0x80;
        // Special case size lower for plain text need to do double and padding
        avx2::dbl(&(m_cmacTemp[0]));

        xor_a_b(plainText, m_cmacTemp, m_cmacTemp, size);
        // Padding
        xor_a_b(
            temp_bytes, m_cmacTemp + size, m_cmacTemp + size, (SIZE_CMAC)-size);

        err = cmacWrapper(m_cmacTemp, SIZE_CMAC, m_cmacTemp, SIZE_CMAC);
    }

    return err;
}

// Auth methods
template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::getTag(Uint8 out[], Uint64 len)
{
    if (out == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (len != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    utils::CopyBytes(out, &m_cmacTemp[0], SIZE_CMAC);
    memset(&m_cmacTemp[0], 0, 16);
    m_additionalDataProcessedSize = 0;
    return ALC_ERROR_NONE;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::setAad(const Uint8* pAad, Uint64 aadLen)
{
    if (pAad == nullptr) {
        printf("\n nullptr ");
        return ALC_ERROR_INVALID_ARG;
    }
    alc_error_t err = addAdditionalInput(pAad, aadLen);
    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::setTagLength(Uint64 tagLength)
{
    // AES-SIV always uses a 128-bit (16-byte) synthetic IV as the tag
    // This is fundamental to the SIV construction and cannot be changed
    if (tagLength != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    return ALC_ERROR_NONE;
}

// Encrypt/Decrypt methods
template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::encrypt(const Uint8* pPlainText,
                               Uint8*       pCipherText,
                               Uint64       len,
                               Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    err = s2v(pPlainText, len); // Nullptr check inside this function
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }
    m_ctrCipher.init(m_key2, (static_cast<Uint32>(keyLenBits)), q, 16);
    Uint64 ctr_outlen = 0;
    err = m_ctrCipher.encrypt(pPlainText, pCipherText, len + m_padLen, &ctr_outlen);
    if (alcp_is_error(err)) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    // AES-CMAC-SIV is an AEAD: output length equals input length on success
    if (outlen != nullptr) {
        *outlen = len;
    }

    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::decrypt(const Uint8* pCipherText,
                               Uint8*       pPlainText,
                               Uint64       len,
                               Uint64*      outlen)

{
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask to synthetic IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_syntheticIv[i] & q[i];
    }

    m_ctrCipher.init(m_key2, (static_cast<Uint32>(keyLenBits)), q, 16);
    Uint64 ctr_outlen = 0;
    err = m_ctrCipher.decrypt(pCipherText, pPlainText, len, &ctr_outlen);
    if (alcp_is_error(err)) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    // Create the tag from generated plain text
    err = s2v(pPlainText, len);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Verify tag, which just got generated (compare with stored synthetic IV)
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_syntheticIv, SIZE_CMAC) == 0) {
        return ALC_ERROR_TAG_MISMATCH;
    }

    // AES-CMAC-SIV is an AEAD: output length equals input length on success
    if (outlen != nullptr) {
        *outlen = len;
    }

    return err;
}

// Explicit template instantiations
template class SivT<CipherKeyLen::eKey128Bit, CpuCipherFeatures::eVaes512>;
template class SivT<CipherKeyLen::eKey192Bit, CpuCipherFeatures::eVaes512>;
template class SivT<CipherKeyLen::eKey256Bit, CpuCipherFeatures::eVaes512>;

template class SivT<CipherKeyLen::eKey128Bit, CpuCipherFeatures::eVaes256>;
template class SivT<CipherKeyLen::eKey192Bit, CpuCipherFeatures::eVaes256>;
template class SivT<CipherKeyLen::eKey256Bit, CpuCipherFeatures::eVaes256>;

template class SivT<CipherKeyLen::eKey128Bit, CpuCipherFeatures::eAesni>;
template class SivT<CipherKeyLen::eKey192Bit, CpuCipherFeatures::eAesni>;
template class SivT<CipherKeyLen::eKey256Bit, CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher
