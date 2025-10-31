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

#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha256_mb_avx512.hh"
#include "alcp/digest/sha2_mb.hh"
#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::digest {

template<alc_digest_len_t digest_len>
void
Sha2MB<digest_len>::init(void)
{
    /* These words were obtained by taking the first thirty-two bits of the
     * fractional parts of the square roots of the first eight prime numbers.
     */
    if constexpr (digest_len == ALC_DIGEST_LEN_256) {
        m_hash[0] = 0x6a09e667;
        m_hash[1] = 0xbb67ae85;
        m_hash[2] = 0x3c6ef372;
        m_hash[3] = 0xa54ff53a;
        m_hash[4] = 0x510e527f;
        m_hash[5] = 0x9b05688c;
        m_hash[6] = 0x1f83d9ab;
        m_hash[7] = 0x5be0cd19;
    } else {
        m_hash[0] = 0xc1059ed8;
        m_hash[1] = 0x367cd507;
        m_hash[2] = 0x3070dd17;
        m_hash[3] = 0xf70e5939;
        m_hash[4] = 0xffc00b31;
        m_hash[5] = 0x68581511;
        m_hash[6] = 0x64f98fa7;
        m_hash[7] = 0xbefa4fa4;
    }
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha2MB<digest_len>::flush(const Uint8** ppMsgBuf,
                          const Uint64  numBuffers,
                          const Uint64  msgLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* Ensure that message size is <2^64 Bits */
    if (__builtin_expect(msgLen >= (UINT64_MAX / 8), 0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (__builtin_expect(ppMsgBuf == nullptr, 0)) {
        return ALC_ERROR_INVALID_DATA;
    }
    for (Uint64 i = 0; i < numBuffers; i++) {
        if (__builtin_expect(ppMsgBuf[i] == nullptr, 0)) {
            return ALC_ERROR_INVALID_DATA;
        }
    }

    m_buffers     = ppMsgBuf;
    m_msg_len     = msgLen;
    m_num_buffers = numBuffers;
    return err;
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha2MB<digest_len>::dequeue(Uint8**      ppDstBuf,
                            const Uint64 numBuffers,
                            const Uint64 digestLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    static bool avx512_available =
        CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_VL)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW);

    // FIXME: Return an error only when numBuffers > m_num_buffers (set in
    // flush). Support for arbitrary numbers of buffers should be added.
    if (__builtin_expect((m_num_buffers == 0) || (numBuffers != m_num_buffers),
                         0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (__builtin_expect(m_buffers == nullptr, 0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (__builtin_expect(ppDstBuf == nullptr, 0)) {
        return ALC_ERROR_INVALID_DATA;
    }
    for (Uint64 i = 0; i < numBuffers; i++) {
        if (__builtin_expect(ppDstBuf[i] == nullptr, 0)) {
            return ALC_ERROR_INVALID_DATA;
        }
    }

    if (__builtin_expect((digest_len / 8) != digestLen, 0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (avx512_available && !(numBuffers & (16 - 1))) {
        // FIXME: Add support for arbitrary buffer counts (not just multiplesof
        // 16)
        err = zen4::Sha256Dequeue(
            m_buffers, m_hash, numBuffers, m_msg_len, ppDstBuf, digestLen);
    } else {
        std::unique_ptr<IDigest> sha2_sb{};
        if constexpr (digest_len == ALC_DIGEST_LEN_224) {
            sha2_sb = std::make_unique<Sha224>();
        } else if constexpr (digest_len == ALC_DIGEST_LEN_256) {
            sha2_sb = std::make_unique<Sha256>();
        } else {
            return ALC_ERROR_NOT_SUPPORTED;
        }

        for (Uint i = 0; i < numBuffers; i++) {
            sha2_sb->init();
            err = sha2_sb->update(m_buffers[i], m_msg_len);
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }
            err = sha2_sb->finalize(ppDstBuf[i], digestLen);
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }
        }
    }

    return err;
}

template class Sha2MB<ALC_DIGEST_LEN_224>;
template class Sha2MB<ALC_DIGEST_LEN_256>;

} // namespace alcp::digest