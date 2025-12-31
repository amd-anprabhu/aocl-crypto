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

#include "alcp/mac/hmac_mb.hh"
#include "alcp/digest.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha2_mb.hh"
#include "alcp/mac/hmac.hh"
#include "alcp/mac/hmac_mb.hh"
#include "alcp/utils/cpuid.hh"
#include <memory>

using alcp::utils::CpuId;

namespace alcp::mac {

template<typename DIGEST_TYPE>
alc_error_t
HmacMB::precompute_hash()
{
    alc_error_t       err       = ALC_ERROR_NONE;
    auto              digest_sb = static_cast<DIGEST_TYPE*>(m_digest_sb.get());
    Uint8             K0[cMaxBlockLengthBytes];
    alignas(64) Uint8 K0_xor_ipad[cMaxBlockLengthBytes]{};
    alignas(64) Uint8 K0_xor_opad[cMaxBlockLengthBytes]{};

    /* Setup K0 */
    if (m_key_len > m_block_size_bytes) {
        digest_sb->init();
        err = digest_sb->update(m_key, m_key_len);
        if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
            return err;
        }
        err = digest_sb->finalize(K0, m_digest_size_bytes);
        if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
            return err;
        }
        memset(K0 + m_digest_size_bytes,
               0,
               m_block_size_bytes - m_digest_size_bytes);
    } else {
        memcpy(K0, m_key, m_key_len);
        memset(K0 + m_key_len, 0, m_block_size_bytes - m_key_len);
    }

    /* K0 ^ pad */
    avx2::get_k0_xor_opad(m_block_size_bytes, K0, K0_xor_ipad, K0_xor_opad);

    // Pre-compute H(K0 ^ ipad)
    digest_sb->init();
    err = digest_sb->update(K0_xor_ipad, m_block_size_bytes);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }
    digest_sb->get_state(m_hash_after_ipad);

    // Pre-compute H(K0 ^ opad)
    digest_sb->init();
    err = digest_sb->update(K0_xor_opad, m_block_size_bytes);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }
    digest_sb->get_state(m_hash_after_opad);

    return err;
}

template<typename DIGEST_MB_TYPE>
alc_error_t
HmacMB::process_buffers(Uint8** ppDstBuf, const Uint64 numBuffers)
{
    alc_error_t err       = ALC_ERROR_NONE;
    auto        digest_mb = static_cast<DIGEST_MB_TYPE*>(m_digest_mb.get());

    // Use pre-computed hash state after H(K0 ^ ipad)
    digest_mb->set_state(m_hash_after_ipad);

    // Compute H((K0 ^ ipad) || message)
    err =
        digest_mb->flush(m_buffers, numBuffers, m_block_size_bytes + m_msg_len);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }
    digest_mb->set_blocks(((m_block_size_bytes + m_msg_len) >> 6) - 1);
    err = digest_mb->dequeue(ppDstBuf, numBuffers, m_digest_size_bytes);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }

    // Use pre-computed hash state after H(K0 ^ opad)
    digest_mb->set_state(m_hash_after_opad);

    // Compute H((K0 ^ opad) || inner_hash)
    err = digest_mb->flush(const_cast<const Uint8**>(ppDstBuf),
                           numBuffers,
                           m_block_size_bytes + m_digest_size_bytes);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }
    digest_mb->set_blocks(((m_block_size_bytes + m_digest_size_bytes) >> 6)
                          - 1);
    err = digest_mb->dequeue(ppDstBuf, numBuffers, m_digest_size_bytes);
    if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
        return err;
    }

    return ALC_ERROR_NONE;
}

alc_error_t
HmacMB::init(const Uint8* pKey, Uint64 keyLen, alc_digest_mode_t digest_mode)
{
    alc_error_t err = ALC_ERROR_NONE;

    static bool avx512_available =
        CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_VL)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW);

    m_key         = pKey;
    m_key_len     = keyLen;
    m_digest_mode = digest_mode;

    switch (digest_mode) {
        case ALC_SHA2_224:
        case ALC_MB_SHA2_224:
            m_block_size_bytes  = ALC_DIGEST_BLOCK_SIZE_SHA2_256 / 8;
            m_digest_size_bytes = ALC_DIGEST_LEN_224 / 8;
            break;
        case ALC_SHA2_256:
        case ALC_MB_SHA2_256:
            m_block_size_bytes  = ALC_DIGEST_BLOCK_SIZE_SHA2_256 / 8;
            m_digest_size_bytes = ALC_DIGEST_LEN_256 / 8;
            break;
        default:
            break;
    }

    if (avx512_available) {
        switch (digest_mode) {
            case ALC_SHA2_224:
            case ALC_MB_SHA2_224:
                m_digest_sb = std::make_unique<alcp::digest::Sha224>();
                m_digest_mb = std::make_unique<alcp::digest::Sha224MB>();
                err         = precompute_hash<alcp::digest::Sha224>();
                break;
            case ALC_SHA2_256:
            case ALC_MB_SHA2_256:
                m_digest_sb = std::make_unique<alcp::digest::Sha256>();
                m_digest_mb = std::make_unique<alcp::digest::Sha256MB>();
                err         = precompute_hash<alcp::digest::Sha256>();
                break;
            default:
                err = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
    }

    return err;
}

alc_error_t
HmacMB::flush(const Uint8** ppMsgBuf,
              const Uint64  numBuffers,
              const Uint64  msgLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* Ensure that numBuffers is valid */
    if (__builtin_expect((numBuffers == 0 || numBuffers > MAX_BUFFERS), 0)) {
        return ALC_ERROR_INVALID_ARG;
    }

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

alc_error_t
HmacMB::dequeue(Uint8** ppDstBuf, const Uint64 numBuffers)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* Validate numBuffers - m_num_buffers is already validated by flush() */
    if (__builtin_expect((numBuffers == 0) || (numBuffers > m_num_buffers),
                         0)) {
        return ALC_ERROR_INVALID_ARG;
    }

    /* Check if flush was called (m_buffers should be set) */
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

    static bool avx512_available =
        CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_VL)
        && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW);

    // Optimized AVX512 path with pre-computed hash states and reusable objects
    if (avx512_available && numBuffers >= 6) {
        switch (m_digest_mode) {
            case ALC_SHA2_224:
            case ALC_MB_SHA2_224:
                err = process_buffers<alcp::digest::Sha224MB>(ppDstBuf,
                                                              numBuffers);
                break;
            case ALC_SHA2_256:
            case ALC_MB_SHA2_256:
                err = process_buffers<alcp::digest::Sha256MB>(ppDstBuf,
                                                              numBuffers);
                break;
            default:
                err = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
    } else {
        // Use single buffer HMAC for each buffer
        std::unique_ptr<Hmac>            hmac_sb = std::make_unique<Hmac>();
        std::unique_ptr<digest::IDigest> digest{};

        if (m_digest_mode == ALC_MB_SHA2_224 || m_digest_mode == ALC_SHA2_224) {
            digest = std::make_unique<digest::Sha224>();
        } else if (m_digest_mode == ALC_MB_SHA2_256
                   || m_digest_mode == ALC_SHA2_256) {
            digest = std::make_unique<digest::Sha256>();
        } else {
            return ALC_ERROR_NOT_SUPPORTED;
        }

        for (Uint64 i = 0; i < numBuffers; i++) {
            err = hmac_sb->init(m_key, m_key_len, digest.get());
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }

            err = hmac_sb->update(m_buffers[i], m_msg_len);
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }

            err = hmac_sb->finalize(ppDstBuf[i], m_digest_size_bytes);
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }

            err = hmac_sb->reset();
            if (__builtin_expect(err != ALC_ERROR_NONE, 0)) {
                return err;
            }
        }
    }

    return err;
}

} // namespace alcp::mac
