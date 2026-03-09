/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "rng_base.hh"

#ifdef USE_IPP
#include "digest/ipp_digest.hh"
#endif

#ifdef USE_OSSL
#include "digest/openssl_digest.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

std::vector<Int64> digest_block_sizes = {
    16, 64, 256, 1024, 8192, 16384, 32768
};

std::vector<Int64> digest_buffer_sizes = { 8, 16, 32 };

void inline Digest_Bench(benchmark::State& state,
                         alc_digest_mode_t mode,
                         Uint64            block_size)
{
    RngBase            rb;
    std::vector<Uint8> msg(block_size);
    AlcpDigestBase     adb(mode);
    DigestBase*        db = &adb;
    alcp_digest_data_t data;
#ifdef USE_IPP
    IPPDigestBase idb(mode);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(mode);
    if (useossl) {
        db = &odb;
    }
#endif

    data.m_digest_len = GetDigestLen(mode) / 8;

    Uint8 digest[data.m_digest_len];
    memset(digest, 0, data.m_digest_len * sizeof(Uint8));
    /* generate random bytes */
    msg = rb.genRandomBytes(block_size);

    data.m_msg     = &(msg[0]);
    data.m_digest  = digest;
    data.m_msg_len = block_size;

    for (auto _ : state) {
        if (!db->digest_update(data)) {
            state.SkipWithError("Error in running digest benchmark:");
        }
        if (!db->digest_finalize(data)) {
            state.SkipWithError("Error in running digest benchmark:");
        }
        db->reset();
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

void inline Digest_Multibuffer_Bench(benchmark::State& state,
                                     alc_digest_mode_t mode,
                                     Uint64            block_size,
                                     Uint64            buffers)
{
    assert(mode == ALC_MB_SHA2_224 || mode == ALC_MB_SHA2_256);

    alcp_digest_data_t data;
    data.m_msg_len    = block_size;
    data.m_digest_len = GetDigestLen(mode) / 8;

    std::vector<std::vector<Uint8>> vec_msg(
        buffers, std::vector<Uint8>(block_size, 0x01));
    std::vector<std::vector<Uint8>> vec_digest(
        buffers, std::vector<Uint8>(data.m_digest_len, 0x0));

    std::vector<const Uint8*> msg_buffer_pointers(buffers);
    std::vector<Uint8*>       digest_buffer_pointers(buffers);
    for (Uint64 i = 0; i < buffers; ++i) {
        msg_buffer_pointers[i]    = vec_msg[i].data();
        digest_buffer_pointers[i] = vec_digest[i].data();
    }
    data.m_p_msg    = msg_buffer_pointers.data();
    data.m_p_digest = digest_buffer_pointers.data();
    data.m_buffers  = buffers;

    AlcpDigestBase adb(mode);
    for (auto _ : state) {
        if (!adb.digest_flush(data)) {
            state.SkipWithError("Error in running digest_flush benchmark");
        }
        if (!adb.digest_dequeue(data)) {
            state.SkipWithError("Error in running digest_dequeue benchmark");
        }
    }

    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size * buffers, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    state.counters["NumBuffers"]       = buffers;
}

static void
BENCH_SHA2_MULTIBUFFER_224(benchmark::State& state)
{
    Digest_Multibuffer_Bench(
        state, ALC_MB_SHA2_224, state.range(0), state.range(1));
}

static void
BENCH_SHA2_MULTIBUFFER_256(benchmark::State& state)
{
    Digest_Multibuffer_Bench(
        state, ALC_MB_SHA2_256, state.range(0), state.range(1));
}

/* add all your new benchmarks here */
/* SHA2 benchmarks */
static void
BENCH_SHA2_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_224, state.range(0));
}
static void
BENCH_SHA2_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_256, state.range(0));
}
static void
BENCH_SHA2_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_384, state.range(0));
}
static void
BENCH_SHA2_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512, state.range(0));
}
/* SHA 512 224 and 256 len*/
static void
BENCH_SHA2_512_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512_224, state.range(0));
}
static void
BENCH_SHA2_512_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512_256, state.range(0));
}

/* SHA3 benchmarks */
static void
BENCH_SHA3_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_224, state.range(0));
}
static void
BENCH_SHA3_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_256, state.range(0));
}
static void
BENCH_SHA3_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_384, state.range(0));
}
static void
BENCH_SHA3_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_512, state.range(0));
}

/* SHAKE */
static void
BENCH_SHAKE_128(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHAKE_128, state.range(0));
}
static void
BENCH_SHAKE_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHAKE_256, state.range(0));
}

/* add benchmarks */
int
AddBenchmarks()
{
    /* check if custom block size is provided by user */
    if (block_size != 0) {
        std::cerr << "Custom block size selected:" << block_size << std::endl;
        digest_block_sizes.resize(1);
        digest_block_sizes[0] = block_size;
    }
    BENCHMARK(BENCH_SHA2_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_256)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_384)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_256)->ArgsProduct({ digest_block_sizes });

    /* SHA3 is not supported for IPP */
    if (!useipp) {
        BENCHMARK(BENCH_SHA3_224)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_256)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_384)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_512)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_128)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_256)->ArgsProduct({ digest_block_sizes });
    }

    if (!useipp && !useossl) {
        BENCHMARK(BENCH_SHA2_MULTIBUFFER_224)
            ->ArgsProduct({ digest_block_sizes, digest_buffer_sizes });
        BENCHMARK(BENCH_SHA2_MULTIBUFFER_256)
            ->ArgsProduct({ digest_block_sizes, digest_buffer_sizes });
    }
    return 0;
}