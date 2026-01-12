/*
 * Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
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

#include "benchmarks_cipher.hh"
#include "cipher/cipher.hh"
#include "gbench_base.hh"
#include <iostream>
#include <memory>
#include <vector>
#include <random>
#include <algorithm>

#define MAX_BLOCK_SIZE 32768
#define MAX_KEY_SIZE   256

/* Variable-Length Multibuffer Benchmark with Absolute Byte Variance */
int
CipherMultibufferVarLenAbsoluteBench(benchmark::State& state,
                                     Uint64            avgBlockSize,
                                     encrypt_t         enc,
                                     alc_cipher_mode_t alcpMode,
                                     size_t            keylen,
                                     Uint64            numBuffers,
                                     Uint64            absoluteVariance)
{
    std::mt19937 gen(42); // Fixed seed for reproducibility

    // Create variable lengths with absolute byte variance
    std::vector<Uint64> bufferLengths(numBuffers);

    // Ensure variance stays within bounds and aligns to 16 bytes
    Uint64 absVar = (absoluteVariance / 16) * 16;  // Align to 16 bytes
    Uint64 minLen = avgBlockSize - absVar;
    Uint64 maxLen = avgBlockSize + absVar;

    // Ensure minLen is valid
    minLen = (minLen / 16) * 16;
    maxLen = (maxLen / 16) * 16;
    if (minLen < 16) minLen = 16;

    std::uniform_int_distribution<Uint64> dist(minLen / 16, maxLen / 16);

    Uint64 totalBytes = 0;
    for (Uint64 i = 0; i < numBuffers; ++i) {
        bufferLengths[i] = dist(gen) * 16;
        totalBytes += bufferLengths[i];
    }

    // Allocate buffers with exact sizes (no padding needed)
    std::vector<std::vector<Uint8>> vec_in(numBuffers);
    std::vector<std::vector<Uint8>> vec_out(numBuffers);

    for (Uint64 i = 0; i < numBuffers; ++i) {
        vec_in[i].resize(bufferLengths[i], 0x01);
        vec_out[i].resize(bufferLengths[i], 0x21);
    }

    alignas(16)
        Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    std::vector<std::vector<Uint8>> ivs(numBuffers,
                                        std::vector<Uint8>(iv, iv + 16));
    std::vector<const Uint8*>       iv_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        std::next_permutation(ivs[i].begin(), ivs[i].end());
        iv_pointers[i] = ivs[i].data();
    }

    alignas(16) Uint8          key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8          tkey[MAX_KEY_SIZE / 8] = {};
    alcp::testing::CipherBase* p_cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 16, &key[0], keylen, tkey, avgBlockSize);

    p_cb = &acb;

    std::vector<const Uint8*> input_buffer_pointers(numBuffers);
    std::vector<Uint8*>       output_buffer_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        input_buffer_pointers[i]  = vec_in[i].data();
        output_buffer_pointers[i] = vec_out[i].data();
    }

    // Initialize the cipher context
    if (!p_cb->multibufferInit(
            nullptr, 0, iv_pointers.data(), 16, numBuffers)) {
        state.SkipWithError("BENCH_INIT_FAILURE");
        return -1;
    }

    for (auto _ : state) {
        // Use variable-length flush
        if (!p_cb->flush(input_buffer_pointers.data(),
                        bufferLengths.data(),
                        numBuffers)) {
            state.SkipWithError("BENCH_FLUSH_FAILURE");
        }

        // Use variable-length dequeue
        if (!p_cb->dequeue(output_buffer_pointers.data(),
                          numBuffers,
                          bufferLengths.data())) {
            state.SkipWithError("BENCH_DEQUEUE_FAILURE");
        }
    }

    state.counters["Speed(Bytes/s)"] =
        benchmark::Counter(state.iterations() * totalBytes,
                           benchmark::Counter::kIsRate);
    state.counters["AvgBlockSize(Bytes)"] = avgBlockSize;
    state.counters["NumBuffers"]          = numBuffers;
    state.counters["TotalBytes"]          = totalBytes;
    state.counters["MinLen"]              = minLen;
    state.counters["MaxLen"]              = maxLen;
    state.counters["AbsVariance(Bytes)"]  = absoluteVariance;

    return 0;
}

/* Variable-Length Multibuffer Benchmark with Percentage Variance */
int
CipherMultibufferVarLenBench(benchmark::State& state,
                             Uint64            avgBlockSize,
                             encrypt_t         enc,
                             alc_cipher_mode_t alcpMode,
                             size_t            keylen,
                             Uint64            numBuffers,
                             float             lengthVariance = 0.3f)
{
    std::mt19937 gen(42); // Fixed seed for reproducibility

    // Create variable lengths around avgBlockSize with given variance
    std::vector<Uint64> bufferLengths(numBuffers);
    Uint64 minLen = static_cast<Uint64>(avgBlockSize * (1.0f - lengthVariance));
    Uint64 maxLen = static_cast<Uint64>(avgBlockSize * (1.0f + lengthVariance));

    // Ensure alignment to 16 bytes for AES
    minLen = (minLen / 16) * 16;
    maxLen = (maxLen / 16) * 16;
    if (minLen < 16) minLen = 16;

    std::uniform_int_distribution<Uint64> dist(minLen / 16, maxLen / 16);

    // MinLen approach: No padding required! Allocate exact buffer sizes
    Uint64 totalBytes = 0;

    for (Uint64 i = 0; i < numBuffers; ++i) {
        bufferLengths[i] = dist(gen) * 16; // Align to 16 bytes (AES block size)
        totalBytes += bufferLengths[i];
    }

    // Allocate buffers with exact sizes (no padding needed)
    std::vector<std::vector<Uint8>> vec_in(numBuffers);
    std::vector<std::vector<Uint8>> vec_out(numBuffers);

    for (Uint64 i = 0; i < numBuffers; ++i) {
        vec_in[i].resize(bufferLengths[i], 0x01);
        vec_out[i].resize(bufferLengths[i], 0x21);
    }

    alignas(16)
        Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    std::vector<std::vector<Uint8>> ivs(numBuffers,
                                        std::vector<Uint8>(iv, iv + 16));
    std::vector<const Uint8*>       iv_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        std::next_permutation(ivs[i].begin(), ivs[i].end());
        iv_pointers[i] = ivs[i].data();
    }

    alignas(16) Uint8          key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8          tkey[MAX_KEY_SIZE / 8] = {};
    alcp::testing::CipherBase* p_cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 16, &key[0], keylen, tkey, avgBlockSize);

    p_cb = &acb;

    std::vector<const Uint8*> input_buffer_pointers(numBuffers);
    std::vector<Uint8*>       output_buffer_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        input_buffer_pointers[i]  = vec_in[i].data();
        output_buffer_pointers[i] = vec_out[i].data();
    }

    // Initialize the cipher context
    if (!p_cb->multibufferInit(
            nullptr, 0, iv_pointers.data(), 16, numBuffers)) {
        state.SkipWithError("BENCH_INIT_FAILURE");
        return -1;
    }

    for (auto _ : state) {
        // Use variable-length flush
        if (!p_cb->flush(input_buffer_pointers.data(),
                        bufferLengths.data(),
                        numBuffers)) {
            state.SkipWithError("BENCH_FLUSH_FAILURE");
        }

        // Use variable-length dequeue
        if (!p_cb->dequeue(output_buffer_pointers.data(),
                          numBuffers,
                          bufferLengths.data())) {
            state.SkipWithError("BENCH_DEQUEUE_FAILURE");
        }
    }

    state.counters["Speed(Bytes/s)"] =
        benchmark::Counter(state.iterations() * totalBytes,
                           benchmark::Counter::kIsRate);
    state.counters["AvgBlockSize(Bytes)"] = avgBlockSize;
    state.counters["NumBuffers"]          = numBuffers;
    state.counters["TotalBytes"]          = totalBytes;
    state.counters["MinLen"]              = minLen;
    state.counters["MaxLen"]              = maxLen;
    state.counters["Variance"]            = lengthVariance;

    return 0;
}

/* Fixed-Length Multibuffer Benchmark (for comparison) */
int
CipherMultibufferFixedLenBench(benchmark::State& state,
                               Uint64            blockSize,
                               encrypt_t         enc,
                               alc_cipher_mode_t alcpMode,
                               size_t            keylen,
                               Uint64            numBuffers)
{
    // Dynamic allocation better for larger sizes
    std::vector<std::vector<Uint8>> vec_in(numBuffers,
                                           std::vector<Uint8>(blockSize, 0x01));
    std::vector<std::vector<Uint8>> vec_out(
        numBuffers, std::vector<Uint8>(blockSize, 0x21));
    alignas(16)
        Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    std::vector<std::vector<Uint8>> ivs(numBuffers,
                                        std::vector<Uint8>(iv, iv + 16));
    std::vector<const Uint8*>       iv_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        std::next_permutation(ivs[i].begin(), ivs[i].end());
        iv_pointers[i] = ivs[i].data();
    }

    alignas(16) Uint8          key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8          tkey[MAX_KEY_SIZE / 8] = {};
    alcp::testing::CipherBase* p_cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 16, &key[0], keylen, tkey, blockSize);

    p_cb = &acb;

    std::vector<const Uint8*> input_buffer_pointers(numBuffers);
    std::vector<Uint8*>       output_buffer_pointers(numBuffers);
    std::vector<Uint64>       bufferLengths(numBuffers, blockSize);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        input_buffer_pointers[i]  = vec_in[i].data();
        output_buffer_pointers[i] = vec_out[i].data();
    }

    // Initialize the cipher context
    if (!p_cb->multibufferInit(
            nullptr, 0, iv_pointers.data(), 16, numBuffers)) {
        state.SkipWithError("BENCH_INIT_FAILURE");
        return -1;
    }

    for (auto _ : state) {
        if (!p_cb->flush(input_buffer_pointers.data(), bufferLengths.data(), numBuffers)) {
            state.SkipWithError("BENCH_FLUSH_FAILURE");
        }

        if (!p_cb->dequeue(
                output_buffer_pointers.data(), numBuffers, bufferLengths.data())) {
            state.SkipWithError("BENCH_DEQUEUE_FAILURE");
        }
    }

    state.counters["Speed(Bytes/s)"] =
        benchmark::Counter(state.iterations() * blockSize * numBuffers,
                           benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;
    state.counters["NumBuffers"]       = numBuffers;

    return 0;
}

/* Benchmark functions for CBC mode with variable lengths */
static void
BENCH_AES_VARLEN_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128,
        state.range(1), state.range(2) / 100.0f));
}

static void
BENCH_AES_VARLEN_MULTIBUFFER_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256,
        state.range(1), state.range(2) / 100.0f));
}

/* Benchmark functions for CFB mode with variable lengths */
static void
BENCH_AES_VARLEN_MULTIBUFFER_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128,
        state.range(1), state.range(2) / 100.0f));
}

static void
BENCH_AES_VARLEN_MULTIBUFFER_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256,
        state.range(1), state.range(2) / 100.0f));
}

/* Benchmark functions for CBC mode with ABSOLUTE byte variance */
static void
BENCH_AES_VARLEN_ABS_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenAbsoluteBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128,
        state.range(1), state.range(2)));
}

static void
BENCH_AES_VARLEN_ABS_MULTIBUFFER_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenAbsoluteBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256,
        state.range(1), state.range(2)));
}

/* Benchmark functions for CFB mode with ABSOLUTE byte variance */
static void
BENCH_AES_VARLEN_ABS_MULTIBUFFER_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenAbsoluteBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128,
        state.range(1), state.range(2)));
}

static void
BENCH_AES_VARLEN_ABS_MULTIBUFFER_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenAbsoluteBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256,
        state.range(1), state.range(2)));
}

/* Multi-tier variable-length benchmark (stress test with distinct length tiers) */
int
CipherMultibufferMultiTierBench(benchmark::State& state,
                                 encrypt_t         enc,
                                 alc_cipher_mode_t alcpMode,
                                 size_t            keylen,
                                 Uint64            numBuffers)
{
    // Create multi-tier distribution similar to real-world packet scenarios
    // Example: Many small packets (64-128), some medium (256-512), few large (1200-1500)
    std::vector<Uint64> bufferLengths(numBuffers);

    // Distribution: ~30% small, ~40% medium, ~30% large
    Uint64 smallCount = numBuffers * 30 / 100;
    Uint64 mediumCount = numBuffers * 40 / 100;
    Uint64 largeCount = numBuffers - smallCount - mediumCount;

    std::vector<Uint64> smallSizes  = { 64, 128 };
    std::vector<Uint64> mediumSizes = { 256, 300, 400, 512 };
    std::vector<Uint64> largeSizes  = { 800, 900, 1200, 1500 };

    std::mt19937 gen(42); // Fixed seed for reproducibility

    Uint64 totalBytes = 0;
    Uint64 idx = 0;

    // Assign small buffer lengths
    std::uniform_int_distribution<size_t> smallDist(0, smallSizes.size() - 1);
    for (Uint64 i = 0; i < smallCount; ++i, ++idx) {
        bufferLengths[idx] = smallSizes[smallDist(gen)];
        totalBytes += bufferLengths[idx];
    }

    // Assign medium buffer lengths
    std::uniform_int_distribution<size_t> mediumDist(0, mediumSizes.size() - 1);
    for (Uint64 i = 0; i < mediumCount; ++i, ++idx) {
        bufferLengths[idx] = mediumSizes[mediumDist(gen)];
        totalBytes += bufferLengths[idx];
    }

    // Assign large buffer lengths
    std::uniform_int_distribution<size_t> largeDist(0, largeSizes.size() - 1);
    for (Uint64 i = 0; i < largeCount; ++i, ++idx) {
        bufferLengths[idx] = largeSizes[largeDist(gen)];
        totalBytes += bufferLengths[idx];
    }

    // Shuffle to simulate realistic interleaved packet arrival
    std::shuffle(bufferLengths.begin(), bufferLengths.end(), gen);

    // Allocate buffers with exact sizes
    std::vector<std::vector<Uint8>> vec_in(numBuffers);
    std::vector<std::vector<Uint8>> vec_out(numBuffers);

    for (Uint64 i = 0; i < numBuffers; ++i) {
        vec_in[i].resize(bufferLengths[i], 0x01);
        vec_out[i].resize(bufferLengths[i], 0x21);
    }

    alignas(16)
        Uint8 iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    std::vector<std::vector<Uint8>> ivs(numBuffers,
                                        std::vector<Uint8>(iv, iv + 16));
    std::vector<const Uint8*>       iv_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        std::next_permutation(ivs[i].begin(), ivs[i].end());
        iv_pointers[i] = ivs[i].data();
    }

    alignas(16) Uint8          key[MAX_KEY_SIZE / 8]  = {};
    alignas(16) Uint8          tkey[MAX_KEY_SIZE / 8] = {};
    alcp::testing::CipherBase* p_cb;

    alcp::testing::AlcpCipherBase acb = alcp::testing::AlcpCipherBase(
        alcpMode, iv, 16, &key[0], keylen, tkey, 1024);

    p_cb = &acb;

    std::vector<const Uint8*> input_buffer_pointers(numBuffers);
    std::vector<Uint8*>       output_buffer_pointers(numBuffers);
    for (Uint64 i = 0; i < numBuffers; ++i) {
        input_buffer_pointers[i]  = vec_in[i].data();
        output_buffer_pointers[i] = vec_out[i].data();
    }

    // Initialize the cipher context
    if (!p_cb->multibufferInit(
            nullptr, 0, iv_pointers.data(), 16, numBuffers)) {
        state.SkipWithError("BENCH_INIT_FAILURE");
        return -1;
    }

    for (auto _ : state) {
        // Use variable-length flush
        if (!p_cb->flush(input_buffer_pointers.data(),
                        bufferLengths.data(),
                        numBuffers)) {
            state.SkipWithError("BENCH_FLUSH_FAILURE");
        }

        // Use variable-length dequeue
        if (!p_cb->dequeue(output_buffer_pointers.data(),
                          numBuffers,
                          bufferLengths.data())) {
            state.SkipWithError("BENCH_DEQUEUE_FAILURE");
        }
    }

    // Calculate actual min/max/avg for reporting
    Uint64 minLen = *std::min_element(bufferLengths.begin(), bufferLengths.end());
    Uint64 maxLen = *std::max_element(bufferLengths.begin(), bufferLengths.end());
    Uint64 avgLen = totalBytes / numBuffers;

    state.counters["Speed(Bytes/s)"] =
        benchmark::Counter(state.iterations() * totalBytes,
                           benchmark::Counter::kIsRate);
    state.counters["NumBuffers"]   = numBuffers;
    state.counters["TotalBytes"]   = totalBytes;
    state.counters["MinLen"]       = minLen;
    state.counters["MaxLen"]       = maxLen;
    state.counters["AvgLen"]       = avgLen;
    state.counters["LenRatio"]     = static_cast<double>(maxLen) / minLen;

    return 0;
}

/* Custom benchmark for specific scenarios */
static void
BENCH_AES_CUSTOM_VARLEN_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferVarLenAbsoluteBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128,
        state.range(1), state.range(2)));
}

/* Multi-tier benchmark functions */
static void
BENCH_AES_MULTITIER_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferMultiTierBench(
        state, ENCRYPT, ALC_AES_MODE_CBC, 128, state.range(0)));
}

static void
BENCH_AES_MULTITIER_MULTIBUFFER_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferMultiTierBench(
        state, ENCRYPT, ALC_AES_MODE_CBC, 256, state.range(0)));
}

static void
BENCH_AES_MULTITIER_MULTIBUFFER_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferMultiTierBench(
        state, ENCRYPT, ALC_AES_MODE_CFB, 128, state.range(0)));
}

static void
BENCH_AES_MULTITIER_MULTIBUFFER_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferMultiTierBench(
        state, ENCRYPT, ALC_AES_MODE_CFB, 256, state.range(0)));
}

/* Fixed-length benchmark functions for comparison */
static void
BENCH_AES_FIXED_MULTIBUFFER_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferFixedLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128, state.range(1)));
}

static void
BENCH_AES_FIXED_MULTIBUFFER_CBC_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferFixedLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 256, state.range(1)));
}

static void
BENCH_AES_FIXED_MULTIBUFFER_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferFixedLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128, state.range(1)));
}

static void
BENCH_AES_FIXED_MULTIBUFFER_CFB_256(benchmark::State& state)
{
    benchmark::DoNotOptimize(CipherMultibufferFixedLenBench(
        state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 256, state.range(1)));
}

int
main(int argc, char** argv)
{
    benchmark::Initialize(&argc, argv);

    std::cout << "\n=== Variable-Length Multibuffer Cipher Benchmarks ===\n";
    std::cout << "Testing MinLen optimization for variable-length buffers\n\n";

    /* Test blocksizes, number of buffers, and variance */
    std::vector<Int64> avg_blocksizes = { 512, 1024, 4096, 8192 };
    std::vector<Int64> num_buffers    = { 4, 8, 16, 32, 64 };
    std::vector<Int64> variances      = { 10, 30, 50 }; // Percentage variance
    std::vector<Int64> abs_variances  = { 64, 128, 256, 512 }; // Absolute byte variance

    std::cout << "Variable-Length Benchmarks (Absolute Variance - ±bytes):\n";

    // CBC with Absolute Variance (±64, ±128, ±256 bytes)
    BENCHMARK(BENCH_AES_VARLEN_ABS_MULTIBUFFER_CBC_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers, abs_variances })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_VARLEN_ABS_MULTIBUFFER_CBC_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers, abs_variances })
        ->Unit(benchmark::kMicrosecond);

    // CFB with Absolute Variance
    BENCHMARK(BENCH_AES_VARLEN_ABS_MULTIBUFFER_CFB_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers, abs_variances })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_VARLEN_ABS_MULTIBUFFER_CFB_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers, abs_variances })
        ->Unit(benchmark::kMicrosecond);

    std::cout << "\nVariable-Length Benchmarks (Percentage Variance):\n";

    // CBC Variable-Length Benchmarks with Percentage
    BENCHMARK(BENCH_AES_VARLEN_MULTIBUFFER_CBC_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers, variances })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_VARLEN_MULTIBUFFER_CBC_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers, variances })
        ->Unit(benchmark::kMicrosecond);

    // CFB Variable-Length Benchmarks with Percentage
    BENCHMARK(BENCH_AES_VARLEN_MULTIBUFFER_CFB_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers, variances })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_VARLEN_MULTIBUFFER_CFB_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers, variances })
        ->Unit(benchmark::kMicrosecond);

    std::cout << "\nCustom Scenario: Uniform ±332 bytes with avg=512 (range 180-844):\n";

    // Custom benchmark: avg=512, ±332 bytes
    BENCHMARK(BENCH_AES_CUSTOM_VARLEN_MULTIBUFFER_CBC_128)
        ->Args({ 512, 32, 332 })
        ->Args({ 512, 64, 332 })
        ->Unit(benchmark::kMicrosecond);

    std::cout << "\nMulti-Tier Benchmarks (stress test with 30% small/40% medium/30% large):\n";

    // Multi-Tier Benchmarks - simulates highly heterogeneous packet lengths
    BENCHMARK(BENCH_AES_MULTITIER_MULTIBUFFER_CBC_128)
        ->Args({ 4 })
        ->Args({ 8 })
        ->Args({ 16 })
        ->Args({ 32 })
        ->Args({ 64 })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_MULTITIER_MULTIBUFFER_CBC_256)
        ->Args({ 4 })
        ->Args({ 8 })
        ->Args({ 16 })
        ->Args({ 32 })
        ->Args({ 64 })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_MULTITIER_MULTIBUFFER_CFB_128)
        ->Args({ 4 })
        ->Args({ 8 })
        ->Args({ 16 })
        ->Args({ 32 })
        ->Args({ 64 })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_MULTITIER_MULTIBUFFER_CFB_256)
        ->Args({ 4 })
        ->Args({ 8 })
        ->Args({ 16 })
        ->Args({ 32 })
        ->Args({ 64 })
        ->Unit(benchmark::kMicrosecond);

    std::cout << "\nFixed-Length Benchmarks (for comparison):\n";

    // Fixed-Length Benchmarks for comparison
    BENCHMARK(BENCH_AES_FIXED_MULTIBUFFER_CBC_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_FIXED_MULTIBUFFER_CBC_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_FIXED_MULTIBUFFER_CFB_128)
        ->ArgsProduct({ avg_blocksizes, num_buffers })
        ->Unit(benchmark::kMicrosecond);
    BENCHMARK(BENCH_AES_FIXED_MULTIBUFFER_CFB_256)
        ->ArgsProduct({ avg_blocksizes, num_buffers })
        ->Unit(benchmark::kMicrosecond);

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    return 0;
}
