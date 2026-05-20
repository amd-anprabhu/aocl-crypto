/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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
 * 
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file contains code for TLS CBC Padding removal taken from  
 * providers/implementations/ciphers/ciphercommon_block.c, ssl/record/methods/tls_pad.c and include/internal/constant_time.h 
 * modified by AMD 
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

#include "alcp_cipher_prov_common.h"

#include <openssl/crypto.h>
#include <openssl/prov_ssl.h>
#include <openssl/rand.h>

/* Constant-time helper functions matching OpenSSL's internal/constant_time.h */

/* Returns the given value with the MSB copied to all the other bits. */
static inline unsigned int
constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

/* Returns the given value with the MSB copied to all the other bits. */
static inline size_t
constant_time_msb_s(size_t a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

/* Returns 0xff..f if a < b and 0 otherwise. */
static inline size_t
constant_time_lt_s(size_t a, size_t b)
{
    return constant_time_msb_s(a ^ ((a ^ b) | ((a - b) ^ b)));
}

/* Returns 0xff..f if a >= b and 0 otherwise. */
static inline size_t
constant_time_ge_s(size_t a, size_t b)
{
    return ~constant_time_lt_s(a, b);
}

/* Convenience method for getting an 8-bit mask. */
static inline unsigned char
constant_time_ge_8_s(size_t a, size_t b)
{
    return (unsigned char)constant_time_ge_s(a, b);
}

/* Returns 0xff..f if a == 0 and 0 otherwise. */
static inline size_t
constant_time_is_zero_s(size_t a)
{
    return constant_time_msb_s(~a & (a - 1));
}

/* Returns 0xff..f if a == 0 and 0 otherwise. */
static inline unsigned int
constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

/* Returns 0xff..f if a == b and 0 otherwise. */
static inline size_t
constant_time_eq_s(size_t a, size_t b)
{
    return constant_time_is_zero_s(a ^ b);
}

/* Returns 0xff..f if a == b and 0 otherwise. */
static inline unsigned int
constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

/* Convenience method for getting an 8-bit mask. */
static inline unsigned char
constant_time_eq_8(unsigned int a, unsigned int b)
{
    return (unsigned char)constant_time_eq(a, b);
}

/*
 * Returns the value unmodified, but avoids optimizations.
 * The barriers prevent the compiler from narrowing down the
 * possible value range of the mask and ~mask in the select
 * statements, which avoids the recognition of the select
 * and turning it into a conditional load or branch.
 */
static inline unsigned int
value_barrier(unsigned int a)
{
#if !defined(ALCP_DISABLE_ASSEMBLY) && defined(__GNUC__)
    unsigned int r;
    __asm__("" : "=r"(r) : "0"(a));
#else
    volatile unsigned int r = a;
#endif
    return r;
}

/* Returns (mask & a) | (~mask & b). */
static inline unsigned int
constant_time_select(unsigned int mask, unsigned int a, unsigned int b)
{
    return (value_barrier(mask) & a) | (value_barrier(~mask) & b);
}

/* Convenience method for unsigned chars. */
static inline unsigned char
constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)
{
    return (unsigned char)constant_time_select(mask, a, b);
}


/*
 * CBC_MAC_ROTATE_IN_PLACE is always defined. The rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. This path is always taken - the alternative
 * implementation has been removed as it is never compiled.
 */
#define CBC_MAC_ROTATE_IN_PLACE

/* Based on ssl3_cbc_copy_mac in OpenSSL ssl/record/methods/tls_pad.c */
/*-
 * alcp_ssl3_cbc_copy_mac copies |md_size| bytes from the end of the record in
 * |recdata| to |*mac| in constant time (independent of the concrete value of
 * the record length |reclen|, which may vary within a 256-byte window).
 *
 * On entry:
 *   origreclen >= mac_size
 *   mac_size <= EVP_MAX_MD_SIZE
 *
 * If CBC_MAC_ROTATE_IN_PLACE is defined then the rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. CPUs with smaller cache-lines [if any] are
 * not multi-core and are not considered vulnerable to cache-timing attacks.
 */
static int
alcp_ssl3_cbc_copy_mac(size_t*        reclen,
                  size_t         origreclen,
                  unsigned char* recdata,
                  unsigned char** mac,
                  int*           alloced,
                  size_t         block_size,
                  size_t         mac_size,
                  size_t         good,
                  OSSL_LIB_CTX*  libctx)
{
    /*
     * CBC_MAC_ROTATE_IN_PLACE: Use 64-byte aligned buffer for cache-line
     * optimized constant-time MAC rotation.
     */
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
    char aux1, aux2, aux3, mask;
    unsigned char randmac[EVP_MAX_MD_SIZE];
    unsigned char *out;

    /*
     * mac_end is the index of |recdata| just after the end of the MAC.
     */
    size_t mac_end = *reclen;
    size_t mac_start = mac_end - mac_size;
    size_t in_mac;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    size_t scan_start = 0;
    size_t i, j;
    size_t rotate_offset;

    assert(origreclen >= mac_size && mac_size <= EVP_MAX_MD_SIZE);
    if (!(origreclen >= mac_size && mac_size <= EVP_MAX_MD_SIZE))
        return 0;

    /* If no MAC then nothing to be done */
    if (mac_size == 0) {
        /* No MAC so we can do this in non-constant time */
        if (good == 0)
            return 0;
        return 1;
    }

    *reclen -= mac_size;

    if (block_size == 1) {
        /* There's no padding so the position of the MAC is fixed */
        if (mac != NULL)
            *mac = &recdata[*reclen];
        if (alloced != NULL)
            *alloced = 0;
        return 1;
    }

    /* Create the random MAC we will emit if padding is bad */
    if (RAND_bytes_ex(libctx, randmac, mac_size, 0) <= 0)
        return 0;

    assert(mac != NULL && alloced != NULL);
    if (!(mac != NULL && alloced != NULL))
        return 0;
    *mac = out = OPENSSL_malloc(mac_size);
    if (*mac == NULL)
        return 0;
    *alloced = 1;

    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);

    /* This information is public so it's safe to branch based on it. */
    if (origreclen > mac_size + 255 + 1)
        scan_start = origreclen - (mac_size + 255 + 1);

    in_mac = 0;
    rotate_offset = 0;
    memset(rotated_mac, 0, mac_size);
    for (i = scan_start, j = 0; i < origreclen; i++) {
        size_t mac_started = constant_time_eq_s(i, mac_start);
        size_t mac_ended = constant_time_lt_s(i, mac_end);
        unsigned char b = recdata[i];

        in_mac |= mac_started;
        in_mac &= mac_ended;
        rotate_offset |= j & mac_started;
        rotated_mac[j++] |= b & in_mac;
        j &= constant_time_lt_s(j, mac_size);
    }

    /* Now rotate the MAC */
    j = 0;
    for (i = 0; i < mac_size; i++) {
        /*
         * in case cache-line is 32 bytes,
         * load from both lines and select appropriately
         */
        aux1 = rotated_mac[rotate_offset & ~32];
        aux2 = rotated_mac[rotate_offset | 32];
        mask = constant_time_eq_8(rotate_offset & ~32, rotate_offset);
        aux3 = constant_time_select_8(mask, aux1, aux2);
        rotate_offset++;

        /* If the padding wasn't good we emit a random MAC */
        out[j++] = constant_time_select_8((unsigned char)(good & 0xff),
                                          aux3,
                                          randmac[i]);
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    }

    return 1;
}

/* Based on ssl3_cbc_remove_padding_and_mac in OpenSSL ssl/record/methods/tls_pad.c */
/*-
 * alcp_ssl3_cbc_remove_padding_and_mac removes padding from the decrypted, SSLv3, CBC
 * record in |recdata| by updating |reclen| in constant time. It also extracts
 * the MAC from the underlying record and places a pointer to it in |mac|. The
 * MAC data can either be newly allocated memory, or a pointer inside the
 * |recdata| buffer. If allocated then |*alloced| is set to 1, otherwise it is
 * set to 0.
 *
 * origreclen: the original record length before any changes were made
 * block_size: the block size of the cipher used to encrypt the record.
 * mac_size: the size of the MAC to be extracted
 * aead: 1 if an AEAD cipher is in use, or 0 otherwise
 * returns:
 *   0: if the record is publicly invalid.
 *   1: if the record is publicly valid. If the padding removal fails then the
 *      MAC returned is random.
 */
static int
alcp_ssl3_cbc_remove_padding_and_mac(size_t*        reclen,
                                size_t         origreclen,
                                unsigned char* recdata,
                                unsigned char** mac,
                                int*           alloced,
                                size_t         block_size,
                                size_t         mac_size,
                                OSSL_LIB_CTX*  libctx)
{
    size_t padding_length;
    size_t good;
    const size_t overhead = 1 /* padding length byte */  + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant time.
     */
    if (overhead > *reclen)
        return 0;

    padding_length = recdata[*reclen - 1];
    good = constant_time_ge_s(*reclen, padding_length + overhead);
    /* SSLv3 requires that the padding is minimal. */
    good &= constant_time_ge_s(block_size, padding_length + 1);
    *reclen -= good & (padding_length + 1);

    return alcp_ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx);
}

/* Based on tls1_cbc_remove_padding_and_mac in OpenSSL ssl/record/methods/tls_pad.c */
/*-
 * alcp_tls1_cbc_remove_padding_and_mac removes padding from the decrypted, TLS, CBC
 * record in |recdata| by updating |reclen| in constant time. It also extracts
 * the MAC from the underlying record and places a pointer to it in |mac|. The
 * MAC data can either be newly allocated memory, or a pointer inside the
 * |recdata| buffer. If allocated then |*alloced| is set to 1, otherwise it is
 * set to 0.
 *
 * origreclen: the original record length before any changes were made
 * block_size: the block size of the cipher used to encrypt the record.
 * mac_size: the size of the MAC to be extracted
 * aead: 1 if an AEAD cipher is in use, or 0 otherwise
 * returns:
 *   0: if the record is publicly invalid.
 *   1: if the record is publicly valid. If the padding removal fails then the
 *      MAC returned is random.
 */
static int
alcp_tls1_cbc_remove_padding_and_mac(size_t*        reclen,
                                size_t         origreclen,
                                unsigned char* recdata,
                                unsigned char** mac,
                                int*           alloced,
                                size_t         block_size,
                                size_t         mac_size,
                                int            aead,
                                OSSL_LIB_CTX*  libctx)
{
    size_t good = -1;
    size_t padding_length, to_check, i;
    size_t overhead = ((block_size == 1) ? 0 : 1) /* padding length byte */
                      + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant
     * time.
     */
    if (overhead > *reclen)
        return 0;

    if (block_size != 1) {

        padding_length = recdata[*reclen - 1];

        if (aead) {
            /* padding is already verified and we don't need to check the MAC */
            *reclen -= padding_length + 1 + mac_size;
            return 1;
        }

        good = constant_time_ge_s(*reclen, overhead + padding_length);
        /*
         * The padding consists of a length byte at the end of the record and
         * then that many bytes of padding, all with the same value as the
         * length byte. Thus, with the length byte included, there are i+1 bytes
         * of padding. We can't check just |padding_length+1| bytes because that
         * leaks decrypted information. Therefore we always have to check the
         * maximum amount of padding possible. (Again, the length of the record
         * is public information so we can use it.)
         */
        to_check = 256;        /* maximum amount of padding, inc length byte. */
        if (to_check > *reclen)
            to_check = *reclen;

        for (i = 0; i < to_check; i++) {
            unsigned char mask = constant_time_ge_8_s(padding_length, i);
            unsigned char b = recdata[*reclen - 1 - i];
            /*
             * The final |padding_length+1| bytes should all have the value
             * |padding_length|. Therefore the XOR should be zero.
             */
            good &= ~(mask & (padding_length ^ b));
        }

        /*
         * If any of the final |padding_length+1| bytes had the wrong value, one
         * or more of the lower eight bits of |good| will be cleared.
         */
        good = constant_time_eq_s(0xff, good & 0xff);
        *reclen -= good & (padding_length + 1);
    }

    return alcp_ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx);
}

/* Based on ossl_cipher_tlsunpadblock in OpenSSL providers/implementations/ciphers/ciphercommon_block.c */
/*-
 * ALCP_prov_cipher_tlsunpadblock removes the CBC padding from the decrypted,
 * TLS, CBC record in constant time. Also removes the MAC from the record in
 * constant time.
 *
 * libctx: Our library context
 * tlsversion: The TLS version in use, e.g. SSL3_VERSION, TLS1_VERSION, etc
 * buf: The decrypted TLS record data
 * buflen: The length of the decrypted TLS record data. Updated with the new
 *         length after the padding is removed
 * block_size: the block size of the cipher used to encrypt the record.
 * mac: Location to store the pointer to the MAC
 * alloced: Whether the MAC is stored in a newly allocated buffer, or whether
 *          *mac points into *buf
 * macsize: the size of the MAC inside the record (or 0 if there isn't one)
 * aead: whether this is an aead cipher
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: (in constant time) Record is publicly valid. If padding is invalid then
 *      the mac is random
 */
int
ALCP_prov_cipher_tlsunpadblock(OSSL_LIB_CTX* libctx,
                               unsigned int  tlsversion,
                               Uint8*        buf,
                               size_t*       buflen,
                               size_t        blocksize,
                               Uint8**       mac,
                               int*          alloced,
                               size_t        macsize,
                               int           aead)
{
    int ret;

    switch (tlsversion) {
    case SSL3_VERSION:
        return alcp_ssl3_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
                                               alloced, blocksize, macsize,
                                               libctx);

    case TLS1_2_VERSION:
    case DTLS1_2_VERSION:
    case TLS1_1_VERSION:
    case DTLS1_VERSION:
    case DTLS1_BAD_VER:
        /* Remove the explicit IV */
        buf += blocksize;
        *buflen -= blocksize;
        /* Fall through */
    case TLS1_VERSION:
        ret = alcp_tls1_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
                                              alloced, blocksize, macsize,
                                              aead, libctx);
        return ret;

    default:
        return 0;
    }
}
