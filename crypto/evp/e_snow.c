/* $OpenBSD: e_snow.c,v 1.4 2014/07/10 22:45:57 jsing Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SNOW3G

#include <openssl/snow3g.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "evp_locl.h"

static int
snow3g_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len);

static int
snow3g_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc);

static const EVP_CIPHER snow_cipher = {
	.nid = NID_snow3g,
	.block_size = 1,
	.key_len = 16,
	.iv_len = 16,
	.flags = EVP_CIPH_STREAM_CIPHER,
	.init = snow3g_init,
	.do_cipher = snow3g_cipher,
	.ctx_size = sizeof(snow_ctx)
};

const EVP_CIPHER *
EVP_snow3g(void)
{
	return (&snow_cipher);
}

static int
snow3g_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
  struct snow_key_st key_iv = snow_array_to_key(key, iv);
  SNOW_set_key(key_iv, (snow_ctx*)ctx->cipher_data);
  return 1;
}

static int
snow3g_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
  SNOW(len, in, out, (snow_ctx*)ctx->cipher_data);
  return 1;
}

#endif
