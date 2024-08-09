/* MIT License
 *
 * Copyright (c) 2024 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARES_CRYPTO_H
#define __ARES_CRYPTO_H

struct ares_crypto_ctx;
typedef struct ares_crypto_ctx ares_crypto_ctx_t;

ares_status_t                  ares_crypto_ctx_init(ares_crypto_ctx_t **ctx);
void                           ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx);

struct ares_tls;
typedef struct ares_tls ares_tls_t;

#if 0
ares_tls_t *ares_tls_create(ares_conn_t *conn);
ares_tls_destroy

ares_tls_connect(ares_tls_t *tls);
ares_tls_read(ares_tls_t *tls, unsigned char *buf, size_t *buf_len);
ares_tls_write(ares_tls_t *tls, const unsigned char *buf, size_t *buf_len);
ares_tls_shutdown(ares_tls_t *tls);
#endif

#endif
