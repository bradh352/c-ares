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

#include "ares_private.h"
#include "ares_crypto.h"

#ifdef CARES_USE_CRYPTO

struct ares_crypto_ctx {
  /*! Implementation-specific ctx for system initialization */
  ares_cryptoimp_ctx_t *imp_ctx;

  /*! Forward lookups for sessions */
  ares_htable_strvp_t  *sess_fwd;

  /*! Reverse lookups for sessions (for removal) */
  ares_htable_vpstr_t  *sess_rev;

};

ares_status_t ares_crypto_ctx_init(ares_crypto_ctx_t **ctx)
{
  ares_status_t status;

  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  *ctx = ares_malloc_zero(sizeof(**ctx));
  if (*ctx == NULL) {
    return ARES_ENOMEM;
  }

  status = ares_cryptoimp_ctx_init(&(*ctx)->imp_ctx, *ctx);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  (*ctx)->sess_fwd = ares_htable_strvp_create(ares_tlsimp_session_free);
  if ((*ctx)->sess_fwd == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

done:
  if (status != ARES_SUCCESS) {
    ares_crypto_ctx_destroy(*ctx);
    *ctx = NULL;
  }
  return status;
}

void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }

  ares_htable_strvp_destroy(ctx->sess_fwd);
  ares_htable_vpstr_destroy(ctx->sess_rev);
  ares_cryptoimp_ctx_destroy(ctx->imp_ctx);
  ares_free(ctx);
}

static char *ares_tls_session_key(ares_conn_t *conn)
{
  ares_status_t status                 = ARES_SUCCESS;
  ares_buf_t   *buf;
  char          addr[INET6_ADDRSTRLEN] = "";

  if (conn == NULL) {
    return NULL;
  }

  buf = ares_buf_create();
  if (buf == NULL) {
    return NULL;
  }

  /* Format:  hostname@[ip]:port */

  /* TODO: implement me -- fetch hostname */
  status = ares_buf_append_str(buf, "hostname");
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_buf_append_str(buf, "@[");
  if (status != ARES_SUCCESS) {
    goto done;
  }

  ares_inet_ntop(conn->server->addr.family, &conn->server->addr.addr, addr,
                 sizeof(addr));

  status = ares_buf_append_str(buf, addr);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_buf_append_str(buf, "]:");
  if (status != ARES_SUCCESS) {
    goto done;
  }

  /* Port */
  status = ares_buf_append_num_dec(buf, conn->server->tcp_port, 0);
  if (status != ARES_SUCCESS) {
    goto done;
  }

done:
  return ares_buf_finish_str(buf, NULL);
}

ares_status_t ares_tls_session_insert(ares_crypto_ctx_t *crypto_ctx,
                                      ares_conn_t *conn, void *sess)
{
  char         *key    = ares_tls_session_key(conn);
  ares_status_t status = ARES_SUCCESS;

  if (key == NULL || crypto_ctx == NULL || sess == NULL) {
    return ARES_EFORMERR;
  }

  if (!ares_htable_strvp_insert(crypto_ctx->sess_fwd, key, sess)) {
    status = ARES_ENOMEM;
    goto done;
  }

  if (!ares_htable_vpstr_insert(crypto_ctx->sess_rev, sess, key)) {
    status = ARES_ENOMEM;
    goto done;
  }

done:
  if (status != ARES_SUCCESS) {
    ares_htable_strvp_claim(crypto_ctx->sess_fwd, key);
    ares_htable_vpstr_remove(crypto_ctx->sess_rev, sess);
  }
  ares_free(key);
  return status;
}

ares_status_t ares_tls_session_remove(ares_crypto_ctx_t *crypto_ctx,
                                      void *sess)
{
  const char *key;

  if (crypto_ctx == NULL || sess == NULL) {
    return ARES_EFORMERR;
  }

  key = ares_htable_vpstr_get_direct(crypto_ctx->sess_rev, sess);
  if (key == NULL) {
    return ARES_ENOTFOUND;
  }

  ares_htable_strvp_claim(crypto_ctx->sess_fwd, key);
  ares_htable_vpstr_remove(crypto_ctx->sess_rev, sess);

  return ARES_SUCCESS;
}

void *ares_tls_session_get(ares_crypto_ctx_t *crypto_ctx,
                           ares_conn_t       *conn)
{
  char *key;
  void *sess;

  if (crypto_ctx == NULL || conn == NULL) {
    return NULL;
  }

  key = ares_tls_session_key(conn);
  if (key == NULL) {
    return NULL;
  }

  sess = ares_htable_strvp_get_direct(crypto_ctx->sess_fwd, key);
  ares_free(key);

  return sess;
}

#endif
