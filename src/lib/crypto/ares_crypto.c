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

  /* The backend (OpenSSL provider load, client SSL_CTX, and -- expensively
   * on some platforms -- system CA-root enumeration) is created lazily on
   * first TLS use, not here: a channel that never talks to a DoT server
   * must not pay that cost at init.  Only the cheap session-cache tables
   * are set up eagerly. */
  (*ctx)->sess_fwd = ares_htable_strvp_create(ares_tlsimp_session_free);
  if ((*ctx)->sess_fwd == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  (*ctx)->sess_rev = ares_htable_vpstr_create();
  if ((*ctx)->sess_rev == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_crypto_ctx_destroy(*ctx);
    *ctx = NULL;
  }
  return status;
}

/*! Lazily create the backend implementation context on first TLS use */
static ares_status_t ares_crypto_ctx_ensure_backend(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return ARES_EFORMERR;
  }
  if (ctx->imp_ctx != NULL) {
    return ARES_SUCCESS;
  }
  return ares_cryptoimp_ctx_init(&ctx->imp_ctx, ctx);
}

void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }

  /* The backend must be destroyed first: tearing it down flushes its
   * session cache which calls back into ares_tls_session_remove(), and
   * that dereferences these tables.  Any sessions still held after the
   * backend is gone are released by the table destructors. */
  ares_cryptoimp_ctx_destroy(ctx->imp_ctx);
  ares_htable_strvp_destroy(ctx->sess_fwd);
  ares_htable_vpstr_destroy(ctx->sess_rev);
  ares_free(ctx);
}

static char *ares_tls_session_key(ares_conn_t *conn)
{
  ares_status_t status = ARES_SUCCESS;
  ares_buf_t   *buf;
  char          addr[INET6_ADDRSTRLEN] = "";

  if (conn == NULL) {
    return NULL;
  }

  buf = ares_buf_create();
  if (buf == NULL) {
    return NULL;
  }

  /* Format:  hostname@[ip]:port -- the hostname component is the server's
   * TLS authentication name (blank when none is configured) so the same
   * ip:port with different names never share sessions */
  if (ares_strlen(conn->server->tls_hostname) > 0) {
    status = ares_buf_append_str(buf, conn->server->tls_hostname);
    if (status != ARES_SUCCESS) {
      goto done;
    }
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
  if (status != ARES_SUCCESS) {
    /* A partial key must never be returned: it could alias another
     * server's sessions */
    ares_buf_destroy(buf);
    return NULL;
  }
  return ares_buf_finish_str(buf, NULL);
}

ares_status_t ares_tls_session_insert(ares_crypto_ctx_t *crypto_ctx,
                                      ares_conn_t *conn, void *sess)
{
  char         *key    = ares_tls_session_key(conn);
  ares_status_t status = ARES_SUCCESS;
  void         *old_sess;

  if (key == NULL || crypto_ctx == NULL || sess == NULL) {
    ares_free(key);
    return ARES_EFORMERR;
  }

  /* Replacing an existing session for this key (e.g. a fresh ticket for
   * the same server): the forward insert below releases the old session,
   * so its reverse entry must go too or a later backend removal callback
   * for the old session would tear down the new one's forward entry */
  old_sess = ares_htable_strvp_get_direct(crypto_ctx->sess_fwd, key);
  if (old_sess != NULL) {
    ares_htable_vpstr_remove(crypto_ctx->sess_rev, old_sess);
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

ares_status_t ares_tls_session_remove(ares_crypto_ctx_t *crypto_ctx, void *sess)
{
  const char *key;

  if (crypto_ctx == NULL || sess == NULL) {
    return ARES_EFORMERR;
  }

  key = ares_htable_vpstr_get_direct(crypto_ctx->sess_rev, sess);
  if (key == NULL) {
    return ARES_ENOTFOUND;
  }

  /* Remove (not claim) so the cache's reference on the session is released
   * via the table's value destructor.  Callers (the backend's cache-removal
   * callback) hold their own reference for any continued use.  The rev
   * entry owns `key`, so it must be removed second. */
  ares_htable_strvp_remove(crypto_ctx->sess_fwd, key);
  ares_htable_vpstr_remove(crypto_ctx->sess_rev, sess);

  return ARES_SUCCESS;
}

ares_status_t ares_tls_create(ares_tls_t **tls, ares_crypto_ctx_t *crypto_ctx,
                              ares_conn_t *conn)
{
  ares_status_t status;

  if (tls == NULL || crypto_ctx == NULL || conn == NULL) {
    return ARES_EFORMERR;
  }

  status = ares_crypto_ctx_ensure_backend(crypto_ctx);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ares_tlsimp_create(tls, crypto_ctx->imp_ctx, conn);
}

ares_status_t ares_tls_set_cadata(ares_crypto_ctx_t   *crypto_ctx,
                                  const unsigned char *pem, size_t len)
{
  ares_status_t status;

  if (crypto_ctx == NULL) {
    return ARES_EFORMERR;
  }

  /* Trust anchors may be configured before any connection; make sure the
   * backend (and its certificate store) exists */
  status = ares_crypto_ctx_ensure_backend(crypto_ctx);
  if (status != ARES_SUCCESS) {
    return status;
  }

  return ares_tlsimp_set_cadata(crypto_ctx->imp_ctx, pem, len);
}

void *ares_tls_session_get(ares_crypto_ctx_t *crypto_ctx, ares_conn_t *conn)
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
