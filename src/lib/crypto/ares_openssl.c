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

#ifdef CARES_CRYPTO_OPENSSL
#  include <openssl/crypto.h>
#  include <openssl/provider.h>
#  include <openssl/ssl.h>
#  include <openssl/bio.h>

#  ifdef __APPLE__
#    include <Security/Security.h>
#  endif
#  ifdef _WIN32
#    include <wincrypt.h>
#  endif

struct ares_crypto_ctx {
  OSSL_LIB_CTX  *ctx;
  OSSL_PROVIDER *default_provider;
  SSL_CTX       *sslctx;
  BIO_METHOD    *bio_method;
};

typedef enum {
  ARES_OSSL_STATE_INIT        = 0,
  ARES_OSSL_STATE_CONNECT     = 1,
  ARES_OSSL_STATE_ESTABLISHED = 2,
  ARES_OSSL_STATE_SHUTDOWN    = 3,
  ARES_OSSL_STATE_ERROR       = 4
} ares_ossl_state_t;

struct ares_tls {
  SSL              *ssl;
  ares_conn_err_t   last_io_error;
  ares_ossl_state_t state;
};

#  if defined(__APPLE__)
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  CFArrayRef  anchors;
  int         ret;
  int         i;
  size_t      count = 0;
  X509_STORE *store;

  (void)libctx;

  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  ret = SecTrustCopyAnchorCertificates(&anchors);
  if (ret != 0) {
    return ARES_ESERVFAIL;
  }

  store = SSL_CTX_get_cert_store(ctx);
  for (i = 0; i < CFArrayGetCount(anchors); i++) {
    const void          *ptr = CFArrayGetValueAtIndex(anchors, i);
    SecCertificateRef    cr  = (SecCertificateRef)((void *)ptr);
    CFDataRef            dref;
    X509                *x509;
    const unsigned char *data;

    dref = SecCertificateCopyData(cr);
    if (dref == NULL) {
      continue;
    }

    /* DER-encoded
     *
     * CFDataGetLength will be auto converted to long by
     * the compiler (this is not undefined behavior). */
    data = CFDataGetBytePtr(dref);
    x509 = d2i_X509(NULL, &data, CFDataGetLength(dref));
    CFRelease(dref);
    if (x509 == NULL) {
      continue;
    }

    if (X509_STORE_add_cert(store, x509)) {
      count++;
    }

    X509_free(x509);
  }
  CFRelease(anchors);

  if (!count) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

#  elif defined(_WIN32)

/* NOTE:  OpenSSL v3.2+ supposedly you can do something like:
 *   X509_STORE *vfy = X509_STORE_new();
 *   X509_STORE_load_store_ex(vfy, "org.openssl.winstore://", (*ctx)->ctx,
 * NULL); SSL_CTX_set1_verify_cert_store(ctx, vfy); X509_STORE_free(vfy);
 */
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  HCERTSTORE     hStore;
  PCCERT_CONTEXT pContext = NULL;
  X509_STORE    *store;
  size_t         count = 0;

  (void)libctx;

  if (ctx == NULL) {
    return ARES_EFORMERR;
  }

  hStore = CertOpenSystemStore(0, "ROOT");
  if (hStore == NULL) {
    return ARES_ESERVFAIL;
  }

  store = SSL_CTX_get_cert_store(ctx);

  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
    BYTE * const *cert = &pContext->pbCertEncoded;
    X509 *x509 = d2i_X509(NULL, M_CAST_OFF_CONST(const unsigned char **, cert),
                          (long)pContext->cbCertEncoded);
    if (x509) {
      if (X509_STORE_add_cert(store, x509)) {
        count++;
      }
      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  if (!count) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

#  else

static ares_bool_t file_exists(const char *path, ares_bool_t is_directory)
{
#    ifdef HAVE_STAT
  struct stat st;
  if (stat(filename, &st) != 0) {
    return ARES_FALSE;
  }
#    elif defined(_WIN32)
  struct _stat st;
  if (_stat(filename, &st) != 0) {
    return ARES_FALSE;
  }
#    endif
  if (is_directory) {
    if (st.st_mode & S_IFDIR) {
      return ARES_TRUE;
    }
    return ARES_FALSE;
  }
  if (st.st_mode & S_IFREG) {
    return ARES_TRUE;
  }
  return ARES_FALSE;
}

static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  static const char * const cafile_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/usr/share/ssl/certs/ca-bundle.crt",
    "/etc/pki/tls/certs/ca-bundle.trust.crt",
    "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD via port
                                                 security/ca_root_nss */
    NULL
  };
  static const char * const cadirs[] = {
    "/etc/ssl/certs/",               /* Ubuntu */
    "/system/etc/security/cacerts/", /* Android */
    NULL
  };
  size_t      i;
  X509_STORE *x509_store = NULL;

  x509_store = X509_STORE_new();
  if (x509_store == NULL) {
    return ARES_ENOMEM;
  }

  for (i = 0; i < cadirs[i] != NULL; i++) {
    if (file_exists(cadires[i], ARES_TRUE) &&
        X509_STORE_load_path(x509_store, cadirs[i]) == 1) {
      goto done;
    }
  }

  for (i = 0; i < cafile_paths[i] != NULL; i++) {
    if (file_exists(cafile_paths[i], ARES_FALSE) &&
        X509_STORE_load_file_ex(x509_store, cafile_paths[i], libctx, NULL) ==
          1) {
      goto done;
    }
  }

  X509_STORE_free(x509_store);
  return ARES_ENOTFOUND;

done:
  SSL_CTX_set1_verify_cert_store(ctx, x509_store);

  X509_STORE_free(x509_store);
  return ARES_SUCCESS;
}
#  endif

void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }
  if (ctx->bio_method != NULL) {
    BIO_meth_free(ctx->bio_method);
  }
  if (ctx->sslctx != NULL) {
    SSL_CTX_free(ctx->sslctx);
  }
  if (ctx->default_provider != NULL) {
    OSSL_PROVIDER_unload(ctx->default_provider);
  }
  if (ctx->ctx != NULL) {
    OSSL_LIB_CTX_free(ctx->ctx);
  }
  ares_free(ctx);
}

static int ares_ossl_bio_read_ex(BIO *b, char *buf, size_t len,
                                 size_t *readbytes)
{
  ares_conn_t    *conn = BIO_get_data(b);
  ares_conn_err_t err;
  BIO_clear_retry_flags(b);

  *readbytes = 0;

  /* XXX: save last_io_error */
  err = ares__conn_read(conn, buf, len, readbytes);
  if (err == ARES_CONN_ERR_SUCCESS) {
    return 1;
  }

  if (err == ARES_CONN_ERR_WOULDBLOCK) {
    /* Error is non-fatal, set the reason as need to retry read events */
    BIO_set_retry_read(b);
  }

  return 0;
}

static int ares_ossl_bio_write_ex(BIO *b, const char *buf, size_t len,
                                  size_t *written)
{
  ares_conn_err_t err;
  ares_conn_t    *conn = BIO_get_data(b);

  *written = 0;

  /* XXX: save last_io_error */
  err = ares__conn_write(conn, buf, len, written);
  if (err == ARES_CONN_ERR_SUCCESS) {
    return 1;
  }

  if (err == ARES_CONN_ERR_WOULDBLOCK) {
    /* Error is non-fatal, set the reason as need to retry read events */
    BIO_set_retry_read(b);
  }

  return 0;
}

static long ares_ossl_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  (void)b;
  (void)num;
  (void)ptr;
  switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
      return (long)BIO_get_shutdown(b);
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(b, (int)num);
      return 1;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      /* Required internally by OpenSSL, no-op though */
      return 1;
  }
  return 0;
}

static int ares_ossl_bio_puts(BIO *b, const char *str)
{
  size_t written;
  int    rv;
  rv = ares_ossl_bio_write_ex(b, str, ares_strlen(str), &written);
  if (rv == 0) {
    return -1;
  }
  return (int)written;
}

static int ares_ossl_bio_create(BIO *b)
{
  BIO_set_data(b, NULL);
  BIO_set_init(b, 1);
  BIO_clear_flags(b, INT_MAX);
  return 1;
}

static int ares_ossl_bio_destroy(BIO *b)
{
  if (b == NULL) {
    return 0;
  }

  BIO_set_data(b, NULL);
  BIO_set_init(b, 0);
  BIO_clear_flags(b, INT_MAX);

  return 1;
}

static BIO_METHOD *ares_ossl_create_bio_method(void)
{
  BIO_METHOD *bio_method = BIO_meth_new(
    BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "c-ares tls io glue");

  BIO_meth_set_write_ex(bio_method, ares_ossl_bio_write_ex);
  BIO_meth_set_read_ex(bio_method, ares_ossl_bio_read_ex);
  BIO_meth_set_puts(bio_method, ares_ossl_bio_puts);
  BIO_meth_set_ctrl(bio_method, ares_ossl_bio_ctrl);
  BIO_meth_set_create(bio_method, ares_ossl_bio_create);
  BIO_meth_set_destroy(bio_method, ares_ossl_bio_destroy);

  return bio_method;
}

ares_status_t ares_crypto_ctx_init(ares_crypto_ctx_t **ctx)
{
  ares_status_t status;

  *ctx = ares_malloc_zero(sizeof(**ctx));
  if (*ctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  /* Create library context */
  (*ctx)->ctx = OSSL_LIB_CTX_new();
  if ((*ctx)->ctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  fprintf(stderr, "%s(): initialized library ctx\n", __FUNCTION__);
  /* Load default provider */
  (*ctx)->default_provider = OSSL_PROVIDER_load((*ctx)->ctx, "default");
  if ((*ctx)->default_provider == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  fprintf(stderr, "%s(): loaded default provider\n", __FUNCTION__);

  /* Create SSL Client CTX */
  (*ctx)->sslctx = SSL_CTX_new_ex((*ctx)->ctx, NULL, TLS_client_method());
  if ((*ctx)->sslctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  fprintf(stderr, "%s(): created new client ctx\n", __FUNCTION__);

  /* Load root certificates into client ctx */
  status = ares_ossl_load_caroots((*ctx)->sslctx, (*ctx)->ctx);
  if (status != ARES_SUCCESS) {
    goto done;
  }
  fprintf(stderr, "%s(): loaded ca certificates\n", __FUNCTION__);

  SSL_CTX_set_min_proto_version((*ctx)->sslctx, TLS1_2_VERSION);
  SSL_CTX_set_session_cache_mode((*ctx)->sslctx, SSL_SESS_CACHE_CLIENT);
  SSL_CTX_set_security_level((*ctx)->sslctx, 3);
  SSL_CTX_set_verify((*ctx)->sslctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  (*ctx)->bio_method = ares_ossl_create_bio_method();
  if ((*ctx)->bio_method == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  fprintf(stderr, "%s(): created bio\n", __FUNCTION__);

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_crypto_ctx_destroy(*ctx);
    *ctx = NULL;
  }
  return status;
}

/* TLS Session stuff:
 *  Create some sort of object reference between the SSL * and the application
 *  connection context.  To do this, use SSL_set_app_data() and
 * SSL_get_app_data().
 *
 *  We also need to notify on new sessions and removed sessions with:
 *    SSL_sess_set_new_cb(ssl, new_session_cb);
 *    SSL_sess_set_remove_cb(ssl, del_session_cb);
 * SSL_set_app_data()/SSL_get_app_data()
 */


#endif