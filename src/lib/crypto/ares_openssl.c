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
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#ifdef __APPLE__
#  include <Security/Security.h>
#endif
#ifdef _WIN32
#  include <wincrypt.h>
#endif

struct ares_crypto_ctx {
  OSSL_LIB_CTX  *ctx;
  OSSL_PROVIDER *default_provider;
  SSL_CTX       *sslctx;
};

#if defined(__APPLE__)
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  CFArrayRef  anchors;
  int         ret;
  int         i;
  size_t      count = 0;
  X509_STORE *store;

  (void)libctx;

  if (ctx == NULL)
    return ARES_EFORMERR;

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
    if (dref == NULL)
      continue;

    /* DER-encoded
     *
     * CFDataGetLength will be auto converted to long by
     * the compiler (this is not undefined behavior). */
    data = CFDataGetBytePtr(dref);
    x509 = d2i_X509(NULL, &data, CFDataGetLength(dref));
    CFRelease(dref);
    if (x509 == NULL)
      continue;

    if (X509_STORE_add_cert(store, x509))
      count++;

    X509_free(x509);
  }
  CFRelease(anchors);

  if (!count) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

#elif defined(_WIN32)

/* NOTE:  OpenSSL v3.2+ supposedly you can do something like:
 *   X509_STORE *vfy = X509_STORE_new();
 *   X509_STORE_load_store_ex(vfy, "org.openssl.winstore://", (*ctx)->ctx, NULL);
 *   SSL_CTX_set1_verify_cert_store(ctx, vfy);
 *   X509_STORE_free(vfy);
 */
static ares_status_t ares_ossl_load_caroots(SSL_CTX *ctx, OSSL_LIB_CTX *libctx)
{
  HCERTSTORE     hStore;
  PCCERT_CONTEXT pContext = NULL;
  X509_STORE    *store;
  size_t         count    = 0;

  (void)libctx;

  if (ctx == NULL)
    return ARES_EFORMERR;

  hStore = CertOpenSystemStore(0, "ROOT");
  if (hStore == NULL)
    return ARES_ESERVFAIL;

  store = SSL_CTX_get_cert_store(ctx);

  while ((pContext=CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
    BYTE * const *cert = &pContext->pbCertEncoded;
    X509         *x509 = d2i_X509(NULL, M_CAST_OFF_CONST(const unsigned char **, cert), (long)pContext->cbCertEncoded);
    if (x509) {
      if (X509_STORE_add_cert(store, x509))
        count++;
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

#else

static ares_bool_t file_exists(const char *path, ares_bool_t is_directory)
{
#ifdef HAVE_STAT
  struct stat st;
  if (stat(filename, &st) != 0) {
    return ARES_FALSE;
  }
#elif defined(_WIN32)
  struct _stat st;
  if (_stat(filename, &st) != 0) {
    return ARES_FALSE;
  }
#endif
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
    "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD via port security/ca_root_nss */
    NULL
  };
  static const char * const cadirs[] = {
    "/etc/ssl/certs/", /* Ubuntu */
    "/system/etc/security/cacerts/", /* Android */
    NULL
  };
  size_t i;
  X509_STORE *x509_store = NULL;

  x509_store = X509_STORE_new();
  if (x509_store == NULL) {
    return ARES_ENOMEM;
  }

  for (i=0; i<cadirs[i] != NULL; i++) {
    if (file_exists(cadires[i], ARES_TRUE) &&
        X509_STORE_load_path(x509_store, cadirs[i]) == 1) {
      goto done;
    }
  }

  for (i=0; i<cafile_paths[i] != NULL; i++) {
    if (file_exists(cafile_paths[i], ARES_FALSE) &&
        X509_STORE_load_file_ex(x509_store, cafile_paths[i], libctx, NULL) == 1) {
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
#endif

void ares_crypto_ctx_destroy(ares_crypto_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
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
printf("%s(): initialized library ctx\n", __FUNCTION__);
  /* Load default provider */
  (*ctx)->default_provider = OSSL_PROVIDER_load((*ctx)->ctx, "default");
  if ((*ctx)->default_provider == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
printf("%s(): loaded default provider\n", __FUNCTION__);

  /* Create SSL Client CTX */
  (*ctx)->sslctx = SSL_CTX_new_ex((*ctx)->ctx, NULL, TLS_client_method());
  if ((*ctx)->sslctx == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
printf("%s(): created new client ctx\n", __FUNCTION__);

  /* Load root certificates into client ctx */
  status = ares_ossl_load_caroots((*ctx)->sslctx, (*ctx)->ctx);
  if (status != ARES_SUCCESS) {
    goto done;
  }
printf("%s(): loaded ca certificates\n", __FUNCTION__);

  SSL_CTX_set_min_proto_version((*ctx)->sslctx, TLS1_2_VERSION);
  SSL_CTX_set_session_cache_mode((*ctx)->sslctx, SSL_SESS_CACHE_CLIENT);
  SSL_CTX_set_security_level((*ctx)->sslctx, 3);
  SSL_CTX_set_verify ((*ctx)->sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_crypto_ctx_destroy(*ctx);
    *ctx = NULL;
  }
  return status;
}

/* TLS Session stuff:
 * SSL_CTX_sess_set_new_cb(sslCtx, SSLSessionCacheManager::newSessionCallback);
 *  SSL_CTX_sess_set_remove_cb(sslCtx,
                               SSLSessionCacheManager::removeSessionCallback);
 * SSL_CTX_get_ex_new_index();
 * SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg);
 * void *SSL_get_ex_data(const SSL *s, int idx);
 */


#endif
