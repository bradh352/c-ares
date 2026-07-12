/* MIT License
 *
 * Copyright (c) 2026 Brad House
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

#include "ares-test-tls-server.h"

#ifdef CARES_USE_CRYPTO

/* ========================================================================= *
 * OpenSSL server-side TLS backend (memory-BIO driven, non-blocking)
 * ========================================================================= */
#  ifdef CARES_CRYPTO_OPENSSL

#    include <openssl/ssl.h>
#    include <openssl/bio.h>
#    include <openssl/pem.h>
#    include <openssl/x509v3.h>
#    include <openssl/evp.h>
#    include <openssl/err.h>

namespace ares {
namespace test {

namespace {

/* Runtime self-signed CA + server leaf (P-256, which satisfies the client
 * backend's security level).  Mirrors the socketpair harness generator. */
X509 *MkCert(EVP_PKEY *pubkey, EVP_PKEY *signkey, X509 *issuer, long serial,
             bool is_ca)
{
  X509           *x = X509_new();
  X509_NAME      *name;
  X509_EXTENSION *ext;
  X509V3_CTX      v3ctx;

  if (x == NULL) {
    return NULL;
  }
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
  X509_gmtime_adj(X509_getm_notBefore(x), -60);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60L);
  X509_set_pubkey(x, pubkey);
  /* Build the subject name in a fresh X509_NAME and install it with the
   * setter.  As of OpenSSL 4.0 X509_get_subject_name() returns const, because
   * the cert's internal name must not be mutated in place; the old pattern of
   * adding entries directly to it is invalid there. */
  name = X509_NAME_new();
  if (name == NULL) {
    X509_free(x);
    return NULL;
  }
  X509_NAME_add_entry_by_txt(
    name, "CN", MBSTRING_ASC,
    (const unsigned char *)(is_ca ? "c-ares test CA" : "c-ares test server"),
    -1, -1, 0);
  X509_set_subject_name(x, name);
  /* Self-signed certs use the subject as the issuer.  X509_set_issuer_name()
   * takes a const name and copies it, so the const getter is fine here. */
  X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer)
                                         : name);
  X509_NAME_free(name);
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                            is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
  if (ext != NULL) {
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
  }
  if (!X509_sign(x, signkey, EVP_sha256())) {
    X509_free(x);
    return NULL;
  }
  return x;
}

class OpenSSLServerConn : public TlsServerConn {
public:
  explicit OpenSSLServerConn(SSL_CTX *ctx)
  {
    ssl_  = SSL_new(ctx);
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (ssl_ == NULL || rbio_ == NULL || wbio_ == NULL) {
      return;
    }
    /* An empty memory BIO must report "retry" rather than EOF, otherwise
     * SSL would treat an exhausted inbound buffer as a closed connection. */
    BIO_set_mem_eof_return(rbio_, -1);
    BIO_set_mem_eof_return(wbio_, -1);
    SSL_set_bio(ssl_, rbio_, wbio_); /* SSL takes ownership of both BIOs */
    SSL_set_accept_state(ssl_);
  }

  ~OpenSSLServerConn() override
  {
    if (ssl_ != NULL) {
      SSL_free(ssl_); /* also frees rbio_/wbio_ */
    }
  }

  void FeedCipher(const unsigned char *data, size_t len) override
  {
    if (len > 0 && rbio_ != NULL) {
      BIO_write(rbio_, data, (int)len);
    }
  }

  std::vector<unsigned char> DrainCipher() override
  {
    std::vector<unsigned char> out;
    unsigned char              buf[4096];
    int                        n;
    if (wbio_ == NULL) {
      return out;
    }
    while ((n = BIO_read(wbio_, buf, (int)sizeof(buf))) > 0) {
      out.insert(out.end(), buf, buf + n);
    }
    return out;
  }

  bool Handshake(bool *fatal) override
  {
    int rv;
    int err;
    *fatal = false;
    if (ssl_ == NULL) {
      *fatal = true;
      return false;
    }
    rv = SSL_do_handshake(ssl_);
    if (rv == 1) {
      established_ = true;
      return true;
    }
    err = SSL_get_error(ssl_, rv);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      return false;
    }
    *fatal = true;
    return false;
  }

  bool Established() const override
  {
    return established_;
  }

  bool ReadPlain(std::vector<unsigned char> *out, bool *closed) override
  {
    unsigned char buf[4096];
    *closed = false;
    if (ssl_ == NULL) {
      return false;
    }
    for (;;) {
      int n = SSL_read(ssl_, buf, (int)sizeof(buf));
      if (n > 0) {
        out->insert(out->end(), buf, buf + n);
        continue;
      }
      int err = SSL_get_error(ssl_, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return true;
      }
      if (err == SSL_ERROR_ZERO_RETURN) {
        *closed = true;
        return true;
      }
      return false;
    }
  }

  bool WritePlain(const unsigned char *data, size_t len) override
  {
    size_t off = 0;
    if (ssl_ == NULL) {
      return false;
    }
    while (off < len) {
      int n = SSL_write(ssl_, data + off, (int)(len - off));
      if (n <= 0) {
        return false;
      }
      off += (size_t)n;
    }
    return true;
  }

private:
  SSL *ssl_        = nullptr;
  BIO *rbio_       = nullptr;
  BIO *wbio_       = nullptr;
  bool established_ = false;
};

class OpenSSLServerCtx : public TlsServerCtx {
public:
  ~OpenSSLServerCtx() override
  {
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
    }
    if (srv_cert_ != nullptr) {
      X509_free(srv_cert_);
    }
    if (ca_cert_ != nullptr) {
      X509_free(ca_cert_);
    }
    if (srv_key_ != nullptr) {
      EVP_PKEY_free(srv_key_);
    }
    if (ca_key_ != nullptr) {
      EVP_PKEY_free(ca_key_);
    }
  }

  bool Init()
  {
    BIO  *bio;
    char *pem = nullptr;
    long  len;

    ca_key_  = EVP_EC_gen("P-256");
    srv_key_ = EVP_EC_gen("P-256");
    if (ca_key_ == nullptr || srv_key_ == nullptr) {
      return false;
    }
    ca_cert_ = MkCert(ca_key_, ca_key_, NULL, 1, true);
    if (ca_cert_ == nullptr) {
      return false;
    }
    srv_cert_ = MkCert(srv_key_, ca_key_, ca_cert_, 2, false);
    if (srv_cert_ == nullptr) {
      return false;
    }

    ctx_ = SSL_CTX_new(TLS_server_method());
    if (ctx_ == nullptr) {
      return false;
    }
    if (SSL_CTX_use_certificate(ctx_, srv_cert_) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, srv_key_) != 1) {
      return false;
    }
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

    /* Capture the CA in PEM so the client can trust it */
    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr || !PEM_write_bio_X509(bio, ca_cert_)) {
      if (bio != nullptr) {
        BIO_free(bio);
      }
      return false;
    }
    len = BIO_get_mem_data(bio, &pem);
    ca_pem_.assign(pem, pem + len);
    BIO_free(bio);
    return true;
  }

  std::unique_ptr<TlsServerConn> NewConn() override
  {
    return std::unique_ptr<TlsServerConn>(new OpenSSLServerConn(ctx_));
  }

  std::string CaPEM() const override
  {
    return ca_pem_;
  }

private:
  EVP_PKEY   *ca_key_   = nullptr;
  EVP_PKEY   *srv_key_  = nullptr;
  X509       *ca_cert_  = nullptr;
  X509       *srv_cert_ = nullptr;
  SSL_CTX    *ctx_      = nullptr;
  std::string ca_pem_;
};

}  // namespace

std::unique_ptr<TlsServerCtx> TlsServerCtx::Create()
{
  std::unique_ptr<OpenSSLServerCtx> ctx(new OpenSSLServerCtx());
  if (!ctx->Init()) {
    return nullptr;
  }
  return std::unique_ptr<TlsServerCtx>(ctx.release());
}

}  // namespace test
}  // namespace ares

#  else /* !CARES_CRYPTO_OPENSSL */

/* No server-side TLS termination is implemented for the compiled-in backend
 * yet (e.g. Schannel).  Provide a null factory so the mock DoT tests link and
 * skip gracefully until a server impl for this backend is added. */
namespace ares {
namespace test {

std::unique_ptr<TlsServerCtx> TlsServerCtx::Create()
{
  return nullptr;
}

}  // namespace test
}  // namespace ares

#  endif /* CARES_CRYPTO_OPENSSL */

#endif /* CARES_USE_CRYPTO */
