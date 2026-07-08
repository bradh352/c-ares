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

/* Standalone tests for the TLS backend used by DNS-over-TLS support */

#include "ares-test.h"

extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_private.h"
}

/* The harness requires the OpenSSL crypto backend (the peer end of the
 * socketpair is driven with OpenSSL directly), symbol visibility into the
 * library, and socketpair() (POSIX-only for now; a loopback TCP pair can
 * lift that later) */
#if defined(CARES_USE_CRYPTO) && defined(CARES_CRYPTO_OPENSSL) && \
  !defined(CARES_SYMBOL_HIDING) && !defined(_WIN32)
#  define CARES_TEST_TLS_HARNESS 1
#  include <openssl/ssl.h>
#  include <openssl/pem.h>
#  include <openssl/x509v3.h>
#  include <openssl/evp.h>
#  include <sys/socket.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace ares {
namespace test {

#ifdef CARES_TEST_TLS_HARNESS

/* Drives the client TLS backend over one end of a socketpair against a
 * plain OpenSSL server on the other end, through a minimal fake conn, so
 * the production BIO -> ares_conn_read()/ares_conn_write() path is
 * exercised without requiring any connection-integration code. */

static X509 *TlsTestMkCert(EVP_PKEY *pubkey, EVP_PKEY *signkey, X509 *issuer,
                           long serial, bool is_ca)
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
  name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(
    name, "CN", MBSTRING_ASC,
    (const unsigned char *)(is_ca ? "c-ares test CA" : "c-ares test server"),
    -1, -1, 0);
  X509_set_issuer_name(x,
                       issuer != NULL ? X509_get_subject_name(issuer) : name);
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

class TLSHarness {
public:
  TLSHarness() = default;

  ~TLSHarness()
  {
    if (tls_ != NULL) {
      ares_tlsimp_destroy(tls_);
    }
    if (sssl_ != NULL) {
      SSL_free(sssl_);
    }
    if (sctx_ != NULL) {
      SSL_CTX_free(sctx_);
    }
    CloseFd(0);
    CloseFd(1);
    if (channel_ != NULL) {
      ares_destroy(channel_);
    }
    if (srv_cert_ != NULL) {
      X509_free(srv_cert_);
    }
    if (srv_key_ != NULL) {
      EVP_PKEY_free(srv_key_);
    }
    if (ca_cert_ != NULL) {
      X509_free(ca_cert_);
    }
    if (ca_key_ != NULL) {
      EVP_PKEY_free(ca_key_);
    }
  }

  /* trust_ca == false leaves the generated CA out of the client store, so
   * certificate verification must fail */
  bool Init(bool trust_ca)
  {
    /* Runtime-generated ECDSA P-256 CA + server cert (P-256 satisfies the
     * backend's security level regardless of where that decision lands) */
    ca_key_  = EVP_EC_gen("P-256");
    srv_key_ = EVP_EC_gen("P-256");
    if (ca_key_ == NULL || srv_key_ == NULL) {
      return false;
    }
    ca_cert_ = TlsTestMkCert(ca_key_, ca_key_, NULL, 1, true);
    if (ca_cert_ == NULL) {
      return false;
    }
    srv_cert_ = TlsTestMkCert(srv_key_, ca_key_, ca_cert_, 2, false);
    if (srv_cert_ == NULL) {
      return false;
    }

    if (ares_init(&channel_) != ARES_SUCCESS) {
      return false;
    }

    if (trust_ca) {
      BIO  *bio = BIO_new(BIO_s_mem());
      char *pem = NULL;
      long  len;
      bool  ok;
      if (bio == NULL || !PEM_write_bio_X509(bio, ca_cert_)) {
        BIO_free(bio);
        return false;
      }
      len = BIO_get_mem_data(bio, &pem);
      ok  = ares_tls_set_cadata(channel_->crypto_ctx,
                                (const unsigned char *)pem,
                                (size_t)len) == ARES_SUCCESS;
      BIO_free(bio);
      if (!ok) {
        return false;
      }
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_) != 0) {
      return false;
    }
    if (fcntl(sv_[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(sv_[1], F_SETFL, O_NONBLOCK) != 0) {
      return false;
    }

    /* Minimal fake server/conn: everything ares_conn_read()/
     * ares_conn_write() and the session-cache key derivation consult */
    memset(&server_, 0, sizeof(server_));
    server_.channel                = channel_;
    server_.addr.family            = AF_INET;
    server_.addr.addr.addr4.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    server_.udp_port               = 853;
    server_.tcp_port               = 853;

    memset(&conn_, 0, sizeof(conn_));
    conn_.server = &server_;
    conn_.fd     = sv_[0];
    conn_.flags =
      (ares_conn_flags_t)(ARES_CONN_FLAG_TCP | ARES_CONN_FLAG_TLS);
    conn_.state_flags = ARES_CONN_STATE_CONNECTED;

    if (ares_tls_create(&tls_, channel_->crypto_ctx, &conn_) !=
        ARES_SUCCESS) {
      return false;
    }
    conn_.tls = tls_;

    /* Plain OpenSSL server on the other end of the pair */
    sctx_ = SSL_CTX_new(TLS_server_method());
    if (sctx_ == NULL) {
      return false;
    }
    if (SSL_CTX_use_certificate(sctx_, srv_cert_) != 1 ||
        SSL_CTX_use_PrivateKey(sctx_, srv_key_) != 1) {
      return false;
    }
    SSL_CTX_set_min_proto_version(sctx_, TLS1_2_VERSION);
    sssl_ = SSL_new(sctx_);
    if (sssl_ == NULL) {
      return false;
    }
    if (SSL_set_fd(sssl_, sv_[1]) != 1) {
      return false;
    }
    SSL_set_accept_state(sssl_);
    return true;
  }

  /* Pump both ends until established or client-side failure.  Returns the
   * last client status. */
  ares_conn_err_t PumpHandshake()
  {
    ares_conn_err_t cerr = ARES_CONN_ERR_WOULDBLOCK;
    int             i;

    for (i = 0; i < 100; i++) {
      if (ares_tlsimp_get_state(tls_) != ARES_TLS_STATE_ESTABLISHED) {
        cerr = ares_tlsimp_connect(tls_);
        if (cerr != ARES_CONN_ERR_SUCCESS &&
            cerr != ARES_CONN_ERR_WOULDBLOCK) {
          return cerr;
        }
      }
      if (!srv_done_) {
        int rv = SSL_accept(sssl_);
        if (rv == 1) {
          srv_done_ = true;
        } else {
          int err = SSL_get_error(sssl_, rv);
          if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            /* Server handshake failed (e.g. client sent a fatal alert);
             * keep pumping so the client surfaces its own error */
            srv_fail_ = true;
          }
        }
      }
      if (srv_done_ &&
          ares_tlsimp_get_state(tls_) == ARES_TLS_STATE_ESTABLISHED) {
        return ARES_CONN_ERR_SUCCESS;
      }
    }
    return ARES_CONN_ERR_CONNTIMEDOUT;
  }

  bool ServerRead(unsigned char *buf, size_t buf_len, size_t *read_len)
  {
    int i;
    for (i = 0; i < 100; i++) {
      int rv = SSL_read_ex(sssl_, buf, buf_len, read_len);
      if (rv == 1) {
        return true;
      }
      int err = SSL_get_error(sssl_, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        return false;
      }
    }
    return false;
  }

  bool ServerWrite(const unsigned char *buf, size_t len)
  {
    size_t written = 0;
    int    i;
    for (i = 0; i < 100; i++) {
      int rv = SSL_write_ex(sssl_, buf, len, &written);
      if (rv == 1) {
        return written == len;
      }
      int err = SSL_get_error(sssl_, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        return false;
      }
    }
    return false;
  }

  ares_conn_err_t ClientRead(unsigned char *buf, size_t *len)
  {
    size_t          want = *len;
    ares_conn_err_t err  = ARES_CONN_ERR_WOULDBLOCK;
    int             i;
    for (i = 0; i < 100; i++) {
      *len = want;
      err  = ares_tlsimp_read(tls_, buf, len);
      if (err != ARES_CONN_ERR_WOULDBLOCK) {
        return err;
      }
    }
    return err;
  }

  void CloseFd(int idx)
  {
    if (sv_[idx] != -1) {
      close(sv_[idx]);
      sv_[idx] = -1;
    }
  }

  ares_channel_t *channel_  = nullptr;
  ares_tls_t     *tls_      = nullptr;
  ares_server_t   server_;
  ares_conn_t     conn_;
  int             sv_[2]    = { -1, -1 };
  SSL_CTX        *sctx_     = nullptr;
  SSL            *sssl_     = nullptr;
  bool            srv_done_ = false;
  bool            srv_fail_ = false;
  EVP_PKEY       *ca_key_   = nullptr;
  X509           *ca_cert_  = nullptr;
  EVP_PKEY       *srv_key_  = nullptr;
  X509           *srv_cert_ = nullptr;
};

TEST_F(LibraryTest, CryptoTLSHandshakeIO) {
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());
  EXPECT_EQ(ARES_TLS_STATE_ESTABLISHED, ares_tlsimp_get_state(h.tls_));

  /* client -> server (TCP-framed DNS shape, but the layer is opaque bytes) */
  unsigned char query[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
  size_t        wlen    = sizeof(query);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_write(h.tls_, query, &wlen));
  EXPECT_EQ(sizeof(query), wlen);

  unsigned char sbuf[64];
  size_t        sread = 0;
  ASSERT_TRUE(h.ServerRead(sbuf, sizeof(sbuf), &sread));
  ASSERT_EQ(sizeof(query), sread);
  EXPECT_EQ(0, memcmp(query, sbuf, sread));

  /* server -> client */
  unsigned char resp[] = { 0x00, 0x03, 'a', 'c', 'k' };
  ASSERT_TRUE(h.ServerWrite(resp, sizeof(resp)));

  unsigned char cbuf[64];
  size_t        clen = sizeof(cbuf);
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.ClientRead(cbuf, &clen));
  ASSERT_EQ(sizeof(resp), clen);
  EXPECT_EQ(0, memcmp(resp, cbuf, clen));

  /* graceful shutdown */
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, ares_tlsimp_shutdown(h.tls_));
  EXPECT_EQ(ARES_TLS_STATE_DISCONNECTED, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSVerifyFail) {
  TLSHarness h;
  /* CA not trusted by the client: certificate verification must fail and
   * the connection must not silently proceed (strict by default) */
  ASSERT_TRUE(h.Init(false));

  ares_conn_err_t err = h.PumpHandshake();
  EXPECT_NE(ARES_CONN_ERR_SUCCESS, err);
  EXPECT_NE(ARES_CONN_ERR_WOULDBLOCK, err);
  EXPECT_EQ(ARES_TLS_STATE_ERROR, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSWantFlags) {
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  /* First connect: ClientHello flushed, handshake now needs the server's
   * reply, so progressing requires a readable socket for either logical
   * operation */
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_connect(h.tls_));
  EXPECT_EQ((unsigned int)(ARES_TLS_SF_READ_WANTREAD |
                           ARES_TLS_SF_WRITE_WANTREAD),
            (unsigned int)ares_tlsimp_get_stateflag(h.tls_));

  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Established, nothing pending: read wants a readable socket, and the
   * write direction is unaffected */
  unsigned char b[16];
  size_t        blen = sizeof(b);
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_read(h.tls_, b, &blen));
  EXPECT_EQ((unsigned int)ARES_TLS_SF_READ_WANTREAD,
            (unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
              (unsigned int)ARES_TLS_SF_READ);
  EXPECT_EQ(0, (unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
                 (unsigned int)ARES_TLS_SF_WRITE);

  /* Flood the socketpair until the kernel buffer fills: write must report
   * it wants a writable socket */
  {
    static unsigned char big[4096];
    ares_conn_err_t      werr = ARES_CONN_ERR_SUCCESS;
    int                  i;
    memset(big, 'x', sizeof(big));
    for (i = 0; i < 1000; i++) {
      size_t wl = sizeof(big);
      werr      = ares_tlsimp_write(h.tls_, big, &wl);
      if (werr != ARES_CONN_ERR_SUCCESS) {
        break;
      }
    }
    EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, werr);
    EXPECT_TRUE((unsigned int)ares_tlsimp_get_stateflag(h.tls_) &
                (unsigned int)ARES_TLS_SF_WRITE_WANTWRITE);
  }
}

TEST_F(LibraryTest, CryptoTLSPeerClose) {
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));
  EXPECT_EQ(ARES_CONN_ERR_SUCCESS, h.PumpHandshake());

  /* Abrupt peer close (no close_notify): reads must surface a hard error,
   * not hang or claim success */
  h.CloseFd(1);

  unsigned char buf[16];
  size_t        blen = sizeof(buf);
  ares_conn_err_t err = h.ClientRead(buf, &blen);
  EXPECT_NE(ARES_CONN_ERR_SUCCESS, err);
  EXPECT_NE(ARES_CONN_ERR_WOULDBLOCK, err);
  EXPECT_EQ(ARES_TLS_STATE_ERROR, ares_tlsimp_get_state(h.tls_));
}

TEST_F(LibraryTest, CryptoTLSInterpretEvents) {
  TLSHarness h;
  ASSERT_TRUE(h.Init(true));

  /* Register the fake conn the same way the production register path does,
   * so ares_conn_from_fd() resolves it */
  ares_llist_t      *l    = ares_llist_create(NULL);
  ASSERT_NE(nullptr, l);
  ares_llist_node_t *node = ares_llist_insert_last(l, &h.conn_);
  ASSERT_NE(nullptr, node);
  ASSERT_TRUE(
    ares_htable_asvp_insert(h.channel_->connnode_by_socket, h.conn_.fd, node));

  ares_fd_events_t  ev;
  ares_fd_events_t *out = NULL;
  size_t            n;

  /* Handshake blocked wanting read: a readable fd maps to both logical
   * read and write events; a writable fd maps to nothing */
  EXPECT_EQ(ARES_CONN_ERR_WOULDBLOCK, ares_tlsimp_connect(h.tls_));

  ev.fd     = h.conn_.fd;
  ev.events = ARES_FD_EVENT_READ;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  ASSERT_EQ((size_t)1, n);
  EXPECT_EQ(h.conn_.fd, out[0].fd);
  EXPECT_EQ((unsigned int)(ARES_FD_EVENT_READ | ARES_FD_EVENT_WRITE),
            out[0].events);
  ares_free(out);
  out = NULL;

  ev.events = ARES_FD_EVENT_WRITE;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  ASSERT_EQ((size_t)1, n);
  EXPECT_EQ((unsigned int)ARES_FD_EVENT_NONE, out[0].events);
  ares_free(out);
  out = NULL;

  /* Unknown fd: dropped entirely */
  ev.fd     = h.sv_[1];
  ev.events = ARES_FD_EVENT_READ;
  n         = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  EXPECT_EQ((size_t)0, n);
  ares_free(out);
  out = NULL;

  /* Non-TLS conn: events pass through untouched */
  h.conn_.flags = ARES_CONN_FLAG_TCP;
  ev.fd         = h.conn_.fd;
  ev.events     = ARES_FD_EVENT_READ;
  n             = 1;
  ASSERT_EQ(ARES_SUCCESS,
            ares_conn_interpret_events(&out, h.channel_, &ev, &n));
  ASSERT_EQ((size_t)1, n);
  EXPECT_EQ((unsigned int)ARES_FD_EVENT_READ, out[0].events);
  ares_free(out);
  out = NULL;
  h.conn_.flags =
    (ares_conn_flags_t)(ARES_CONN_FLAG_TCP | ARES_CONN_FLAG_TLS);

  /* Deregister before the channel is destroyed (ares_destroy() asserts the
   * table is empty) */
  ares_htable_asvp_remove(h.channel_->connnode_by_socket, h.conn_.fd);
  ares_llist_destroy(l);
}

#endif /* CARES_TEST_TLS_HARNESS */


}  // namespace test
}  // namespace ares
