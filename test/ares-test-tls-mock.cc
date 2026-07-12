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

/* Focused DNS-over-TLS edge-case tests driven through the gmock mock server.
 *
 * Unlike the socketpair backend harness (ares-test-tls.cc), these run a real
 * ares_gethostbyname() through the full process loop against a MockServer that
 * terminates TLS with whichever crypto backend c-ares was built against.  That
 * means the same tests exercise the OpenSSL and Schannel client backends
 * without either needing the other's library.  We only sanity check the
 * edge cases specific to TLS, not the whole query suite. */

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

/* Needs the crypto subsystem and symbol visibility into the library
 * (ares_tls_set_cadata / channel->crypto_ctx).  Backend-agnostic and not
 * POSIX-only: runs anywhere the mock server's TLS termination is available. */
#if defined(CARES_USE_CRYPTO) && !defined(CARES_SYMBOL_HIDING)

#  include <sstream>

namespace ares {
namespace test {

class MockDoTServerTest : public LibraryTest {
public:
  MockDoTServerTest()
  {
    tls_ctx_ = TlsServerCtx::Create();
    if (tls_ctx_ == nullptr) {
      return;
    }
    server_.reset(new testing::NiceMock<MockServer>(AF_INET, mock_port));
    server_->SetTLSCtx(tls_ctx_);
  }

  ~MockDoTServerTest()
  {
    if (channel_ != nullptr) {
      ares_destroy(channel_);
    }
  }

  bool HasBackend() const
  {
    return tls_ctx_ != nullptr;
  }

  /* Build a channel pointed at the mock DoT server.  trust=true injects the
   * server's CA into the client trust store; verify selects the URI
   * verification mode. */
  bool BuildChannel(bool trust, const char *verify)
  {
    struct ares_options opts;
    int                 optmask = 0;
    char                csv[160];

    memset(&opts, 0, sizeof(opts));
    /* Deterministic: no search domains, short timeout, no query cache */
    opts.ndomains        = 0;
    optmask             |= ARES_OPT_DOMAINS;
    opts.timeout         = 1000;
    optmask             |= ARES_OPT_TIMEOUTMS;
    opts.tries           = 2;
    optmask             |= ARES_OPT_TRIES;
    opts.qcache_max_ttl  = 0;
    optmask             |= ARES_OPT_QUERY_CACHE;

    if (ares_init_options(&channel_, &opts, optmask) != ARES_SUCCESS) {
      return false;
    }

    if (trust) {
      std::string ca = tls_ctx_->CaPEM();
      if (ares_tls_set_cadata(channel_->crypto_ctx,
                              (const unsigned char *)ca.data(),
                              ca.size()) != ARES_SUCCESS) {
        return false;
      }
    }

    snprintf(csv, sizeof(csv), "dns+tls://127.0.0.1:%u?verify=%s",
             (unsigned int)server_->tcpport(), verify);
    return ares_set_servers_csv(channel_, csv) == ARES_SUCCESS;
  }

  void Process(unsigned int cancel_ms = 0)
  {
    using namespace std::placeholders;
    ProcessWork(channel_, std::bind(&MockServer::fds, server_.get()),
                std::bind(&MockServer::ProcessFD, server_.get(), _1),
                cancel_ms);
  }

protected:
  std::shared_ptr<TlsServerCtx>                  tls_ctx_;
  std::unique_ptr<testing::NiceMock<MockServer>> server_;
  ares_channel_t                                *channel_ = nullptr;
};

/* Handshake + framed query/response over the encrypted channel. */
TEST_F(MockDoTServerTest, Query)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'dot.example.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

/* Strict verification against an untrusted server cert must fail the query,
 * not fall back to plaintext or hang. */
TEST_F(MockDoTServerTest, VerifyFailStrict)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(false, "strict"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(ARES_SUCCESS, result.status_);
}

/* Opportunistic mode encrypts without verifying, so an untrusted cert still
 * yields a successful query. */
TEST_F(MockDoTServerTest, Opportunistic)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(false, "opportunistic"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 5, 6, 7, 8 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
}

/* Server closes the connection after replying; a subsequent query must open a
 * fresh connection, re-handshake and still succeed. */
TEST_F(MockDoTServerTest, ServerCloseThenReconnect)
{
  if (!HasBackend()) {
    GTEST_SKIP() << "no mock DoT server backend for this crypto build";
  }
  ASSERT_TRUE(BuildChannel(true, "strict"));

  DNSPacket rsp;
  rsp.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dot.example.com", T_A))
    .add_answer(new DNSARR("dot.example.com", 100, { 1, 2, 3, 4 }));
  ON_CALL(*server_, OnRequest("dot.example.com", T_A))
    .WillByDefault(SetReply(server_.get(), &rsp));

  server_->DisconnectAfterReply();
  HostResult r1;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r1);
  Process();
  EXPECT_TRUE(r1.done_);
  EXPECT_EQ(ARES_SUCCESS, r1.status_);

  HostResult r2;
  ares_gethostbyname(channel_, "dot.example.com", AF_INET, HostCallback, &r2);
  Process();
  EXPECT_TRUE(r2.done_);
  EXPECT_EQ(ARES_SUCCESS, r2.status_);
}

}  // namespace test
}  // namespace ares

#endif /* CARES_USE_CRYPTO && !CARES_SYMBOL_HIDING */
