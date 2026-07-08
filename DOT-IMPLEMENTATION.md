# DNS-over-TLS (DoT) Implementation Plan

Tracking document for DoT support in c-ares (upstream feature request:
[#818](https://github.com/c-ares/c-ares/issues/818)).  This lives on the
`DoT` branch alongside the code and is updated as work progresses; checkboxes
below are the progress tracker.

## Purpose and direction

Implement DNS-over-TLS (RFC 7858) as an optional feature with no hard
dependency added to default builds:

- **Crypto abstraction layer** (`src/lib/crypto/`) so TLS backends are
  pluggable.  First backend is **OpenSSL >= 3.0**; the design leaves room for
  others later (Windows Schannel, Apple SecureTransport/Network.framework,
  rustls-ffi, wolfSSL) without touching the core.
- **Performance first-class**: the latency penalty of TLS is mitigated with
  **TLS v1.3 Early Data (0-RTT)** — the first query on a resumed session is
  sent in the ClientHello flight — combined with client-side **session
  resumption** (session cache keyed per server) and, where the OS supports
  it, **TCP Fast Open** so the early-data flight rides the SYN.  Target: a
  warm DoT query costs no more round trips than plain TCP, and close to UDP.
- **Both usage profiles of RFC 8310**: strict (authenticated: hostname
  verification against system roots) and opportunistic (encrypt if possible,
  no authentication) — strict is the default whenever an authentication name
  is configured.
- Build option: `CARES_CRYPTO` (CMake) / `--enable-crypto` (autotools), OFF
  by default.  Without it, stubs (`ares_crypto_stubs.c`) compile in and all
  TLS operations report `ARES_ENOTIMP`/`ARES_CONN_ERR_NOTIMP`.

## Current state (what exists on this branch)

The branch contains the **backend building blocks**; nothing activates them
yet — no code path sets `ARES_CONN_FLAG_TLS` or attaches a TLS session to a
connection, so the feature is inert even when compiled in.

Implemented:

- Build-system plumbing for `CARES_CRYPTO` in CMake, autotools
  (pkg-config `openssl >= 3.0.0`), and the static makefiles; `CARES_USE_CRYPTO`
  / `CARES_CRYPTO_OPENSSL` config defines; stub implementations for
  no-crypto builds.
- `ares_crypto_ctx_t` lifecycle wired into `ares_init_options()` /
  `ares_destroy()` (`channel->crypto_ctx`).
- Session cache scaffolding in `ares_crypto.c`: forward (`key -> session`)
  and reverse (`session -> key`) hashtables with key format
  `hostname@[ip]:port`, insert/remove/get, destructor hook to the backend's
  `SSL_SESSION_free`.
- OpenSSL backend (`ares_openssl.c`):
  - Own `OSSL_LIB_CTX` + default provider + client `SSL_CTX`
    (TLS >= 1.2, client session cache with new/remove callbacks,
    partial/moving-write modes, `SSL_VERIFY_PEER`).
  - CA root loading for macOS (Security framework anchors), Windows
    (`CertOpenSystemStore("ROOT")` enumeration), and unix (well-known
    ca-bundle file/dir probing).
  - Custom `BIO_METHOD` bridging OpenSSL I/O to `ares_conn_read()` /
    `ares_conn_write()`, propagating `ARES_CONN_ERR_WOULDBLOCK`.
  - Non-blocking state machine (`ares_tls_state_t`): connect, read, write,
    shutdown, with WANT_READ/WANT_WRITE state flags
    (`ares_tls_stateflag_t`).
  - TLS v1.3 Early Data primitives: `ares_tlsimp_earlydata_write()` with
    per-session `max_early_data` cap query.
- Event translation: `ares_conn_interpret_events()` remaps raw fd
  read/write events through the TLS want-flags (a TLS "write wants read"
  turns a readable fd into a logical write event); called from
  `ares_process_fds_nolock()`.
- `ares_conn_t` carries `tls` pointer and `ARES_CONN_FLAG_TLS`.

## Known defects in the current building blocks

Found in review of the branch; fix during Phase 1 (most are in code that is
currently unreachable, so nothing is user-visible today):

- [ ] `ares_crypto_ctx_init()` never creates `sess_rev`, so
      `ares_tls_session_insert()` always fails at the reverse insert —
      session caching (and therefore resumption and early data) cannot work.
- [ ] `ares_tls_session_key()`: hostname component is a `TODO` (literal
      string `"hostname"`); on internal allocation failure it returns a
      partial key instead of NULL (missing buf destroy + NULL return).
- [ ] `ares_tls_session_insert()` leaks `key` when the early parameter
      check returns `ARES_EFORMERR` (key is built before the check).
- [ ] Session refcount audit: the cache's retained reference (from the new
      callback) is dropped via `ares_htable_strvp_claim()` on removal
      without an `SSL_SESSION_free()`, which leaks a reference when a
      cached session is consumed by `ares_tlsimp_create()`.
- [ ] `ares_ossl_bio_write_ex()` sets `BIO_set_retry_read()` on
      WOULDBLOCK; must be `BIO_set_retry_write()`.
- [ ] `ares_tlsimp_create()`: `bio == NULL` sets `ARES_ENOMEM` but is
      missing `goto done`, falling through to `BIO_set_data(NULL, ...)`;
      also a `bio` leak if failure occurs before `SSL_set_bio()`.
- [ ] `ares_tlsimp_write()`: the `state == INIT` implicit-connect /
      early-data block is unreachable (guard above already rejects
      `state != ESTABLISHED`); the early-data flow needs an explicit design
      (see Phase 1) rather than being buried in write.
- [ ] `ares_tlsimp_connect()` does not set WANT_READ/WANT_WRITE state
      flags, but `ares_conn_interpret_events()` maps events for TLS
      connections *only* via those flags — fd events during the handshake
      are dropped and the handshake stalls.  Connect (and shutdown, and
      early-data write) must publish want-flags like read/write do.
- [ ] `SSL_CTX_set_read_ahead(1)` buffers TLS records inside OpenSSL:
      decrypted data can be pending with no fd readable event.  The read
      path must drain until WOULDBLOCK (and/or consult `SSL_pending()`)
      before re-arming on fd events, or responses will sit unread.
- [ ] Debug `fprintf(stderr, ...)` calls left in
      `ares_cryptoimp_ctx_init()`.
- [ ] `SSL_CTX_set_security_level(3)` rejects RSA < 3072-bit server
      certificates; several real-world resolvers still use RSA-2048.
      Decide the level (2 is the likely sweet spot) and document it.
- [ ] Windows: verify `CertOpenSystemStore(0, "ROOT")` compiles under
      `UNICODE` builds (should be `CertOpenSystemStoreA` or a `TEXT()`
      argument), and audit the const-cast on `pbCertEncoded`.
- [ ] Error mapping: `SSL_connect() == 0` returns `CONNREFUSED`
      unconditionally; certificate-verification failures should surface
      distinguishably (at minimum a debug-obtainable verify result, e.g.
      `SSL_get_verify_result()`), or diagnosing strict-mode failures will
      be miserable.

## Phase 1 — Complete the backend (connection integration)

Goal: a server flagged for TLS completes queries end-to-end (handshake,
framed query/response, graceful shutdown), with session resumption and early
data working.  All items assume the defect list above is fixed first.

### Step 0: standalone backend test harness (testability before integration)

The backend's only coupling to the rest of c-ares is the custom BIO calling
`ares_conn_read()` / `ares_conn_write()`.  Making that boundary injectable
lets every backend function be exercised in CI *before* any connection
integration exists, so the defect fixes and state-machine work get red/green
feedback immediately instead of waiting for the full hookup:

- [ ] **I/O seam**: `ares_tls_t` gets read/write callback pointers + arg
      instead of calling `ares_conn_read()`/`ares_conn_write()` directly;
      `ares_tlsimp_create()` keeps today's behavior by installing the conn
      functions, and a create-variant (or test hook) accepts explicit
      callbacks.  Zero production behavior change, tiny diff.
- [ ] **Socketpair harness (gtest, `CARES_CRYPTO=ON` leg)**: client backend
      on one end of a `socketpair()`, a plain OpenSSL *server* `SSL_CTX`
      driven directly by the test on the other end (the test binary already
      links OpenSSL in crypto builds).  Non-blocking on both ends so the
      WANT_READ/WANT_WRITE paths actually execute.  Coverage targets:
      - handshake to ESTABLISHED, want-flag publication at every state
      - framed write/read round-trip, partial/repeated writes
      - graceful shutdown, abrupt peer close, mid-handshake close
      - certificate verification success/mismatch (runtime-generated CA)
      - session resumption on a second connection (cache hit, single-use
        ticket removal)
      - TLS v1.3 Early Data: accepted (server reads 0-RTT flight) and
        rejected (`SSL_EARLY_DATA_REJECTED` -> caller replay contract)
- [ ] **Pure unit tests** (no seam needed, available as soon as defects are
      fixed): session cache insert/get/remove/claim + refcount behavior;
      `ares_conn_interpret_events()` mapping matrix (needs only a minimal
      conn struct with flags + a tls handle).
- [ ] **Live smoke check** (optional, not CI-gated): tiny dev tool or
      live-guarded test dialing a public resolver (1.1.1.1:853) through the
      seam — handshake + one framed query — to reality-check against real
      deployments before `adig` can speak DoT.

The Phase 3 mock-DoT-server work then *extends* this harness (same
runtime-generated CA and server plumbing) rather than starting from scratch.

- [ ] **Server-level TLS configuration** in `ares_server_t` /
      `ares_sconfig_t`: `use_tls` flag, TLS port (default **853**, RFC 7858),
      optional authentication name (hostname for SNI + certificate
      verification), verification mode (strict / opportunistic / insecure).
- [ ] **Connection setup**: in the conn creation path, when the server
      config says TLS, set `ARES_CONN_FLAG_TLS`, create the TLS session via
      `ares_tlsimp_create()` after socket connect starts, and drive
      `ares_tlsimp_connect()` from the process loop until ESTABLISHED
      (states already exist).  TLS implies `ARES_CONN_FLAG_TCP` framing
      (2-byte length prefix — the existing TCP framing code is reused
      unchanged above the TLS layer).
- [ ] **I/O routing**: `ares_conn_read()` / `ares_conn_write()` /
      `ares_conn_flush()` route through `ares_tlsimp_read()` /
      `ares_tlsimp_write()` when `ARES_CONN_FLAG_TLS` (the BIO underneath
      calls the raw socket paths).  Honor the OpenSSL retry contract:
      repeated `SSL_write_ex()` after WOULDBLOCK must present the same
      logical data.
- [ ] **SNI + hostname verification**: plumb the configured
      authentication name into `SSL_set_tlsext_host_name()` and
      `SSL_set1_host()` (both currently commented out).  Strict mode fails
      the connection on verification failure; opportunistic mode disables
      verification but still encrypts; with no name configured and strict
      not requested, fall back to opportunistic per RFC 8310.
- [ ] **Session cache completion**: real hostname in the session key;
      insert path exercised via the new-session callback; single-use
      tickets for TLS 1.3 (already removed on get — verify refcounts).
- [ ] **TLS v1.3 Early Data (0-RTT)**: on connection setup, if a cached
      session reports `max_early_data > 0`, serialize the first pending
      query (TCP length-prefixed) via `ares_tlsimp_earlydata_write()`
      before/with the handshake, then complete the handshake; check
      `SSL_get_early_data_status()` — on `SSL_EARLY_DATA_REJECTED` the
      query must be re-sent through the normal write path (the buffered
      outbound stream in `ares_conn_t.out_buf` makes replay natural).
      Cap at the session's early-data limit.  **Security note**: 0-RTT data
      is replayable; DNS queries are idempotent so this is acceptable
      (same rationale as DoH GET), but must be documented, and early data
      must never be enabled for future non-idempotent uses.
- [ ] **TFO interplay**: when TCP Fast Open is available, the early-data
      flight should ride the SYN payload (true 0-RTT to a warm resolver).
      Verify the existing TFO plumbing (`ARES_CONN_FLAG_TFO*`) composes
      with the TLS connect path on Linux/macOS, and degrades cleanly where
      TFO is unavailable.
- [ ] **Shutdown & teardown**: graceful `ares_tlsimp_shutdown()` on
      connection close where practical (don't block teardown on it);
      `ares_tlsimp_destroy()` in conn cleanup; interaction with
      `ARES_CONN_FLAG_NONEW` connection retirement.
- [ ] **Timeout behavior**: handshake counts against query timeout;
      confirm a stalled handshake trips the existing timeout/retry
      machinery and marks the connection failed rather than hanging.
- [ ] **EDNS considerations for DoT** (nice-to-have, may defer):
      padding (RFC 7830 / policy RFC 8467) and edns-tcp-keepalive
      (RFC 7828) to hold connections open — c-ares already has an
      idle-connection concept for TCP to piggyback on.

## Phase 2 — Configuration hookup

### Manual configuration (URI scheme)

`ares_set_servers_csv()` already accepts `dns://host:port?tcpport=N` URIs
(parsed by `parse_nameserver_uri()` via `ares_uri`, written back by
`ares_get_server_addr_uri()`).  Extend with a TLS scheme:

- [ ] Scheme **`dns+tls://`**, default port 853.  Proposed query keys:
  - `hostname=<name>` — authentication name (SNI + certificate
    verification); presence implies strict mode.
  - `verify=strict|opportunistic|none` — explicit profile override
    (`none` = opportunistic without even attempting verification;
    exact split TBD during implementation).
  - Example: `dns+tls://1.1.1.1?hostname=one.one.one.one`
  - IP is still the URI host (c-ares dials IPs, never resolves a resolver
    name via itself); link-local `%iface` continues to work.
- [ ] Round-trip: `ares_get_servers_csv()` emits `dns+tls://` for TLS
      servers (existing `ares_server_use_uri()` logic extended).
- [ ] Duplicate-server detection / server sort must treat
      `(ip, port, tls, hostname)` as the identity, not just `(ip, port)`.
- [ ] `adig -s dns+tls://...` works for free once CSV parsing does; add a
      note to adig docs.
- [ ] Docs: `ares_set_servers_csv.3` scheme table; `FEATURES.md` entry.
- [ ] Decide public API surface beyond CSV: none required initially
      (options struct untouched -> no ABI concern).  A channel-level knob
      for "opportunistic TLS for all servers" can come later.

### Host OS configuration

- [ ] **Android**: Private DNS is the one mainstream OS DoT deployment.
      `ares_android.c` already uses ConnectivityManager/LinkProperties via
      JNI; extend with `LinkProperties.isPrivateDnsActive()` and
      `getPrivateDnsServerName()` (API 28+).  Hostname-only mode requires
      bootstrap resolution of the resolver name over Do53 — decide whether
      to support that or only apply DoT when the OS supplies both.
- [ ] **systemd-resolved** (Linux): `DNSOverTLS=yes|opportunistic` in
      `resolved.conf`/drop-ins and per-link settings.  Machines using the
      127.0.0.53 stub get DoT transparently and c-ares should *not*
      second-guess; the interesting case is `resolv.conf` pointing at real
      upstreams while resolved is configured for DoT.  Investigate reading
      the config (file parse vs D-Bus/varlink query) — likely follow-up,
      not initial scope.
- [ ] **Windows**: no OS-level DoT as of Win11 (native support is DoH:
      `Dnscache\Parameters\DohInterfaceSettings`).  Nothing to read for
      DoT; revisit if Microsoft ships DoT.  (Reading DoH config becomes
      relevant only with a future DoH transport.)
- [ ] **macOS**: encrypted-DNS is configured via profiles /
      `NEDNSSettingsManager`; the private `dnsinfo.h` snapshot c-ares uses
      does not obviously expose it.  Investigate `scutil --dns` /
      newer dnsinfo fields; likely out of initial scope.
- [ ] **DDR (RFC 9462/9463)** — opt-in upgrade path: query
      `_dns.resolver.arpa` SVCB (c-ares already parses SVCB/HTTPS RRs) to
      discover the Do53 resolver's designated DoT endpoint (`alpn=dot`,
      port, target name), verify per RFC 9462 §4.2 (certificate must cover
      the unencrypted resolver IP), and upgrade.  This is the
      standards-track answer to "the OS only gave us an IP" and probably
      the highest-value auto-config item; needs an explicit opt-in flag.
- [ ] Ordering/failover policy when a channel mixes DoT and Do53 servers
      (strict DoT server unreachable -> fall back to plaintext or fail?
      Strict must not silently fall back; opportunistic may).

## Phase 3 — Testing (full-stack; extends the Phase 1 Step 0 harness)

Backend-level coverage (state machine, resumption, early data accept/reject)
already exists from Phase 1 Step 0; this phase covers the integrated stack.

- [ ] **Mock DoT server**: extend the gmock test server with a TLS
      variant when built `CARES_CRYPTO=ON`, reusing the Step 0
      runtime-generated CA/server-cert plumbing, with a test hook to
      inject the CA (or `verify=none`) into the client ctx.  Covers via
      real `ares_query()` traffic: handshake, framed query/response,
      server-initiated close, mid-handshake close, handshake timeout,
      certificate mismatch in strict vs opportunistic mode, session
      resumption on second connection.
- [ ] **Early data through the channel**: verify the second connection
      sends the first query as early data (observable via server-side
      `SSL_read_early_data()`), and the rejection path re-sends the query
      correctly — no lost or duplicated query, correct response
      correlation.
- [ ] **Event-loop integration**: run the mock-TLS suite under all event
      backends (epoll/kqueue/poll/select/IOCP configurations CI already
      exercises) — the want-flag remapping is exactly the kind of thing
      that behaves differently per backend.
- [ ] **Live tests** (opt-in, like existing live suite): 1.1.1.1 /
      8.8.8.8 / 9.9.9.9 with their hostnames, strict mode.
- [ ] **CI**: add `CARES_CRYPTO=ON` legs (Ubuntu, macOS, Windows+OpenSSL),
      including ASAN and the Werror gate; keep a no-crypto leg guarding
      the stubs. `reuse lint` for new files.
- [ ] **Fuzzing**: framing above TLS is the existing TCP framing (already
      fuzzed); no new parser surface expected.  Revisit if a config-string
      surface (URI query keys) grows — extend the existing URI fuzzing
      if/where applicable.

## Open questions / decisions to make

- OpenSSL security level (3 today — breaks RSA-2048 resolvers; 2?).
- ALPN: send `dot` (registered ID)?  Required for DDR-discovered
  endpoints; harmless otherwise.  Probably yes, unconditionally.
- Default when only `dns+tls://IP` given with no hostname: opportunistic
  encrypt-only, or verify-cert-chain-without-name?  (RFC 8310 allows both;
  DDR §4.2 wants IP-in-SAN verification which OpenSSL supports via
  `X509_VERIFY_PARAM_set1_ip`.)
- Whether `ares_reinit()` should preserve TLS sessions (crypto ctx is
  per-channel and survives reinit today — verify).
- Session cache size bound / expiry (currently unbounded, per-channel;
  fine for typical few-server channels, but put a cap on it).
- Second crypto backend priority (Schannel would remove the OpenSSL
  dependency on the platform where distribution is hardest).

## Progress log

- 2026-07-08: branch squashed onto current main (`513601c3`); this
  document added.  State: building blocks only, feature inert; defect list
  and phased plan recorded above.
- 2026-07-08: added Phase 1 Step 0 — standalone backend test harness via an
  I/O seam at the BIO boundary, so the backend is fully testable in CI
  before connection integration begins.
