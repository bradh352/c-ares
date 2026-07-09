# DNS-over-TLS (DoT) Implementation Plan

Tracking document for DoT support in c-ares (upstream feature request:
[#818](https://github.com/c-ares/c-ares/issues/818)).  This lives on the
`DoT` branch alongside the code and is updated as work progresses; checkboxes
below are the progress tracker.

Convention: references to this document, its phase/step numbering, or other
planning artifacts belong here and in commit messages only — never in code
comments, which must stand on their own (planning references in code grow
stale the moment the plan moves).

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
currently unreachable, so nothing is user-visible today).  Items tagged
**[pre-harness]** are the minimal set that must land before the Step 0
harness can produce signal; everything else is verified *by* the harness or
deferred to its phase:

- [x] **[pre-harness]** `ares_crypto_ctx_init()` never creates `sess_rev`, so
      `ares_tls_session_insert()` always fails at the reverse insert —
      session caching (and therefore resumption and early data) cannot work.
- [x] `ares_tls_session_key()`: partial-key-on-allocation-failure fixed
      (NULL returned; a partial key could alias another server's
      sessions).  The misleading `"hostname"` literal is gone; the
      component is blank until server-level TLS configuration provides an
      authentication name (tracked by the Phase 1 config item).
- [x] `ares_tls_session_insert()` leaked `key` when the early parameter
      check returned `ARES_EFORMERR`.  Fixed.
- [x] Session refcount audit: the cache's retained reference (from the new
      callback) was dropped via `ares_htable_strvp_claim()` on removal
      without an `SSL_SESSION_free()`, leaking a reference when a cached
      session was consumed by `ares_tlsimp_create()`.  Fixed:
      `ares_tls_session_remove()` now removes (releasing the cache's
      reference through the table destructor) instead of claiming.
- [x] Teardown ordering crash (found by the test harness on first run):
      `ares_crypto_ctx_destroy()` destroyed the session tables before the
      backend, but `SSL_CTX_free()` flushes the session cache and fires the
      remove callback, which walks those tables — use-after-free on every
      channel destroy that had cached a session.  Fixed: backend torn down
      first.
- [x] **[pre-harness]** `ares_ossl_bio_write_ex()` sets
      `BIO_set_retry_read()` on WOULDBLOCK; must be
      `BIO_set_retry_write()`.
- [x] **[pre-harness]** `ares_tlsimp_create()`: `bio == NULL` sets
      `ARES_ENOMEM` but is missing `goto done`, falling through to
      `BIO_set_data(NULL, ...)`; also a `bio` leak if failure occurs before
      `SSL_set_bio()`.
- [x] `ares_tlsimp_write()`: the unreachable `state == INIT`
      implicit-connect / early-data block is removed.  The early-data flow
      is explicit: `ares_tlsimp_earlydata_write()` before/with
      `ares_tlsimp_connect()`, then `ares_tlsimp_earlydata_accepted()`
      decides requeue; write requires an established connection and
      documents the same-data retry contract (pinned by the partial-write
      test).
- [x] `ares_tlsimp_connect()` did not set WANT_READ/WANT_WRITE state
      flags, but `ares_conn_interpret_events()` maps events for TLS
      connections *only* via those flags — fd events during the handshake
      were dropped and the handshake would stall.  Fixed: connect,
      shutdown, and early-data write now publish want-flags (connect and
      shutdown publish both logical directions since handshake progress
      gates everything).
- [x] `SSL_CTX_set_read_ahead(1)` buffers TLS records inside OpenSSL:
      decrypted data can be pending with no fd readable event.  Resolved
      at the backend level with `ares_tlsimp_get_read_pending()`
      (`SSL_has_pending()`) plus the documented drain contract, pinned by
      the CryptoTLSReadPending test.  The Phase 1 I/O-routing item must
      honor it in the process loop.
- [x] **[pre-harness]** Debug `fprintf(stderr, ...)` calls left in
      `ares_cryptoimp_ctx_init()`.
- [x] `SSL_CTX_set_security_level(3)` — decided: **level 2**.  The harness
      proved level 3 empirically unusable for this feature: OpenSSL
      disables session tickets at level 3, which forecloses TLSv1.3
      resumption and therefore 0-RTT early data entirely (it also rejects
      the RSA-2048 certificates still common on public resolvers).
- [x] `SSL_CTX_remove_session()` misuse (found by the resumption test):
      it not only removes the session from the ctx cache, it marks the
      session **non-resumable**, so the single-use implementation in
      `ares_tlsimp_create()` was defeating the resumption it had just set
      up (and early-data writes hard-failed).  Fixed: single-use is now
      enforced by removing from the c-ares cache only.
- [x] Stale reverse-table entry on ticket replacement (found by the
      resumption test): inserting a second ticket under the same key
      replaced the forward entry but left the old session's reverse entry;
      a later backend removal callback for the old session (e.g. OpenSSL
      evicting a session after an unclean close) would then tear down the
      *new* session's forward entry.  Fixed in
      `ares_tls_session_insert()`.
- [x] Windows cert-store loading could never have compiled: it used a
      `M_CAST_OFF_CONST` macro that does not exist in this tree, and the
      cast pattern let `d2i_X509` advance (mutate) the enumeration
      context's `pbCertEncoded` field.  Rewritten with a local pointer and
      `CertOpenSystemStoreA` (UNICODE-safe); crypt32 linked in CMake and
      autotools.  Verified: the MSYS2 crypto CI legs compile, link and
      test it (PR #1252 green).
- [x] Error mapping reworked: certificate-verification failures return
      the new `ARES_CONN_ERR_SECURITY` (via `SSL_get_verify_result()`,
      pinned by the verify-fail test); a clean TLS close_notify maps to
      `ARES_CONN_ERR_CONNCLOSED` + DISCONNECTED state instead of a generic
      error (normal DoT server idle-close behavior, pinned by the
      graceful-close test); the `SSL_connect() == 0` special case is
      folded into the standard error path.

## Phase 1 — Complete the backend (connection integration)

Goal: a server flagged for TLS completes queries end-to-end (handshake,
framed query/response, graceful shutdown), with session resumption and early
data working.  All items assume the defect list above is fixed first.

### Step 0: standalone backend test harness (testability before integration)

The backend's only coupling to the rest of c-ares is the custom BIO calling
`ares_conn_read()` / `ares_conn_write()`, and those only require
`conn->server->channel` (socket functions), `conn->fd`, and correct
`flags`/`state_flags`.  No production changes are needed to test the backend
standalone: the fixture creates a real channel via `ares_init()`, a minimal
fake `ares_server_t`/`ares_conn_t` (internal-struct access is established
practice in `ares-test-internal.cc`) around one end of a `socketpair()`,
and calls `ares_tlsimp_create()` on it — exercising the *production*
BIO -> `ares_conn_*` -> `ares_socket_*` path, error mapping included, before
any connection-integration code exists.  Every defect fix gets red/green
feedback in CI immediately.

Prerequisites (beyond the **[pre-harness]** defect fixes above):

- [x] **Test-reachable entry point**: `struct ares_crypto_ctx` is opaque
      outside `ares_crypto.c`, so a test holding `channel->crypto_ctx`
      cannot reach the `imp_ctx` that `ares_tlsimp_create()` takes.  Add a
      thin generic wrapper (e.g. `ares_tls_create(crypto_ctx, conn)`)
      dereferencing internally — the Phase 1 connection integration needs
      this entry point anyway, so it is not test-only scaffolding.
- [x] **Test build plumbing**: link
      OpenSSL into `arestest` when
      `CARES_CRYPTO=ON` (the harness drives a server `SSL_CTX` directly)
      and add a `CARES_CRYPTO=ON` CI leg (ubuntu first; ASAN variant early
      since the harness is what demonstrates the session refcount leak).
      Use ECDSA P-256 for generated test certs so the current security
      level 3 setting is satisfied regardless of how that decision lands.

- [x] **Socketpair harness (gtest, `CARES_CRYPTO=ON` leg)** — complete, in
      `test/ares-test-tls.cc` (10 tests): handshake to ESTABLISHED,
      want-flags (handshake-blocked, read-empty, write-flooded), framed
      write/read round-trip, graceful shutdown, certificate verification
      success + untrusted-CA failure, abrupt peer close, mid-handshake
      close, partial/repeated writes with byte-exact stream integrity,
      session resumption (cache hit, single-use consumption, cache
      repopulation from fresh tickets, `SSL_session_reused` confirmed
      server-side), TLSv1.3 Early Data accepted (0-RTT payload observed
      server-side pre-handshake-completion) and rejected (fresh server
      ticket keys; replay through the normal write path arrives exactly
      once), and the `ares_conn_interpret_events()` matrix (remap both
      directions, no-events entry, unknown-fd drop, non-TLS passthrough).
      New provider API: `ares_tlsimp_earlydata_accepted()` for the
      integration's requeue decision.  Original coverage-target list:
      client backend
      on one end of a `socketpair()` via the fake-conn fixture above, a
      plain OpenSSL *server* `SSL_CTX` driven directly by the test on the
      other end (the test binary already links OpenSSL in crypto builds).
      Non-blocking on both ends so the WANT_READ/WANT_WRITE paths actually
      execute.  Coverage targets:
      - handshake to ESTABLISHED, want-flag publication at every state
      - framed write/read round-trip, partial/repeated writes
      - graceful shutdown, abrupt peer close, mid-handshake close
      - certificate verification success/mismatch (runtime-generated CA)
      - session resumption on a second connection (cache hit through the
        session cache, single-use ticket removal) — this also covers the
        `ares_crypto.c` session-cache functions, no separate unit tests
        needed
      - TLS v1.3 Early Data: accepted (server reads 0-RTT flight) and
        rejected (`SSL_EARLY_DATA_REJECTED` -> caller replay contract)
      - `ares_conn_interpret_events()` remapping: register the fake conn in
        `channel->connnode_by_socket` (llist node + htable insert, same
        internals the production register path uses) so
        `ares_conn_from_fd()` resolves it, drive the real TLS session into
        each blocked state over the socketpair (empty pipe ->
        READ_WANTREAD, filled pipe -> WRITE_WANTWRITE, stalled handshake ->
        connect want-flags once that defect fix lands), and assert the
        remapped event output — plus non-TLS passthrough and unknown-fd /
        zero-event handling.

The Phase 3 mock-DoT-server work then *extends* this harness (same
runtime-generated CA and server plumbing) rather than starting from scratch;
Phase 3 also re-exercises the event remapping through the real process loop
across all event backends.

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

## Session ticket / single-use design notes

Recorded from analysis (2026-07-09) so the rationale isn't lost:

- **Single-use is deliberate, not mandated**: RFC 8446 Appendix C.4 says
  clients SHOULD NOT reuse a ticket (passive-observer correlation — a real
  privacy concern for DNS).  Additionally, server-side 0-RTT anti-replay
  (RFC 8446 sec. 8.1) commonly enforces single-use tickets, so reuse would
  get the 0-RTT flight rejected by strict servers anyway.  Single-use
  client behavior is both the privacy-correct and the
  reliably-fast choice.
- **The 0-RTT benefit is not one-shot — tickets replenish**: TLS 1.3
  servers send multiple NewSessionTicket messages per connection (OpenSSL
  default 2, tunable via SSL_CTX_set_num_tickets()), and fresh tickets are
  also issued on *resumed* connections.  Steady state is 0-RTT on every
  reconnect, indefinitely.  The CryptoTLSSessionResumption test pins the
  repopulation behavior.
- **Single-slot cache is a deliberate simplification**: the cache keeps
  one (the newest) ticket per server key.  With c-ares's
  one-connection-per-server model that sustains an unbroken 0-RTT chain.
  Not covered: parallel connection bursts to one server — the second
  simultaneous connection finds the cache empty and full-handshakes
  (correct, just not 0-RTT).  If that ever matters, upgrade to a per-key
  ticket queue (new-session callback appends, create pops); note the
  queue depth is bounded by however many tickets the server chooses to
  issue (OpenSSL servers default to 2 per handshake) — ticket count is
  server policy and a client cannot request more.  Since c-ares keeps a
  single persistent connection per server and multiplexes queries over
  it, parallel same-server connections essentially don't occur, which is
  what justifies the single slot.
- **TLS 1.2**: the single-use guidance is 1.3-specific; 1.2 tickets
  (RFC 5077) are conventionally reused and have no early data.  Our
  uniform single-use policy just costs a 1.2 server an occasional extra
  full handshake — acceptable, and DoT deployments are 1.3-era.

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

- [ ] **`ares_conn_interpret_events()` through the real process loop**:
      Step 0 covers the mapping logic directly; this validates it embedded
      in `ares_process_fds()` across all event backends via the mock-TLS
      suite (per-backend timing differences are where remapping bugs
      surface).
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

- Unix CA-root discovery should probably try
  `SSL_CTX_set_default_verify_paths()` first (the packaged OpenSSL's own
  OPENSSLDIR plus `SSL_CERT_FILE`/`SSL_CERT_DIR` env overrides are
  authoritative on distros), keeping the hardcoded path probes as the
  fallback for static/custom OpenSSL builds; the probe list also lacks
  OpenBSD/NetBSD (`/etc/ssl/cert.pem`), SUSE (`/etc/ssl/ca-bundle.pem`),
  and Solaris (`/etc/certs/`).  Related: minimal container images
  (Alpine/distroless without ca-certificates) legitimately have no bundle
  -- which is why root loading is best-effort at init.

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
- 2026-07-09: PR #1252 CI matrix fully green (28/28) including the crypto
  legs.  Shakeout fixed real issues: C90 comment lexing in -Werror
  builds, base-diff clang-format, ares_init() hard-failing on CA-less
  systems (containers/embedded; root loading now best-effort), and
  missing crypt32 linkage on Windows (first-ever compile+link+test of
  the wincrypt cert-store path).
- 2026-07-09: CARES_CRYPTO CI legs added (Ubuntu build+test + ASAN
  variant; MSYS2 MINGW64/CLANG64 with openssl — first CI ever to compile
  the Windows cert-store path) and draft PR
  [#1252](https://github.com/c-ares/c-ares/pull/1252) opened against
  upstream so the full matrix runs on every push of this branch.
- 2026-07-09: remaining backend defect list cleared (session-key
  partial/placeholder, insert key leak, dead write block, read-ahead
  pending accessor + drain contract, Windows cert-store rewrite --
  including the discovery that it referenced a nonexistent macro and had
  never compiled -- and the error-mapping rework adding
  ARES_CONN_ERR_SECURITY and clean-close CONNCLOSED).  12/12 harness
  tests green, normal + ASAN.  Windows compile validation awaits the
  crypto CI leg.
- 2026-07-09: Step 0 complete — remaining harness coverage landed
  (mid-handshake close, partial writes with stream-integrity check,
  session resumption, Early Data accept + reject/replay; 10/10 green,
  normal + ASAN).  The resumption/0-RTT tests flushed out three more
  defects, all fixed: security level 3 silently disables session tickets
  (dropped to level 2 — decision now recorded above),
  `SSL_CTX_remove_session()` marks sessions non-resumable (single-use now
  enforced in the c-ares cache only), and ticket replacement left a stale
  reverse-table entry that let OpenSSL's bad-session eviction tear down
  the wrong cache entry.  Added `ares_tlsimp_earlydata_accepted()`.
- 2026-07-08: test harness landed (`test/ares-test-tls.cc`): fake-conn
  socketpair fixture with runtime-generated ECDSA CA/server certs, plain
  OpenSSL server peer, five tests green under normal and ASAN crypto
  builds.  Enablers added: `ares_tls_set_cadata()` (PEM trust-anchor
  injection; the unix root loader now uses the ctx cert store so
  additions take effect uniformly).  Defects fixed: connect/shutdown/
  early-data want-flag publication, session refcount on removal, and a
  teardown-ordering use-after-free the harness caught on its first run.
- 2026-07-08: pre-harness fixes landed: sess_rev creation, BIO retry-write
  flag, tlsimp_create missing goto, debug fprintf removal, generic
  ares_tls_create() entry point, OpenSSL linkage for arestest in CMake
  crypto builds.  CI legs still pending (workflow changes done separately).
- 2026-07-08: added Phase 1 Step 0 — standalone backend test harness so the
  backend is fully testable in CI before connection integration begins.
  Simplified after review: no I/O seam needed (a minimal fake conn around a
  socketpair drives the production BIO->conn->socket path directly); no
  separate session-cache/interpret_events unit tests (covered by the
  harness resumption tests and the Phase 3 full-stack tests respectively);
  live smoke check dropped.
