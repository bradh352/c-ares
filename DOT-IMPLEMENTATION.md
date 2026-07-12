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

## Scope overview

The full feature, so the plan visibly covers everything (details in the
sections below).  This is intent-level scope, not a rigid phase order.

**Done and CI-validated:**
- Crypto abstraction layer + OpenSSL >= 3 backend (handshake, verification,
  session resumption).
- Functional DoT end to end: `dns+tls://` server config, TLS on the
  connection, SNI + strict/opportunistic verification.
- Performance: TLS 1.3 Early Data (0-RTT) + TCP Fast Open — warm queries
  cost no extra round trips.
- Crypto CI legs (Linux/ASAN, MSVC+OpenSSL, MSYS2).

**Remaining scope:**
- **Server security grouping** — secure servers preferred; no silent
  downgrade to plaintext (strict tier + opt-in fallback flag).  Security
  requirement, not a nicety.
- **Bootstrap resolution** — resolve resolver IP<->hostname over insecure
  servers *only* to enable a secure connection, never to answer user
  queries.
- **Configuration flexibility** — custom CA cert, client certs (mTLS),
  hostname-validation modes.
- **OS DoT config sources** — read the host OS's DoT configuration
  (Android Private DNS, systemd-resolved read directly, macOS/iOS, …); a
  research item; findings folded into the OS DoT config section below.
  Includes DDR (RFC 9462) /
  DNR (RFC 9463) standards-track auto-discovery.
- **Additional crypto backends** — Schannel (dependency-free Windows) and
  others; abstraction already exists.
- **Testing & docs** — full-stack mock DoT suite, all event backends, live
  tests, macOS crypto CI leg, man-page / `FEATURES.md` entries.
- **Overlaps** — #642 domain-specific servers shares the server-grouping
  machinery; #882 URI schemes are the config representation.

## Current state (what exists on this branch)

**DNS-over-TLS is functional and performant end to end.** A `dns+tls://`
server completes real queries (handshake, framed query/response, session
resumption, connection reuse, SNI + certificate verification) with TLS 1.3
0-RTT early data and TCP Fast Open, validated across the full CI matrix.
The remaining work is the "Remaining scope" list above (security grouping,
config flexibility, OS config sources, more backends, tests/docs).

This section describes the original backend building blocks the branch
started from; see the phase sections and the progress log for what has
since been completed.

Original building blocks:

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
- [x] `SSL_CTX_set_read_ahead(1)` buffered TLS records inside OpenSSL so
      decrypted data could be pending with no fd readable event.  During
      Phase 1 integration this caused a nondeterministic race (responses
      stuck inside the TLS layer until query timeout, spurious reconnects).
      **Removed read-ahead entirely** -- without it every byte the client
      needs corresponds to socket-readable data and the standard event loop
      works unchanged; c-ares is not throughput-bound so the extra
      SSL_read calls don't matter.  `ares_tlsimp_get_read_pending()`
      (`SSL_has_pending()`) is retained as defensive API, still pinned by
      the CryptoTLSReadPending test.
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
- [x] **CI legs** (`CARES_CRYPTO=ON`, on every push via draft PR #1252):
      Ubuntu (build+test incl. containers, Werror) + Ubuntu ASAN, MSYS2
      MINGW64/CLANG64 (mingw openssl), and MSVC x64 (choco OpenSSL) — the
      MSVC leg validates compile/link + the full non-TLS suite under the
      crypto build (the TLS harness is POSIX-only).  All other legs guard
      the no-crypto stubs; `reuse lint` covers new files.  (A macOS crypto
      leg is still outstanding — tracked in Phase 3.)

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

### Manual configuration (URI scheme)

The manual `dns+tls://` server config is foundational to Phase 1 -- nothing
is configurable or testable without it -- so it lives here rather than in
the later config-hookup phase.  `ares_set_servers_csv()` already accepts
`dns://host:port?tcpport=N` URIs (parsed by `parse_nameserver_uri()` via
`ares_uri`, written back by `ares_get_server_addr_uri()`); this extends it
with a TLS scheme.

- [x] Scheme **`dns+tls://`**, default port 853.  Query keys:
  - `hostname=<name>` — authentication name (SNI + certificate
    verification); presence implies strict mode.
  - `verify=strict|opportunistic` — explicit profile override
    (opportunistic = encrypt without certificate verification; this is the
    "none" intent, so no separate `none` value was added).
  - Example: `dns+tls://1.1.1.1?hostname=one.one.one.one`.  IP is still the
    URI host (c-ares dials IPs, never resolves a resolver name via itself);
    link-local `%iface` continues to work.  Rejected up front
    (`ARES_ENOTIMP`) when built without crypto.
- [x] Round-trip: `ares_get_servers_csv()` emits `dns+tls://` for TLS
      servers (`ares_server_use_uri()` extended), pinned by
      TLSServerConfigCSV.
- [x] Duplicate-server detection / server sort treats
      `(ip, port, tls, verify, hostname)` as the identity
      (`ares_server_tls_match` / `ares_sconfig_tls_match`).
- [x] Public API surface beyond CSV: **none** required (options struct
      untouched -> no ABI concern).  A channel-level "opportunistic TLS for
      all servers" knob can come later.
- [ ] `adig -s dns+tls://...` works for free via CSV parsing (untested
      end-to-end against a live DoT server); add a note to adig docs.
- [ ] Docs: `ares_set_servers_csv.3` scheme table; `FEATURES.md` entry.

### Connection integration

- [x] **Server-level TLS configuration** in `ares_server_t` /
      `ares_sconfig_t`: `use_tls`, `tls_hostname` (auth name), `tls_verify`
      (default/strict/opportunistic); default port 853; TLS settings are
      part of server identity (find/isdup/in_newconfig compare them).
- [x] **Connection setup**: `ares_open_connection()` sets
      `ARES_CONN_FLAG_TLS` and creates the session for TLS servers; queries
      to a TLS server are forced onto TCP (`ares_send_query_int`); the
      handshake is pumped lazily from the read/write entry points
      (`ares_conn_tls_pump`) until ESTABLISHED; existing TCP framing reused
      above TLS unchanged.  TFO is deferred for TLS connections.
- [x] **I/O routing**: `ares_conn_read()`/`ares_conn_write()` split into
      raw (`_raw`) and TLS-routed forms; the BIO bridge calls the raw
      paths to avoid recursion; the same-data retry contract holds
      (verified by the partial-write test).
- [x] **SNI + hostname verification**: `tls_hostname` plumbed into
      `SSL_set_tlsext_host_name()` + `SSL_set1_host()`; default resolves to
      strict-with-name / opportunistic-without per RFC 8310; opportunistic
      sets `SSL_VERIFY_NONE`.  The end-to-end verify-fail test confirms
      strict does not fall back to plaintext.
- [x] **Session cache completion**: session key includes the real
      `tls_hostname` so different auth names never share sessions; insert
      via the new-session callback and single-use consumption are covered
      by the resumption test.
- [x] **TLS v1.3 Early Data (0-RTT)**: implemented in `ares_conn_write()`.
      While the handshake is in progress and the resumed session reports
      early-data capacity, the pending query (the `out_buf` head the flush
      loop peeks) is fed to `ares_tlsimp_earlydata_write()`, tracked in
      `conn->tls_earlydata_sent` but NOT reported written -- so a rejected
      flight stays buffered and replays.  On handshake completion,
      `ares_tlsimp_earlydata_accepted()` reconciles: accepted bytes are
      reported written (consumed), rejected ones fall through to the normal
      write.  Capped at the session budget; a cache miss reports budget 0
      and the block is skipped (ordinary 1-RTT handshake).  0-RTT replay is
      safe because DNS queries are idempotent (documented in a code
      comment; must never enable early data for a non-idempotent use).
      Pinned by CryptoDoTEarlyData (server observes the 2nd query as early
      data via `SSL_read_early_data`, no query lost/duplicated).
- [x] **TFO interplay**: TFO is now enabled for TLS connections too
      (`ares_open_connection` sets `ARES_CONN_FLAG_TFO` for all TCP).  The
      composition is automatic: the TLS BIO's writes go through
      `ares_conn_write_raw()`, so the first write -- OpenSSL's ClientHello,
      carrying 0-RTT early data on a resumed session -- rides the SYN via
      the existing `TFO_INITIAL` sendto path (`MSG_FASTOPEN` on Linux,
      `connectx` on macOS), giving true 0-RTT including the TCP round trip.
      Falls back to an ordinary connect where TFO is unavailable.  The
      `ares_conn_query_write` flush-immediately-on-`TFO_INITIAL` guard
      already triggers the send without waiting for TCP connect.  Verified:
      DoT + early-data tests deterministic with TFO active (macOS connectx
      loopback), ASAN clean, no change to the non-TLS TCP path; CI
      exercises real TFO on Linux (`tcp_fastopen=3`).
- [x] **Shutdown & teardown**: best-effort `ares_tlsimp_shutdown()` on
      close of an established TLS connection (preserves the session for
      resumption), `ares_tlsimp_destroy()` in the cleanup path and the
      open-connection error path.
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

### Host OS configuration

Reading the host OS's DoT configuration is a substantial research +
implementation area covered in the "OS DoT configuration sources" section
below (summary + full research findings).  It is listed here only to mark
where it slots into config hookup.

### Server security grouping (no silent downgrade)

A channel can end up with a mix of secure (DoT) and plaintext (Do53)
servers — e.g. an app configures a DoT resolver but the system also
supplies Do53 upstreams.  The current `server_sort_cb` orders purely by
health (consecutive failures, then retry time, then config index), so a
DoT server with a single failure loses to a healthy Do53 server: a silent
privacy downgrade.  Preventing that is a core security requirement, not a
nicety.

**Decided policy (2026-07-11): strict tier with opt-in fallback.**
- Secure servers form a strictly higher-priority tier than plaintext:
  server selection exhausts all usable secure servers before ever
  considering a plaintext one for a *user query*.
- Default: **no downgrade.**  If secure servers are configured and all are
  unreachable/failing, user queries fail rather than fall back to
  plaintext.
- A channel flag (working name `ARES_FLAG_DNS_ALLOW_DOWNGRADE`) lets an
  application opt in to plaintext fallback when the entire secure tier is
  down.  Off by default.
- Plaintext servers may still be used for **bootstrap resolution** (below)
  regardless of the flag — that path never answers user queries.

- [ ] Add a security-tier key to `server_sort_cb` (secure before insecure)
      so selection/failover honors the tier; a query started against the
      secure tier must not silently retry onto the insecure tier.
- [ ] `ARES_FLAG_DNS_ALLOW_DOWNGRADE` (default off) gating any
      cross-tier fallback for user queries.
- [ ] When the secure tier is exhausted and downgrade is off, return a
      clear status (not a generic SERVFAIL that hides the downgrade
      refusal).
- [ ] Tests: mixed DoT/Do53 channel prefers DoT; DoT-down + no flag =
      query fails (no plaintext leak); DoT-down + flag = plaintext used;
      pure-Do53 channel unchanged.

### Bootstrap resolution (IP <-> hostname for validation)

Some configuration sources give only a resolver **IP** (no hostname, so
strict certificate validation by name isn't possible) or only a
**hostname** (no address to dial).  Per the maintainer's intent, c-ares
may resolve the missing half over the **insecure** servers during init or
on first use — solely to *enable* the secure connection (SNI / cert
validation), never to answer user queries.

- [ ] Design the bootstrap lookup (when, cached where, failure handling)
      and its interaction with the security tier (bootstrap explicitly
      allowed to use insecure servers).
- [ ] Decide the IP-only fallback: opportunistic encrypt-only vs.
      IP-in-SAN verification (`X509_VERIFY_PARAM_set1_ip`) vs. reverse
      lookup for a name.  Ties into the "no hostname" open question below.
- Entangled with OS config reading (which is what produces IP-only /
  hostname-only entries) and with #642 domain-specific servers, so this
  lands alongside that work rather than standalone.

### Configuration flexibility (custom CA, client certs / mTLS, hostname)

Captured from issue #818 intent and a concrete user request (mTLS to a
private DoT resolver):

- [ ] **Custom CA certificate(s)** for validating the resolver, instead of
      (or in addition to) the system trust store.  The internal
      `ares_tls_set_cadata()` already exists; needs a public config surface
      (URI query key like `cafile=`/`cadata=`, and/or an option).
- [ ] **Client certificates (mTLS)** to authenticate c-ares to the
      upstream resolver — requested in #818.  Needs cert+key config plumbed
      into the backend (`SSL_CTX_use_certificate`/`_PrivateKey` on the
      client side) and a config surface.
- (Done in Phase 1) **Skip / relax hostname validation** via
  `verify=opportunistic` (encrypt without verification).  A
  verify-chain-but-not-name middle mode could still be added if needed.
- [ ] Decide the config surface for the above (URI query keys vs. new
      `ares_set_*` API vs. options struct) and the ABI implications.

## Phase 3 — Testing (full-stack; extends the Phase 1 Step 0 harness)

Backend-level coverage (state machine, resumption, early data accept/reject)
already exists from Phase 1 Step 0; this phase covers the integrated stack.

- [ ] **`ares_conn_interpret_events()` through the real process loop**:
      Step 0 covers the mapping logic directly; this validates it embedded
      in `ares_process_fds()` across all event backends via the mock-TLS
      suite (per-backend timing differences are where remapping bugs
      surface).  *Partial:* CryptoDoTQuery already runs a real query
      through the process loop over a TLS connection on the default
      (select) backend; the all-event-backend sweep remains.
- [ ] **Mock DoT server**: extend the gmock test server with a TLS
      variant when built `CARES_CRYPTO=ON`, reusing the Step 0
      runtime-generated CA/server-cert plumbing, with a test hook to
      inject the CA (or `verify=none`) into the client ctx.  Covers via
      real `ares_query()` traffic: handshake, framed query/response,
      server-initiated close, mid-handshake close, handshake timeout,
      certificate mismatch in strict vs opportunistic mode, session
      resumption on second connection.  *Partial:* CryptoDoTQuery (real
      query + connection reuse) and CryptoDoTVerifyFail (strict cert
      mismatch, no plaintext fallback) exist via a threaded in-test DoT
      server; the remaining sub-cases and a gmock-integrated variant
      remain.
- (Done in Phase 1 — CryptoDoTEarlyData: server observes the 2nd query as
  early data, no loss/dup; see the Early Data item there.)  A channel-level
  *reject* variant (fresh server ticket keys) could still be added, though
  CryptoTLSEarlyDataReject already pins the no-loss/no-dup contract at the
  backend level.
- [ ] **Event-loop integration**: run the mock-TLS suite under all event
      backends (epoll/kqueue/poll/select/IOCP configurations CI already
      exercises) — the want-flag remapping is exactly the kind of thing
      that behaves differently per backend.
- [ ] **Live tests** (opt-in, like existing live suite): 1.1.1.1 /
      8.8.8.8 / 9.9.9.9 with their hostnames, strict mode.
- (Done in Phase 1 — see the CI item under Step 0.)  Remaining CI: a macOS
  crypto leg (Security-framework root loading is only compile-checked today
  via local dev builds).
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
- Session cache eviction is currently keyed on graceful vs. abrupt close;
  confirm that interacts sanely with `ARES_CONN_FLAG_NONEW` retirement.

## Additional crypto backends

The provider abstraction (`ares_cryptoimp_*` / `ares_tlsimp_*`) was built
to make backends pluggable.  OpenSSL >= 3 is the only one implemented.
Others, with the challenges the maintainer documented in #818:

- **Windows SChannel** — removes the OpenSSL dependency on the platform
  where shipping it is hardest.  Challenges: the common SSPI/Schannel
  examples don't cover TLS 1.3; TLS 1.3 needs correct handling of
  `SEC_I_RENEGOTIATE` in `DecryptMessage`; and it is **not clear how to
  send TLS early data (0-RTT)** via Schannel, so 0-RTT may be
  OpenSSL-only.  Refs in the issue.
- **Apple** — SecureTransport is legacy and TLS 1.2-only (unusable for a
  1.3-era feature).  The modern Network.framework doesn't expose a
  buffer-in/buffer-out TLS primitive: because c-ares lets the app swap the
  socket layer via `ares_set_socket_functions()`, we can't delegate the
  actual network I/O to Network.framework, and the integration would need
  Objective-C.  Likely not viable as a c-ares backend; Apple platforms use
  the OpenSSL backend.
- **wolfSSL / rustls-ffi / mbedTLS** — plausible additional backends for
  embedded / small-footprint or memory-safe deployments; not scoped yet.

Priority: the abstraction exists, so a second backend is additive and
non-urgent.  Schannel is the highest-value target (dependency-free
Windows) if/when someone takes the TLS 1.3 + 0-RTT investigation.

## OS DoT configuration sources

Reading DoT configuration from the host OS the way c-ares already reads
plaintext DNS config.  The research is **complete** — the actionable
priority summary and checkboxes are here; the full platform-by-platform
matrix, exact interfaces, permissions, empirical macOS findings, and
sources follow in the "Research findings" subsection below.

Two findings corrected earlier plan assumptions: **Windows is no longer
DoH-only** (native DoT client, registry-only schema), and **Apple
`dnsinfo` — what c-ares reads today — exposes no encrypted DNS at all**
(verified empirically; only the entitlement-gated `NEDNSSettingsManager`
has it).

Key findings and the resulting implementation priority:

**Tier 1 — worth reading (clean, unprivileged interfaces):**

- [ ] **Linux / systemd-resolved** — the single best target.  Read
      resolved's real config directly (bypassing the 127.0.0.53 stub, as
      intended) via **Varlink `io.systemd.Resolve.DumpDNSConfiguration`**
      (systemd ≥ 259) with fallback to the **`org.freedesktop.resolve1`
      D-Bus** `DNSEx`/`CurrentDNSServerEx`/`DNSOverTLS` properties (≥ 239).
      Unprivileged; exposes per-server SNI, port, mode, and per-link /
      per-domain scoping (the latter also unlocks #642).  Also covers
      NetworkManager systems (NM pushes into resolved; its own keyfiles are
      root-only `0600` and not worth reading).
- [ ] **Android** Private DNS — minimal extension of the existing
      ConnectivityManager JNI: `isPrivateDnsActive()` +
      `getPrivateDnsServerName()` (API 28+, resolved **optionally** so
      pre-28 init still works).  Strict mode gives a hostname (bootstrap
      to IPs over the plaintext servers); opportunistic gives a boolean.

**Tier 2 — readable but caveated:**

- [ ] **Windows** — correction: **Windows now has a native DoT client**
      (not DoH-only).  DoH is fully readable (registry or
      `DNS_INTERFACE_SETTINGS3` API), but **DoT is registry-only and its
      schema is undocumented** — best-effort empirical read under
      `…\Dnscache\InterfaceSpecificParameters\{GUID}\DohInterfaceSettings\`.
- [ ] **Local forwarders** (unbound / stubby / unwind / local_unbound) when
      c-ares runs on the same host — parse the forwarder's own config
      (`forward.conf`, `unwind.conf`, `stubby.yml`).  Non-standard,
      app-specific, best-effort.

**Blocked — rely on explicit app config or DDR:**

- **macOS / iOS** — correction: the `dnsinfo` snapshot c-ares reads today
  **does not expose encrypted DNS at all** (no DoH/DoT field in any
  version); `scutil --dns` can't either.  The only API with the details is
  the entitlement-gated `NEDNSSettingsManager`.  A profile-installed DoT
  resolver's plaintext IPs may even surface via dnsinfo and get queried in
  the clear, silently defeating intent.  On Apple platforms, rely on
  explicit application configuration.
- **ChromeOS** — DoH-only and unreadable by a sandboxed library.

**Cross-platform fallback (highest-value auto-config):**

- [ ] **DDR (RFC 9462)** — self-contained SVCB-based auto-upgrade from a
      plaintext resolver IP: SVCB query to `_dns.resolver.arpa`, then
      **require the original resolver IP in the cert `iPAddress` SAN**
      (Verified Discovery).  c-ares already parses SVCB.  Needs an opt-in.
      **DNR (RFC 9463)** is network-pushed via DHCP/RA and not directly
      consumable by a resolver library — rely on the OS (systemd-resolved
      fed by networkd ≥ 257) to translate it into a DoT server c-ares then
      reads via Tier 1.

### Research findings (full platform matrix)

### Summary table

| Platform | DoT in OS resolver? | Readable by unprivileged lib? | Auth hostname (SNI) exposed? | Notes |
|---|---|---|---|---|
| **Android** (Private DNS) | **Yes** (API 28+) | **Yes** — JNI `LinkProperties` (`ACCESS_NETWORK_STATE`) | **Yes** (strict); opportunistic = boolean only | Extends existing ConnectivityManager JNI. Validated DoT IPs hidden; resolve hostname yourself. |
| **Linux — systemd-resolved** | **Yes** (`DNSOverTLS=`) | **Yes** — D-Bus `resolve1` or Varlink `DumpDNSConfiguration` | **Yes** (`#ServerName` in `DNSEx`) | **Best target on Linux.** Also reflects what NetworkManager pushed. |
| **Linux — NetworkManager** | Only via backend (usually resolved) | **No** — keyfiles root-only `0600` | (in keyfiles, unreadable) | Read resolved instead. |
| **Linux — dnsmasq** | **No** | file only | N/A | Forwards plaintext to a local DoT daemon. |
| **Linux/BSD — unbound / stubby** | **Yes** (local forwarder) | file only, perms vary | Yes (`@853#name`, `tls_auth_name`) | Non-standard app-specific formats. |
| **/etc/resolv.conf** | **No concept** | file | **No** — structurally impossible | Bare IP; no port/SNI/TLS field. |
| **Windows 11 / Server** | **DoH yes; DoT now yes** | DoH via API or registry; **DoT registry-only** | DoT: **yes** (`dothost`), API doesn't expose it | Registry read unprivileged. DoT registry schema undocumented. |
| **macOS** | **Yes** (DoH+DoT since Big Sur) | **No** (empirically confirmed: only a `127.0.0.1` placeholder in dnsinfo/scutil/SCDynamicStore; real config only via entitlement-gated NE) | Only via NE / profile | Verified on macOS 26.5.1, VPN off. |
| **iOS / iPadOS** | **Yes** (same as macOS) | **No** (entitlement-gated) | Yes but unreadable by a generic lib | More locked down than macOS. |
| **ChromeOS** | **DoH-only** | **No** (Chrome-internal) | N/A | Resolve through the system resolver. |
| **FreeBSD/OpenBSD/NetBSD (base)** | **No native**; local forwarder only | file (forwarder config) | Yes (forwarder config) | `local_unbound`, `unwind`, pkgsrc unbound. |
| **OpenWrt / routers** | **No native**; local forwarder | file (on the router) | Yes (`tls_auth_name`) | LAN clients see plaintext at router IP. |
| **DDR (RFC 9462)** | Cross-platform *discovery* | **Self-contained** — c-ares does it itself | ADN validated via cert SAN | **Recommended universal fallback** from a plaintext IP. |
| **DNR (RFC 9463)** | Network push via DHCP/RA | **No** — no portable DHCP surface | ADN in the option | OS-stack territory; consume via systemd-resolved. |

---

### Android — "Private DNS"

- **Supported?** **Yes**, native DoT since **Android 9 / API 28** (2018). A
  real system-resolver feature, not a forwarder.
- **Stored.** Settings → Private DNS (Off / Automatic / provider hostname).
  Persisted in `Settings.Global`: `private_dns_mode`
  (`off`/`opportunistic`/`hostname`) and `private_dns_specifier`. Effective
  per-network state via `android.net.LinkProperties`.
- **How c-ares reads it.** Extend the existing ConnectivityManager JNI:
  `getActiveNetwork()` → `getLinkProperties()` → `isPrivateDnsActive()`
  (`()Z`, API 28) and `getPrivateDnsServerName()`
  (`()Ljava/lang/String;`, API 28). Needs install-time
  `ACCESS_NETWORK_STATE`. (`Settings.Global.getString` also works; keys are
  `@hide` but the table is world-readable.)
- **Fields.** Mode inferred: not active → off; active + null name →
  opportunistic; non-null name → strict (that name is the SNI /
  cert-validation name).
- **Gotchas.** Strict gives a **hostname, not IPs** — validated DoT IPs are
  in `getValidatedPrivateDnsServers()` which is `@SystemApi`, not callable;
  c-ares must resolve the hostname over the plaintext `getDnsServers()` IPs
  (bootstrap). `net.dns*` sysprops are SELinux-blocked (why c-ares already
  uses the JNI path). **Impl caveat:** these methods are API 28+ while the
  existing lookups target API 21–23, and current init nulls *all* method
  IDs on any failure — resolve the two new IDs **optionally**.
- **Sources.** https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html
  · AOSP `LinkProperties.java` · `DnsManager.java` · c-ares #111, #276
  (sysprop block).

### Linux — systemd-resolved (the best readable target)

- **Supported?** **Yes.** `DNSOverTLS=` = `yes` (strict, cert-validated, no
  fallback) / `opportunistic` (try DoT, fall back to plaintext, cannot
  authenticate) / `no` (default since v239).
- **Stored.** `/etc/systemd/resolved.conf` + drop-ins
  (`resolved.conf.d/*.conf` under `/etc`, `/run`, `/usr/lib`, merged);
  per-link via networkd `.network` or `resolvectl dnsovertls`. **Server
  syntax with SNI:** `ADDRESS[:PORT][%INTERFACE][#SERVERNAME]` — the
  `#SERVERNAME` is the TLS cert-validation name / SNI.
- **How c-ares reads it — without the 127.0.0.53 stub** (three unprivileged
  paths):
  1. **D-Bus `org.freedesktop.resolve1` (systemd ≥ 239)** — verified
     against source. Manager: `DNSEx` = `a(iiayqs)` (ifindex, family,
     address, **port `q`**, **server_name `s` = SNI**); `CurrentDNSServerEx`
     = `(iiayqs)`; **`DNSOverTLS` = `s`** (string, not bool on the wire).
     Link object (`/org/freedesktop/resolve1/link/_<ifindex>`): `DNSEx` =
     `a(iayqs)` (**no** leading ifindex — separate parser), `DNSOverTLS` =
     `s`, `Domains` = `a(sb)` (`~domain` routing bool). **Per-server SNI and
     per-link/per-domain DoT servers are exposed.**
  2. **Varlink `io.systemd.Resolve.DumpDNSConfiguration` (systemd ≥ 259)** —
     cleanest; socket `/run/systemd/resolve/` mode `0666`, not polkit-gated;
     one JSON reply with each server's `address`/`port`/`ifindex`/**`name`
     (SNI)**/`accessible` plus `dnsOverTLS` enum. (Do NOT use the polkit-gated
     `Monitor.SubscribeDNSConfiguration`.)
  3. **Config files** — world-readable but global-only, no per-link runtime
     state, must re-implement precedence.
- **Permissions.** Reading unprivileged (bus policy allows
  `Properties.Get`/`GetAll` to any local user; polkit gates only mutation).
- **Sources.** `resolved.conf(5)`, `org.freedesktop.resolve1(5)`; systemd
  source `resolved-bus.c`, `resolved-link-bus.c`, `resolved-varlink.c`,
  `varlink-io.systemd.Resolve.c`; bus policy + polkit files.

### Linux — NetworkManager

- NM is a config **broker**, not a resolver; DoT depends on `[main] dns=`
  (`systemd-resolved` can do DoT; `dnsmasq`/`default` can't; `dnsconfd` is
  newer for NM's native `dns+tls://`). Keys exist
  (`connection.dns-over-tls`, per-server `9.9.9.9#dns.quad9.net`; NM 1.52
  added `dns+tls://` URI + `[global-dns]`).
- **Not readable** by non-root: per-connection keyfiles
  `/etc/NetworkManager/system-connections/*.nmconnection` are enforced
  `0600`. **Read systemd-resolved instead** — it reflects what NM pushed.
- **Sources.** NetworkManager.conf, nm-settings-keyfile docs; NM 1.52 blog;
  lwn.net/Articles/1021357.

### Linux — dnsmasq / unbound / stubby / resolv.conf

| Resolver | DoT? | Config | Reads | Fields | Gotchas |
|---|---|---|---|---|---|
| **dnsmasq** | No | `/etc/dnsmasq.conf`, `.d/*` | file | `server=IP[#port]` (`#`=port) | Forwards plaintext to a local DoT daemon. |
| **unbound** (local) | Yes | `/etc/unbound/unbound.conf(.d)` | file | `forward-addr: IP@853#authname`, `forward-tls-upstream: yes`, `tls-cert-bundle` | `include:` globs; recursive=no upstream. |
| **stubby** | Yes | `/etc/stubby/stubby.yml` | file (YAML) | `address_data`, `tls_port`, `tls_auth_name`, `tls_authentication` | It *is* the DoT terminator; clients see `127.0.0.1`. |
| **/etc/resolv.conf** | **No concept** | `/etc/resolv.conf` | file | **none** | **Structurally cannot represent DoT/SNI/port.** No standard extension. |

### Windows (11 / Server 2022–2025)

- **Supported?** The "DoH-only" belief is **stale**. DoH shipped with Win11 /
  Server 2022; **native DoT client support was added** and is documented in
  the current `netsh dnsclient` reference (`dothost=<hostname>:<port>`,
  global `dot=yes|no`; first in Insider 25158, Aug 2022). *Caveat:* full GA
  status of DoT client across stable Win11 24H2/25H2 vs. still
  command-line-leaning is **not cleanly confirmed** by a single primary
  source — verify on target builds.
- **Stored.**
  - **Registry (authoritative):**
    `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\{GUID}\DohInterfaceSettings\Doh\{ServerIP}`
    (note **`InterfaceSpecificParameters`**, not directly under
    `Parameters`). Values: `DohFlags` (`REG_QWORD` bitmask: `0x1` template
    from system list, `0x2` explicit `DohTemplate`, `0x4` allow unencrypted
    fallback, `0x8` NRPT auto-upgrade) and `DohTemplate` (`REG_SZ`).
  - **netsh:** `netsh dnsclient add/set/show encryption server=<IP>
    dohtemplate=<url> dothost=<host>:<port> autoupgrade= udpfallback=`; global
    `doh=`/`dot=`/`ddr=`. `dothost` is the DoT auth hostname.
  - PowerShell `*-DnsClientDohServerAddress`; Group Policy exists for **DoH**
    only, not DoT.
- **How c-ares reads it.**
  - `GetInterfaceDnsSettings` + `DNS_INTERFACE_SETTINGS3`
    (`ServerProperties` → `DNS_DOH_SERVER_SETTINGS { Template; Flags; }`) —
    **DoH only, no DoT field**, unprivileged read.
  - **Registry read (only way to get DoT):** open
    `DohInterfaceSettings\Doh\{IP}` `KEY_READ`; `HKLM` world-readable →
    unprivileged. **DoT registry sub-schema is undocumented** — enumerate
    empirically, best-effort.
- **Gotchas.** DoT registry-only + undocumented; API is DoH-only.
  `DohFlags` is a bitmask. Win11 also does DDR (RFC 9462), `netsh … global
  ddr=`.
- **Sources.** netsh dnsclient (Learn, updated 2026-02); doh-client-support;
  `DNS_INTERFACE_SETTINGS3`, `DNS_DOH_SERVER_SETTINGS`,
  `GetInterfaceDnsSettings`; 4sysops DoT-via-netsh; DDR blog.

### macOS

- **Supported?** **Yes — DoH and DoT**, since **macOS 11 Big Sur** (WWDC20).
- **Stored.** (1) Configuration profile `.mobileconfig`, payload
  `com.apple.dnsSettings.managed`: `DNSProtocol` = `HTTPS`/`TLS`; DoT uses
  **`ServerName`** (cert name); optional `ServerAddresses`,
  `SupplementalMatchDomains`, `OnDemandRules`. (2) NetworkExtension via
  `NEDNSSettingsManager` → `NEDNSOverTLSSettings` (`serverName`, `servers`).
- **How c-ares reads it — the critical finding: it can't via the current
  path.** The private `dnsinfo.h` `dns_resolver_t` c-ares reads has **no
  encrypted-DNS field in any version** (verified against the in-tree copy
  `src/lib/thirdparty/apple/dnsinfo.h` and Apple's live header — neither
  mentions TLS/HTTPS/server-name/URL, and `flags` has no "encrypted" bit).
  `scutil --dns` is a thin front-end over the same data → **cannot show**
  DoH/DoT. `SCDynamicStore` exposes no documented key. The **only** API with
  the details is `NEDNSSettingsManager`, which requires the
  `com.apple.developer.networking.networkextension` **entitlement** (Apple
  approval + provisioning) and centers on the app's *own* config, not a
  general system query.
- **Gotchas.** A profile/NE DoT resolver won't appear as encrypted in
  dnsinfo; at best its plaintext `ServerAddresses` surface as ordinary IPs,
  which c-ares would then query as **plaintext** — silently defeating
  intent. **On macOS, rely on explicit application configuration.**
- **Verified against Apple's live source + a live test (2026-07-11, macOS
  26.5.1).**
  - *Header (definitive):* the current `dnsinfo.h`
    (`apple-oss-distributions/configd` main, `DNSINFO_VERSION 20170629`)
    has **no** TLS/ServerName/DoH/URL/encrypted field.  The struct is
    actively maintained (recently gained `service_identifier`, `cid`,
    `if_name`; `dns_config_t` gained `generation`,
    `service_specific_resolver`, `version`) — so the omission of encrypted
    DNS is deliberate, not staleness.  `dns_configuration_copy()` (what
    `ares_sysconfig_mac.c` calls) therefore cannot carry DoT config.
  - *Architecture:* macOS routes all DNS through `mDNSResponder` via mach
    IPC, which terminates DoT/DoH **internally** — there is **no loopback
    DNS proxy** (confirmed: nothing listens on `127.0.0.1:53/853`,
    `mDNSResponder` has zero LISTEN sockets).  So no `dnsmasq`-style local
    resolver to read, either.
  - *Live test (partially contaminated — see caveat):* with a DoT profile
    installed (`DNSProtocol=TLS`, `ServerName=one.one.one.one`,
    `ServerAddresses=1.1.1.1`), the readable layers showed nothing usable:
    `dns_configuration_copy()` exposed either no DoT entry or only a
    `domain=placeholder-NNNNN.hostname.internal port=1 ns=127.0.0.1`
    sentinel; `scutil --dns` nothing encrypted;
    `State:/Network/PrivateDNS` empty; the configured `1.1.1.1` /
    `one.one.one.one` never appeared.
    The test was then **repeated on a clean machine with the VPN
    disconnected** (DNS owned by the real `en0` service, not the VPN), DoT
    profile installed and active: identical result — the DoT service key
    (`State:/Network/Service/<uuid>/DNS`) held only
    `DomainName=placeholder-NNNNN.hostname.internal`,
    `ServerAddresses=127.0.0.1`, `ServerPort=1`; `dnsinfo` showed the same
    `127.0.0.1:1` placeholder; `State:/Network/PrivateDNS` stayed empty; and
    a brute-force scan of **every** SCDynamicStore key for the configured
    server / name / `DNSProtocol` / `TLS` / `853` found nothing.  The VPN
    confound is eliminated — the behavior is the same clean.
  - *DoT proven active while config stays hidden (strongest evidence):*
    with the profile active, `netstat` shows a live **ESTABLISHED TCP
    connection to `2606:4700:4700::853`** (Cloudflare `one.one.one.one`
    over DoT) originating from `mDNSResponder` -- so DoT is demonstrably
    working.  Yet the real server appears **only in the socket table**,
    never in any config surface (dnsinfo/scutil/SCDynamicStore still show
    only the `127.0.0.1` placeholder).  The resolver is observable as a
    *connection* but not as readable *configuration*, and the socket table
    carries no `ServerName` for cert validation anyway.  (Aside: `udp/5353`
    listeners are Bonjour/mDNS from apps like Chrome, unrelated to DoT.)
  **Settled:** on current macOS the active DoT config is exposed only as a
  `127.0.0.1` placeholder in every surface a C library can read
  (`dnsinfo`, `scutil --dns`, SCDynamicStore incl. `State:/Network/PrivateDNS`
  and per-service DNS keys).  The real resolver IP and `ServerName` live
  solely inside `mDNSResponder`, reachable only via the entitlement-gated
  `NEDNSSettingsManager`.  There is **no** readable path (dnsinfo has no
  field; no loopback proxy; SCDynamicStore only shows the placeholder).
  **Net for the plan: rely on explicit application configuration on Apple
  platforms.**  (Only the entitlement-gated NE API could ever read it, and
  it centers on the app's own config, not a system query.)
- **Empirically verified (2026-07-11, macOS, live test).** Installed a DoT
  config profile (`DNSProtocol=TLS`, `ServerName=one.one.one.one`,
  `ServerAddresses=1.1.1.1,1.0.0.1`) and probed every readable layer:
  - `dns_configuration_copy()` (what `ares_sysconfig_mac.c` calls) returns
    the DoT profile as a **placeholder resolver only**:
    `domain=placeholder-NNNNN.hostname.internal port=1 flags=0x4006
    nns=1 ns=127.0.0.1`.  The real server (`1.1.1.1`) and `ServerName`
    (`one.one.one.one`) are **absent**; `flags` gains a private `0x4000`
    bit but carries no server/name/TLS detail.
  - `scutil --dns` (front-end over the same data): shows nothing encrypted.
  - `State:/Network/PrivateDNS` (SCDynamicStore): **stays empty**; the
    profile's `State:/Network/Service/<uuid>/DNS` entry likewise holds only
    `ServerAddresses=127.0.0.1`, `DomainName=placeholder-...`.
  Conclusion is now hard evidence, not inference: macOS **deliberately
  hides** the encrypted resolver behind a `127.0.0.1` placeholder in every
  public/SPI surface a library can read.  The only source of truth is the
  entitlement-gated `NEDNSSettingsManager`.  A library reading dnsinfo
  would either miss DoT entirely or (worse) query the unrelated plaintext
  servers.  **Definitively: rely on explicit application configuration on
  Apple platforms.**
- **Sources.** dnsinfo headers (apple-oss-distributions/configd + in-tree);
  WWDC20 10047; `com.apple.dnsSettings.managed` payload;
  `NEDNSOverTLSSettings`; NetworkExtension entitlement docs.

### iOS / iPadOS

- **Yes** (iOS/iPadOS 14, 2020), same profile payload + `NEDNSSettingsManager`
  as macOS. **Not readable** by a generic library (no `scutil`, no
  filesystem, only the entitlement-gated API). Plan for explicit app config.

### ChromeOS

- **DoH-only** (system `dns-proxy`); no DoT anywhere in Chromium `net/dns`.
  Config in Chrome prefs / enterprise policy (`DnsOverHttpsMode`/
  `Templates`), flowing over ChromeOS-internal shill/D-Bus. **Unreadable** by
  sandboxed native code; `/etc/resolv.conf` points at the local plaintext
  listener. Resolve through the system resolver.

### BSDs (FreeBSD / OpenBSD / NetBSD)

No native DoT in any base stub resolver; DoT is always a **local forwarder
on 127.0.0.1** with plaintext to it, so `/etc/resolv.conf` reveals nothing.

- **FreeBSD** — `local_unbound` (opt-in). `/var/unbound/forward.conf`:
  `forward-tls-upstream: yes`, `forward-addr: 9.9.9.9@853#dns.quad9.net`,
  `tls-cert-bundle`. Parse `forward.conf` (chroot-relative to `/var/unbound`).
- **OpenBSD** — `unwind(8)` (opt-in). `/etc/unwind.conf`:
  `forwarder { 9.9.9.9 authentication name "dns.quad9.net" DoT }` + a
  `preference { DoT }` block (`oDoT-*` = opportunistic).
- **NetBSD** — no base DoT; pkgsrc `unbound` only, no standard path.
- **Sources.** FreeBSD handbook / local_unbound; `unwind.conf(5)`,
  `unwind(8)`, `resolvd(8)`; pkgsrc unbound.

### OpenWrt / routers / embedded

No native DoT (default dnsmasq); added via **stubby** / **unbound** local
forwarder; LAN clients see plaintext at the router IP. stubby UCI
`/etc/config/stubby` (`option tls_authentication '1'`, per-`config resolver`
`option tls_auth_name`) or getdns YAML `/etc/stubby/stubby.yml`. Readable
only if c-ares runs **on the router**; non-standard, tool-specific.
**Sources.** OpenWrt dot_dnsmasq_stubby; stubby package README.

**The "local forwarder" theme (Linux/BSD/routers):** a daemon on 127.0.0.1
terminates DoT; the stub talks plaintext to it; `/etc/resolv.conf` never
reveals DoT. Learning upstreams means reading the forwarder's own config
(`unbound.conf`/`forward.conf`, `unwind.conf`, `stubby.yml`/`/etc/config/stubby`)
— all app-specific, non-standardized, best-effort.

### DDR (RFC 9462) and DNR (RFC 9463) — auto-discovery

Both build on SVCB (RFC 9460) + its DNS-server mapping (RFC 9461), converging
on an **ADN (Authentication Domain Name) + encrypted endpoints with
SvcParams**, authenticated by TLS certificate.

#### DDR — Discovery of Designated Resolvers (client-pull)
- A client with only a **plaintext resolver IP** discovers that resolver's
  designated encrypted endpoint via SVCB and upgrades. **Exactly the c-ares
  situation.**
- **Queries:** IP-only → SVCB (type 64) for `_dns.resolver.arpa.` sent to
  that resolver; name-known → SVCB for `_dns.<resolver-name>`.
- **SvcParams:** `alpn` (**`dot`**=DoT, `h2`/`h3`=DoH, `doq`=DoQ), `port`
  (default 853 DoT/DoQ, 443 DoH), `dohpath`, `ipv4hint`/`ipv6hint`.
- **Verified Discovery (security-critical):** IP-based flow — the cert must
  validate to a trust anchor **and contain the original Do53 resolver IP in
  an `iPAddress` SAN**; name-based — the ADN in a `dNSName` SAN. Blocks
  on-path redirection. Residual: **downgrade** (dropping the SVCB query).
  "Opportunistic Discovery" (no auth) only when the encrypted resolver
  shares the Do53 IP, SHOULD be limited to private IPs.
- **c-ares usage:** fully self-contained — SVCB `_dns.resolver.arpa` to the
  known IP over Do53 → if `alpn=dot`, TLS to the endpoint → **require the
  original IP in the cert `iPAddress` SAN** → fall back to plaintext on any
  failure. Live at Google Public DNS and Cloudflare 1.1.1.1; c-ares already
  parses SVCB.
- **Sources.** RFC 9462, RFC 9461; Apple WWDC22 10079; APNIC blog.

#### DNR — Discovery of Network-designated Resolvers (network-push)
- Network provisions resolver info via DHCPv4/DHCPv6/RA options. Payload:
  Service Priority, **ADN** (always), Addr(s), SvcParams (`alpn`+`port`
  required; ADN-only mode tells the client to run DDR to fill in the rest).
- **IANA codes (verified):** DHCPv6 `OPTION_V6_DNR`=144; DHCPv4
  `OPTION_V4_DNR`=162; IPv6 RA Encrypted DNS Option=144.
- **c-ares gotcha:** DNR lives in DHCP/RA packets a resolver library never
  sees. **systemd v257** parses DNR (`UseDNR=`) and hands designated
  resolvers to resolved for auto-DoT, but exposes no generic app API. So:
  the OS presents a configured DoT server (c-ares reads it via Tier 1); if
  the OS ever hands only an ADN, feed DDR's name-based flow.
- **Sources.** RFC 9463; IANA registries; systemd `UseDNR=` NEWS.

**Auto-discovery support (2026, with caveats):** Windows 11 = DDR yes, DNR
yes (opt-in). systemd = DNR yes (v257, internal), no DDR. Apple = DDR yes
(iOS16/macOS13), DNR no. Android/Chromium = neither. Some "no" entries are
absence-of-evidence.

---

### Recommendations for c-ares (priority order)

**Tier 1 — read the OS's real DoT config (high value, clean interfaces):**
1. **Linux / systemd-resolved** — the single best target. Unprivileged,
   live, machine-readable, exposes **per-server SNI, port, mode, and
   per-link/per-domain scoping**. Prefer **Varlink
   `io.systemd.Resolve.DumpDNSConfiguration`** (≥259) with **fallback to the
   `org.freedesktop.resolve1` D-Bus `DNSEx`/`CurrentDNSServerEx`/`DNSOverTLS`
   properties** (≥239). Also covers NetworkManager systems (NM pushes into
   resolved). Bypasses the 127.0.0.53 stub exactly as intended.
2. **Android / Private DNS** — a minimal extension of the existing
   ConnectivityManager JNI (`isPrivateDnsActive()` +
   `getPrivateDnsServerName()`, API 28+, resolved optionally).

**Tier 2 — registry / file parse (workable, caveated):**
3. **Windows** — registry read of
   `…\Dnscache\InterfaceSpecificParameters\{GUID}\DohInterfaceSettings\…`
   (unprivileged). Covers **DoH fully**; **DoT is registry-only and
   undocumented** — best-effort. The `DNS_INTERFACE_SETTINGS3` API is
   DoH-only.
4. **Local forwarders (unbound/stubby/unwind/local_unbound) when c-ares runs
   on the same host** — parse the forwarder config. Non-standard,
   permission- and presence-dependent; opportunistic best-effort.

**Blocked / not worth reading (rely on explicit config or DDR):**
- **macOS / iOS / iPadOS** — encrypted-DNS config is not in `dnsinfo`/
  `scutil`; only the entitlement-gated NetworkExtension API. Rely on
  explicit application configuration.
- **ChromeOS** — DoH-only, unreadable by a sandboxed native lib.
- **NetworkManager keyfiles** — root-only; read resolved instead.
- **`/etc/resolv.conf`** — structurally cannot carry DoT.

**Cross-platform fallback — implement DDR (RFC 9462).** When the OS yields
only a **plaintext resolver IP** (the common case everywhere the above
fails), c-ares can auto-upgrade **on its own**: one SVCB query to
`_dns.resolver.arpa` on that IP, then a TLS handshake whose cert **must
carry the original resolver IP in an `iPAddress` SAN** (Verified Discovery).
Live at the two largest public resolvers; the most portable path to
encrypted DNS. **DNR (RFC 9463)** is not directly consumable by c-ares; rely
on the OS (e.g. systemd-resolved fed by networkd v257) to translate DNR into
a DoT server that c-ares then reads via Tier 1.

## Progress log

Newest first.

- 2026-07-12: reorganized the plan so completed items live in the phase
  where they were actually done.  Moved the whole "Manual configuration
  (URI scheme)" subsection into Phase 1 (it's foundational -- nothing is
  configurable or testable without it); moved the CI-legs item into Phase 1
  Step 0 and the channel-level early-data test note into Phase 1's Early
  Data item.  Phase 2/3 now contain only remaining work (no completed
  boxes).
- 2026-07-12: merged the standalone OS DoT config research
  (`DOT-OS-CONFIG.md`) into this document as the "Research findings"
  subsection under "OS DoT configuration sources"; removed the separate
  file and its `.reuse/dep5` entry.  Single tracking document now.
- 2026-07-11: OS DoT config research completed (platform matrix, exact
  interfaces, permissions, sources; then a companion doc, since merged
  into this document -- see the 07-12 entry).  Two plan assumptions corrected: Windows now has a native DoT
  client (registry-only, undocumented schema), and Apple dnsinfo/scutil --
  what c-ares reads today -- exposes no encrypted-DNS info at all (only
  the entitlement-gated NEDNSSettingsManager does).  Resulting priority:
  Tier 1 = systemd-resolved (Varlink/D-Bus, exposes SNI/port/mode/scope)
  and Android Private DNS; Tier 2 = Windows registry + local forwarders;
  blocked = macOS/iOS/ChromeOS (rely on explicit config); DDR (RFC 9462)
  as the self-contained cross-platform fallback.  Plan OS section updated
  to match.
- 2026-07-11: plan expanded to full scope after reviewing issue #818
  intent.  Added first-class sections for server security grouping
  (decided policy: strict tier + opt-in ARES_FLAG_DNS_ALLOW_DOWNGRADE,
  no silent plaintext downgrade by default), bootstrap resolution
  (IP<->hostname over insecure servers, never for user queries),
  configuration flexibility (custom CA, client certs/mTLS, hostname
  modes), additional crypto backends (Schannel/Apple challenges from the
  issue), and OS DoT config sources with a companion research doc
  the OS DoT config research (Android/systemd-resolved/macOS/Windows +
  DDR/DNR; originally a companion doc, later merged into this document).
  Added a top-level Scope overview.  No phase renumbering (issue predates
  this plan; intent only).
- 2026-07-11: TFO composition landed.  TFO is enabled for TLS connections
  too, so OpenSSL's ClientHello (with 0-RTT early data on a resumed
  session) rides the SYN via the existing TFO_INITIAL sendto path -- true
  0-RTT including the TCP round trip, degrading cleanly where TFO is
  unavailable.  One-condition change in ares_open_connection; the BIO ->
  ares_conn_write_raw path and the flush-on-TFO_INITIAL guard make it
  automatic.  DoT/early-data tests deterministic with TFO active, ASAN
  clean, non-TLS TCP unchanged.  Task #5 (Early Data + TFO) complete.
- 2026-07-10: TLSv1.3 Early Data (0-RTT) integrated into the connection
  layer.  `ares_conn_write()` feeds the pending query into the early-data
  flight during the handshake when the resumed session has budget, tracks
  it in `conn->tls_earlydata_sent` without consuming out_buf, and
  reconciles on handshake completion (accepted -> consumed; rejected ->
  replayed via the normal write).  New end-to-end CryptoDoTEarlyData test
  (query 1 caches a session + connection closes; query 2 resumes and rides
  0-RTT, server observes it via SSL_read_early_data) -- deterministic
  15/15, ASAN clean, no regression to the 358 non-TLS mock tests.  TFO
  composition (SYN-ride) remains as a distinct follow-on.
- 2026-07-09: Phase 1 CI green across the full matrix (only the Coveralls
  *upload* step fails -- fork PRs can't access the repo token; Build/Test/
  Generate-Coverage in that job pass).  Functional DoT is validated on
  Linux (Werror/ASAN/containers), macOS, the BSDs, Solaris, MSVC x64/x86
  (with and without OpenSSL), and MSYS2 mingw/clang, both crypto and
  no-crypto builds.  Phase 1 is the shippable milestone; 0-RTT early data
  + TFO (below) is the remaining optimization.
- 2026-07-09: Phase 1 CI shakeout.  Two real regressions caught and fixed
  (folded into the integration commit): (1) parse_nameserver_uri() never
  zeroed its output struct -- unlike parse_nameserver() -- so the new
  use_tls field was stack garbage on the URI path, and ares_dup()'s
  CSV->URI round-trip could then set use_tls spuriously, making a plain
  server attempt a TLS handshake (VerifySocketFunctionCallback failure on
  all platforms); (2) a clang-format changed-lines miss.  The MINGW64 crypto-build failure of the UDP burst-stress
  MockUDPEventThreadMaxQueriesTest turned out to be a real (if
  DoT-unrelated) issue: the crypto context was initialized eagerly in
  every ares_init(), and on Windows that enumerates the entire system
  root cert store (plus OpenSSL provider load + SSL_CTX) -- per channel,
  even for channels that never use TLS.  That latency pushed the
  timing-sensitive burst test over its edge.  Fixed by making the backend
  lazy: ares_crypto_ctx_init() now only sets up the cheap session-cache
  tables, and the OpenSSL provider/SSL_CTX/CA-root work is deferred to
  ares_crypto_ctx_ensure_backend() on first TLS use (ares_tls_create /
  ares_tls_set_cadata).  Non-DoT channels pay nothing.
- 2026-07-09: Phase 1 connection integration landed.  DoT is now
  functional end-to-end: `dns+tls://ip[:port]?hostname=&verify=` server
  config (identity-aware dedup, CSV round-trip), TLS flag + session on the
  connection, lazy handshake pump from the I/O entry points, raw/routed
  read-write split, SNI + strict/opportunistic verification, session key
  with real hostname, graceful close.  New tests: TLSServerConfigCSV,
  CryptoDoTQuery (real ares_gethostbyname over a threaded in-test DoT
  server, connection reuse asserted), CryptoDoTVerifyFail.  Integration
  surfaced the read-ahead race (see defect list) -- removed read-ahead,
  now deterministic (15/15).  Full suite green under default and crypto
  builds.
- 2026-07-09: matrix green again at 29/29 after the MSVC leg landed.
  MSVC shakeout: chocolatey deploys OpenSSL to 'C:\Program Files\OpenSSL'
  (and currently ships OpenSSL 4.0.x, so the backend now has a
  compile/link data point against the new major version).  The Alpine leg
  caught the best bug of the batch: event translation allocated on every
  ares_process_fds() call even with no TLS connections, and dropped all
  fd events on allocation failure -- now allocation-free on the non-TLS
  hot path with raw-event fallback on ENOMEM (spurious TLS wakeups are
  harmless, dropped events are not).
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
- 2026-07-08: branch squashed onto current main (`513601c3`); this
  document added.  State: building blocks only, feature inert; defect list
  and phased plan recorded above.
