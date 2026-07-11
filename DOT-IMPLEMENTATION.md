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
  research item tracked in `DOT-OS-CONFIG.md`.  Includes DDR (RFC 9462) /
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

### Manual configuration (URI scheme)

`ares_set_servers_csv()` already accepts `dns://host:port?tcpport=N` URIs
(parsed by `parse_nameserver_uri()` via `ares_uri`, written back by
`ares_get_server_addr_uri()`).  Extend with a TLS scheme:

- [x] Scheme **`dns+tls://`**, default port 853.  Implemented query keys:
  - `hostname=<name>` — authentication name (SNI + certificate
    verification); presence implies strict mode.
  - `verify=strict|opportunistic` — explicit profile override
    (opportunistic = encrypt without certificate verification; this is
    the "none" intent, so no separate `none` value was added).
  - Example: `dns+tls://1.1.1.1?hostname=one.one.one.one`
  - IP is still the URI host (c-ares dials IPs, never resolves a resolver
    name via itself); link-local `%iface` continues to work.  Rejected up
    front (`ARES_ENOTIMP`) when built without crypto.
- [x] Round-trip: `ares_get_servers_csv()` emits `dns+tls://` for TLS
      servers (`ares_server_use_uri()` extended), pinned by
      TLSServerConfigCSV.
- [x] Duplicate-server detection / server sort treats
      `(ip, port, tls, verify, hostname)` as the identity
      (`ares_server_tls_match` / `ares_sconfig_tls_match`).
- [x] Decide public API surface beyond CSV: **none** required (options
      struct untouched -> no ABI concern).  A channel-level
      "opportunistic TLS for all servers" knob can come later.
- [ ] `adig -s dns+tls://...` works for free via CSV parsing (untested
      end-to-end against a live DoT server); add a note to adig docs.
- [ ] Docs: `ares_set_servers_csv.3` scheme table; `FEATURES.md` entry.

### Host OS configuration

Reading the host OS's DoT configuration is a substantial research +
implementation area covered in its own section below (OS DoT configuration
sources) and the companion research doc `DOT-OS-CONFIG.md`.  It is listed
here only to mark where it slots into config hookup.

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
- [x] **Skip / relax hostname validation** — already available as
      `verify=opportunistic` (encrypt without verification); a
      verify-chain-but-not-name middle mode could be added if needed.
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
- [x] **Early data through the channel**: CryptoDoTEarlyData verifies the
      second connection sends the query as early data (server-side
      `SSL_read_early_data()` observes exactly one early query), the answer
      is correct, and no query is lost or duplicated (2 accepts, 2 queries
      total).  The rejection→replay contract is covered at the backend
      level by CryptoTLSEarlyDataReject; a channel-level reject variant
      (fresh server ticket keys) could be added but the backend test
      already pins the no-loss/no-dup behavior.
- [ ] **Event-loop integration**: run the mock-TLS suite under all event
      backends (epoll/kqueue/poll/select/IOCP configurations CI already
      exercises) — the want-flag remapping is exactly the kind of thing
      that behaves differently per backend.
- [ ] **Live tests** (opt-in, like existing live suite): 1.1.1.1 /
      8.8.8.8 / 9.9.9.9 with their hostnames, strict mode.
- [x] **CI**: `CARES_CRYPTO=ON` legs running on every push via draft PR
      #1252: Ubuntu (build+test incl. containers, Werror) + Ubuntu ASAN,
      MSYS2 MINGW64/CLANG64 (mingw openssl), and MSVC x64
      (choco OpenSSL) — the MSVC leg validates compile/link and the full
      non-TLS suite under the crypto build since the TLS harness is
      POSIX-only.  All other legs keep guarding the no-crypto stubs.
      Remaining: macOS crypto leg (Security-framework root loading is
      only compile-checked today via local dev builds); nmake/static
      makefiles stay stub-only by design.  `reuse lint` covers new files
      via the existing job.
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
plaintext DNS config.  The research is **complete** — full platform matrix,
exact interfaces, permissions, and sources in
[`DOT-OS-CONFIG.md`](DOT-OS-CONFIG.md).  Key findings and the resulting
implementation priority:

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

## Progress log

Newest first.

- 2026-07-11: OS DoT config research completed and written to
  DOT-OS-CONFIG.md (platform matrix, exact interfaces, permissions,
  sources).  Two plan assumptions corrected: Windows now has a native DoT
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
  DOT-OS-CONFIG.md (Android/systemd-resolved/macOS/Windows + DDR/DNR).
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
