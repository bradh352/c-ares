# OS DoT (DNS-over-TLS) Configuration Sources — Research

Companion research document to [`DOT-IMPLEMENTATION.md`](DOT-IMPLEMENTATION.md).

Goal: for every relevant OS/platform, determine whether the OS system
resolver supports DoT (RFC 7858) and exactly how that configuration is
stored and exposed — so c-ares can read the host's DoT configuration
(secure resolvers, their authentication hostnames for certificate
validation, and strict-vs-opportunistic mode) the way it already reads
plaintext DNS config. Compiled 2026-07-11 from a dedicated multi-source
research pass; claims are cited inline, uncertainties flagged.

**Two findings corrected earlier assumptions in the plan:**
1. **Windows is no longer DoH-only.** Native DoT *client* support shipped
   (via `netsh dnsclient` / registry), including a per-server
   authentication hostname (`dothost`).
2. **Apple `dnsinfo` — what c-ares reads today — does NOT expose encrypted
   DNS.** The `dns_resolver_t` struct has no DoH/DoT field in any version;
   macOS/iOS DoT config is only reachable via the entitlement-gated
   NetworkExtension API.

---

## Summary table

| Platform | DoT in OS resolver? | Readable by unprivileged lib? | Auth hostname (SNI) exposed? | Notes |
|---|---|---|---|---|
| **Android** (Private DNS) | **Yes** (API 28+) | **Yes** — JNI `LinkProperties` (`ACCESS_NETWORK_STATE`) | **Yes** (strict); opportunistic = boolean only | Extends existing ConnectivityManager JNI. Validated DoT IPs hidden; resolve hostname yourself. |
| **Linux — systemd-resolved** | **Yes** (`DNSOverTLS=`) | **Yes** — D-Bus `resolve1` or Varlink `DumpDNSConfiguration` | **Yes** (`#ServerName` in `DNSEx`) | **Best target on Linux.** Also reflects what NetworkManager pushed. |
| **Linux — NetworkManager** | Only via backend (usually resolved) | **No** — keyfiles root-only `0600` | (in keyfiles, unreadable) | Read resolved instead. |
| **Linux — dnsmasq** | **No** | file only | N/A | Forwards plaintext to a local DoT daemon. |
| **Linux/BSD — unbound / stubby** | **Yes** (local forwarder) | file only, perms vary | Yes (`@853#name`, `tls_auth_name`) | Non-standard app-specific formats. |
| **/etc/resolv.conf** | **No concept** | file | **No** — structurally impossible | Bare IP; no port/SNI/TLS field. |
| **Windows 11 / Server** | **DoH yes; DoT now yes** | DoH via API or registry; **DoT registry-only** | DoT: **yes** (`dothost`), API doesn't expose it | Registry read unprivileged. DoT registry schema undocumented. |
| **macOS** | **Yes** (DoH+DoT since Big Sur) | **No** via `dnsinfo`/`scutil`; only NetworkExtension (entitlement) | Yes but only via NE / profile | c-ares' current dnsinfo path is a dead end for encrypted DNS. |
| **iOS / iPadOS** | **Yes** (same as macOS) | **No** (entitlement-gated) | Yes but unreadable by a generic lib | More locked down than macOS. |
| **ChromeOS** | **DoH-only** | **No** (Chrome-internal) | N/A | Resolve through the system resolver. |
| **FreeBSD/OpenBSD/NetBSD (base)** | **No native**; local forwarder only | file (forwarder config) | Yes (forwarder config) | `local_unbound`, `unwind`, pkgsrc unbound. |
| **OpenWrt / routers** | **No native**; local forwarder | file (on the router) | Yes (`tls_auth_name`) | LAN clients see plaintext at router IP. |
| **DDR (RFC 9462)** | Cross-platform *discovery* | **Self-contained** — c-ares does it itself | ADN validated via cert SAN | **Recommended universal fallback** from a plaintext IP. |
| **DNR (RFC 9463)** | Network push via DHCP/RA | **No** — no portable DHCP surface | ADN in the option | OS-stack territory; consume via systemd-resolved. |

---

## Android — "Private DNS"

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

## Linux — systemd-resolved (the best readable target)

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

## Linux — NetworkManager

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

## Linux — dnsmasq / unbound / stubby / resolv.conf

| Resolver | DoT? | Config | Reads | Fields | Gotchas |
|---|---|---|---|---|---|
| **dnsmasq** | No | `/etc/dnsmasq.conf`, `.d/*` | file | `server=IP[#port]` (`#`=port) | Forwards plaintext to a local DoT daemon. |
| **unbound** (local) | Yes | `/etc/unbound/unbound.conf(.d)` | file | `forward-addr: IP@853#authname`, `forward-tls-upstream: yes`, `tls-cert-bundle` | `include:` globs; recursive=no upstream. |
| **stubby** | Yes | `/etc/stubby/stubby.yml` | file (YAML) | `address_data`, `tls_port`, `tls_auth_name`, `tls_authentication` | It *is* the DoT terminator; clients see `127.0.0.1`. |
| **/etc/resolv.conf** | **No concept** | `/etc/resolv.conf` | file | **none** | **Structurally cannot represent DoT/SNI/port.** No standard extension. |

## Windows (11 / Server 2022–2025)

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

## macOS

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
  (Confidence high on the dnsinfo/scutil dead-end; medium on the exact
  profile on-disk path.)
- **Sources.** dnsinfo headers (apple-oss-distributions/configd + in-tree);
  WWDC20 10047; `com.apple.dnsSettings.managed` payload;
  `NEDNSOverTLSSettings`; NetworkExtension entitlement docs.

## iOS / iPadOS

- **Yes** (iOS/iPadOS 14, 2020), same profile payload + `NEDNSSettingsManager`
  as macOS. **Not readable** by a generic library (no `scutil`, no
  filesystem, only the entitlement-gated API). Plan for explicit app config.

## ChromeOS

- **DoH-only** (system `dns-proxy`); no DoT anywhere in Chromium `net/dns`.
  Config in Chrome prefs / enterprise policy (`DnsOverHttpsMode`/
  `Templates`), flowing over ChromeOS-internal shill/D-Bus. **Unreadable** by
  sandboxed native code; `/etc/resolv.conf` points at the local plaintext
  listener. Resolve through the system resolver.

## BSDs (FreeBSD / OpenBSD / NetBSD)

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

## OpenWrt / routers / embedded

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

## DDR (RFC 9462) and DNR (RFC 9463) — auto-discovery

Both build on SVCB (RFC 9460) + its DNS-server mapping (RFC 9461), converging
on an **ADN (Authentication Domain Name) + encrypted endpoints with
SvcParams**, authenticated by TLS certificate.

### DDR — Discovery of Designated Resolvers (client-pull)
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

### DNR — Discovery of Network-designated Resolvers (network-push)
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

## Recommendations for c-ares (priority order)

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
