# OS DoT (DNS-over-TLS) Configuration Sources — Research

Companion research document to [`DOT-IMPLEMENTATION.md`](DOT-IMPLEMENTATION.md).

Goal: for every operating system / platform where it's relevant, determine
whether the OS's own system resolver supports DoT (RFC 7858) and exactly
how that configuration is stored and exposed — so c-ares can read the host
OS's DoT configuration (which secure resolvers, their authentication
hostnames for certificate validation, and strict-vs-opportunistic mode) the
same way it already reads plaintext DNS server configuration.

> **Status: research in progress.** This document is being compiled; the
> platform matrix and recommendations below are populated from a dedicated
> research pass and will be reviewed before any implementation depends on
> them.

<!-- The platform-by-platform findings, summary table, and recommendations
     are inserted here once the research pass completes. -->
