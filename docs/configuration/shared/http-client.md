---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

A string or an object.

When string, the tag of a shared [HTTP Client](/configuration/shared/http-client/) defined in top-level `http_clients`.

When object:

```json
{
  "engine": "",
  "version": 0,
  "disable_version_fallback": false,
  "headers": {},
  "fallback": [],
  "outbounds": [],

  ... // HTTP2 Fields

  "tls": {},

  ... // Dial Fields
}
```

### Fields

#### engine

HTTP engine to use.

Values:

* `go` (default)
* `apple`

`apple` uses NSURLSession, only available on Apple platforms.

!!! warning ""

    Experimental only: do not use in hot paths on iOS and tvOS.

Supported fields:

* `headers`
* `tls.server_name` (must match request host)
* `tls.insecure`
* `tls.min_version` / `tls.max_version`
* `tls.certificate` / `tls.certificate_path`
* `tls.certificate_public_key_sha256`
* Dial Fields

Unsupported fields:

* `version`
* `disable_version_fallback`
* HTTP2 Fields
* QUIC Fields
* `tls.engine`
* `tls.alpn`
* `tls.disable_sni`
* `tls.cipher_suites`
* `tls.curve_preferences`
* `tls.client_certificate` / `tls.client_certificate_path` / `tls.client_key` / `tls.client_key_path`
* `tls.fragment` / `tls.record_fragment`
* `tls.kernel_tx` / `tls.kernel_rx`
* `tls.ech`
* `tls.utls`
* `tls.reality`

#### version

HTTP version.

Available values: `1`, `2`, `3`.

`2` is used by default.

When `3`, [HTTP2 Fields](#http2-fields) are replaced by [QUIC Fields](#quic-fields).

#### disable_version_fallback

Disable automatic fallback to lower HTTP version.

#### headers

Custom HTTP headers.

`Host` header is used as request host.

#### fallback

Tags of shared HTTP clients defined in top-level `http_clients`, tried in order when a download
through this client fails.

A remote rule-set whose download through this client fails (an error, an unexpected status,
no data for the stall timeout, or content that is not a rule-set) repeats it through each
fallback client in turn, until one brings the list. The fallbacks of a fallback client are not
followed. Other users of the client do not fall back.

#### outbounds

Tags of outbounds a download through this client may go through, the first one the default
first try. Only for a client of top-level `http_clients`; not with `detour` or `fallback`. A
user of the client that does not know the ways (any but a remote rule-set) goes through the
first one.

A remote rule-set downloads through the ways in this order, for the host of its URL:

1. the way that brought the last file from this host;
2. the first way of the list;
3. the ways that brought a file from another host, the fastest first;
4. the ways the URL tests passed, the lowest delay first (a group by the outbound it uses now);
5. the ways not known yet, in the order of the list;
6. the ways that failed for this host, the oldest failure first.

No way is left out, but those the program that runs the box excludes (a group while it uses an
excluded outbound). The next way starts beside those under way when none of them showed
progress for 4 s (no answer yet), or a body has paused for 1 s (3 s once 1 MiB of it came); at
most three at once. The first way that brings a list that parses wins and the
others are stopped; a body that is not a rule-set (a page served with status 200) fails its way.
When the first way failed for the host the last time, the second starts with it. What the
downloads found is kept for the life of the box, and across boxes when the program that runs
them keeps it.

### HTTP2 Fields

When `version` is `2` (default).

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

When `version` is `3`.

See [QUIC Fields](/configuration/shared/quic/) for details.

### TLS Fields

See [TLS](/configuration/shared/tls/#outbound) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
