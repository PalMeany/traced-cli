# traced

**traced** is a traceroute for people who need to know *where* packets actually go and *who* touches them.
It is a single static Go binary with a live MTR view, trace history with diffs and a local web map.

- **Probes:** ICMP, TCP and UDP over IPv4 and IPv6. ICMP works **without sudo** on macOS through an unprivileged datagram ICMP socket. When run as root, traced uses raw sockets.
- **ECMP:** every TTL gets several probes (3 by default), each on its own flow. Every router that answers is shown, so load-balanced branches are visible.
- **MPLS:** label stacks are decoded from ICMP extensions (RFC 4884 / RFC 4950).
- **SNI/DPI probe:** sends a TLS ClientHello with a chosen SNI and runs a TTL scan to find the hop where a RST, a silent drop or a ServerHello happens. A control SNI is sent for comparison.
- **Geolocation from several sources, checked against RTT physics:**
  - rDNS parsing: 220+ IATA/city codes plus backbone naming schemes (Cogent, Arelion, NTT CLLI, Lumen/Level3, GTT, HE, RETN, Rostelecom, MTS, Selectel, clouds…)
  - an IXP prefix table (1,094 PeeringDB prefixes are built in, and `traced update-ixp` refreshes them)
  - RFC 8805 geofeeds, found automatically through RDAP/WHOIS (RFC 9632)
  - RIPE IPmap (an answer backed only by a wide latency radius plus IPmap's "most populous city" pick is treated as a guess, and the radius itself as a constraint)
  - ip-api / ipinfo or a local `.mmdb`
  - the registry country of the allocation (RDAP/WHOIS) as a cross-check: weak claims for another country are demoted, and its main city inside the IPmap latency radius is offered instead (`registry`)

  A location that would need faster-than-fibre RTT (for example "Ashburn" for a hop 5 ms from Moscow) is flagged `rtt_anomaly`. traced then falls back to the next plausible source, or interpolates from the neighbouring hops. A weak claim sandwiched between two hops in the same city with no time for the detour (Stockholm → "Dublin" → Stockholm within 1 ms) is interpolated too.
- **WHOIS/RDAP:** for a domain target: registrar, dates, NS, status, DNSSEC and DNS records. For an IP: ASN, org, netname, RIR and geofeed. `traced whois` also adds the provider profile and a reputation verdict for every address.
- **Provider / ASN analytics** (`traced asn <ASN|IP|domain>`), all sources queried in parallel with their own timeouts; a source that times out or answers 429 is reported and the rest still renders:
  - **PeeringDB:** network type, declared traffic (`info_traffic`), ratio, scope, peering policy, max prefixes, IRR as-set, every exchange (port speed, route-server peering) and facility with coordinates
  - **CAIDA AS Rank:** global rank, customer cone (AS / prefixes / addresses), upstream / peer / customer counts, organisation
  - **RIPEstat:** announced IPv4/IPv6 prefixes (count, address space, full list with `--prefixes`), BGP neighbours and the strongest upstreams, RIS visibility, first seen
  - **APNIC Labs:** eyeball estimate — users, share of the country and of the Internet, per economy
- **Reputation** (`traced rep <IP|ASN|domain>`), verdict **Clean / Low risk / Suspicious / Dirty** with a line per source:
  - local copies of **Kinetio DTIH** (addresses and subnets with attack types), **Spamhaus DROP v4/v6 and ASN-DROP**, **FireHOL level1**, **Emerging Threats** block list, **Tor exit** list
  - **Spamhaus ZEN** DNSBL for IPs; the documented test point is checked first, and the `127.255.255.25x` refusal codes of public resolvers are reported as *skipped*, never as a listing (`TRACED_DNSBL_RESOLVER=ip` uses your own resolver)
  - **AbuseIPDB** when `ABUSEIPDB_API_KEY` is set (otherwise `skipped: no API key`)
  - for an AS every list is matched against its announced prefixes, and Kinetio hits are weighed by the size of the address space (a few scanners in a cloud ≠ a dirty hoster)
  - lists overlap (FireHOL level1 contains DROP), so the strongest signal sets the score and each further listing adds 5 instead of summing
- **Open data cache** (`traced feeds`, `traced feeds update [name…] [--force]`): everything lives in `~/.cache/traced/feeds` with a TTL per feed (6 h … 7 days). A stale feed is refreshed on use; if the refresh fails the old copy keeps working and the command says how old it is. Downloads use ETag / If-Modified-Since. PeeringDB comes as a weekly bulk dump (anonymous API access is limited to a few calls per hour); when the API refuses, the daily dump mirrored by CAIDA is used.
- **Live MTR:** an ANSI terminal UI with loss, jitter, sparklines, ASN, city/IXP and geo source.
- **History and diff:** every trace is stored, and `traced diff` shows changed hops, the AS path and RTT deltas.
- **Local web map** (`go:embed`, MapLibre GL, CARTO Dark Matter basemap):
  - city clusters you can click, labelled with their hop numbers; segments colored from the first hop to the last, with a direction arrow, and dashed lines for loss and ECMP branches
  - a path that goes back and forth over the same cities (Moscow → Frankfurt → Moscow → Helsinki) draws every pass as its own arc: the way back bows to the other side, repeated passes bow further out
  - hovering a segment highlights it with its hop rows (hop a → b, cities, Δrtt); hovering or clicking a hop in the table shows its segment on the map
  - overlay of several routes, with an AS-path diff
  - live traces streamed over SSE
  - switchable layers: **Submarine cables (ВОЛС)** with a popup (name, length, RFS, owners, landing stations), **Landing points**, and **IX / PoP** — exchanges and facilities of every AS on the route (from PeeringDB)
  - clicking a hop (table row, `ASxxxx` in a marker popup) opens the **AS card**: CAIDA rank and cone, PeeringDB type/traffic/ratio/policy, prefixes, eyeballs and the reputation verdict
  - **cable hints** for long segments (≥ 1000 km): cables that land near both ends are named in the segment popup and highlighted on the map. This is a heuristic — nothing proves the packets used that cable

- **Online map link:** after a trace (and when you quit `traced mtr`) the result is published and a link is printed — `карта: https://traced.netkitty.dev/t/<id>`. The page is the same map in read-only mode: hops, ASN, cities, RTT, the path and the hop table. Links live 30 days. `--no-share` or `TRACED_NO_SHARE=1` turns it off; `--share-url` points to your own `traced share-server`.

![web map](docs/screenshot.png)

> **Privacy:** there are no remote probes. Everything runs on your machine. By default the finished trace itself (target, hop IPs, PTR names, ASN, geo, RTT, the target's public WHOIS/DNS and SNI probe, the public AS profiles of the path and cable hints) is uploaded for the map link — nothing else: no history id, interface or tunnel names, notes, and your public IP is not added (the first private hop such as 192.168.1.1 stays as is). `--no-share` / `TRACED_NO_SHARE=1` keeps everything local; then only lookups (RDAP, IPmap, GeoIP, DNS, PeeringDB/CAIDA/RIPEstat for AS profiles — `--no-asn` turns those off) and basemap tiles leave the host. `--offline` keeps geolocation local (rDNS, IXP table, local geofeeds, mmdb).
> Site: https://traced.netkitty.dev (зеркало https://traced.nuvira.su)


## Без установки (как bench.sh)

```sh
curl -sL traced.netkitty.dev | sh -s -- 1.1.1.1
wget -qO- traced.netkitty.dev | sh -s -- sni example.com
```

В конце печатается ссылка на карту трассы: `карта: https://traced.netkitty.dev/t/<id>` (хранится 30 дней; отключить — `--no-share` или `TRACED_NO_SHARE=1`):

```sh
curl -sL traced.netkitty.dev | sh -s -- 1.1.1.1 --no-share
```

Скрипт определяет ОС/архитектуру (linux amd64/arm64/arm/386, macOS, FreeBSD), качает бинарник из последнего релиза во временную папку, сверяет SHA256, запускает с вашими аргументами и удаляет. На linux без root трассировка запускается через sudo. Конкретная версия: `TRACED_VERSION=v1.2.0`.

## Install

```sh
go install github.com/PalMeany/traced-cli/cmd/traced@latest
# or
git clone https://github.com/PalMeany/traced-cli && cd traced-cli && make install   # -> $(go env GOPATH)/bin/traced
```

Go 1.26+ is required. There are no CGO dependencies.

## Usage

```text
traced <target> [flags]          trace (ICMP by default)
traced mtr <target> [flags]      live MTR view (q quit, p pause, r reset, n names, m map)
traced sni <host> [--sni name]   TLS ClientHello probe: where does a filter cut the SNI
traced whois <domain|ip>         RDAP/WHOIS + DNS + ASN + geofeed + reputation
traced asn <ASN|ip|domain>       provider profile: PeeringDB, CAIDA rank/cone, BGP prefixes, eyeballs
traced rep <ip|ASN|domain>       reputation: Kinetio, Spamhaus DROP/ZEN, FireHOL, ET, Tor, AbuseIPDB
traced feeds [update [name…]]    open data cache: cables, PeeringDB, APNIC, reputation lists
traced history [--limit N]       stored traces
traced diff <id1> <id2>          compare two traces (ids, unique prefixes or 1 = newest)
traced map [id...]               open the local web map (with traces preselected)
traced serve [--listen addr]     web UI without opening a browser (127.0.0.1:7477)
traced update-ixp                refresh the IXP prefix table from PeeringDB (feeds update does it too)
```

Common flags:

| flag | meaning |
|---|---|
| `-I` / `-T` / `-U` | ICMP (default) / TCP SYN / UDP probes |
| `-p PORT` | destination port (TCP 443, UDP 33434) |
| `-4` / `-6` | force the address family |
| `-q N` | probes per hop (default 3, ECMP discovery) |
| `-m N`, `-w DUR`, `--gap DUR` | max TTL, probe timeout, pause between packets |
| `--paris` | keep one flow id (one path through load balancers) |
| `--iface auto\|none\|en0` | bind probes to an interface; `auto` (default) bypasses VPN/TUN routes |
| `--sni NAME` | run the SNI probe against the target after the trace |
| `--web` | open the result on the map |
| `--json` | machine-readable output |
| `--no-geo`, `--offline`, `--mmdb FILE`, `--geofeed FILE\|DIR` | geolocation controls |
| `--origin LAT,LON\|CODE` | your own location, for stricter RTT physics checks |
| `-n`, `--no-whois`, `--no-save` | numeric output; skip WHOIS; do not save the trace |
| `--no-share` | do not publish the trace / print the online map link (also `TRACED_NO_SHARE=1`) |
| `--share-url URL` | publish to your own share server instead of https://traced.netkitty.dev |
| `--no-asn` | skip the AS profiles of the path (rank, traffic, PoPs, reputation) |
| `--no-rep`, `--no-dnsbl` | `asn`/`whois`: skip the reputation check / the Spamhaus ZEN query |
| `--prefixes` | `asn`: print every announced prefix |
| `--force` | `feeds update`: ignore the TTL |

Environment variables: `TRACED_IPINFO_TOKEN`, `TRACED_MMDB`, `TRACED_IFACE`, `TRACED_ORIGIN`, `TRACED_NO_SHARE`, `TRACED_SHARE_URL`, `NO_COLOR`,
`ABUSEIPDB_API_KEY` (optional AbuseIPDB check), `PEERINGDB_API_KEY` (higher PeeringDB limits), `TRACED_DNSBL_RESOLVER=ip[:port]`,
`TRACED_DNSBL=0` (no ZEN queries), `TRACED_FEEDS_AUTO=0` (never refresh feeds on use), `TRACED_CACHE_DIR`.
With `--json` the link is added as the `share_url` field.
History is stored in `~/.local/share/traced/traces/*.json`. The cache (RDAP, PTR, ASN, IPmap, GeoIP, geofeeds, PeeringDB) lives in `~/.cache/traced/`, the open data feeds in `~/.cache/traced/feeds/`.
Your own geofeeds can be dropped into `~/.config/traced/geofeeds/*.csv`.

## Examples

```console
$ traced cloudflare.com -T
› route to 104.16.133.229 goes through tunnel utun8 — bypassing it via en0 (use --iface none to trace inside the tunnel)
traced cloudflare.com (104.16.133.229) TCP:443 · dgram socket, via en0
  #  host                                         network                  location               source   rtt ms
  1  192.168.1.1                                                           private                         6.58 6.32 7.10
  3  as25513.asbr.router (212.188.6.45)           AS8359 MTS MTS PJSC      Ryazanskiy, RU         ipmap    10.9 7.73 9.23
  4  mag9-cr03-be12.51.msk.mts-internet.net (…)   AS8359 MTS MTS PJSC      Moscow, RU             rdns     9.88 8.25 9.97
  8  radio-cr01-ae3.0.hel.mts-internet.net (…)    AS8359 MTS MTS PJSC      Helsinki, FI           rdns     33.8 27.5 ECMP×2
  └  radio-cr01-ae9.0.hel.mts-internet.net (…)    AS8359 MTS MTS PJSC      Helsinki, FI           rdns     27.0
  9  162.158.236.6                                AS13335 CLOUDFLARENET    Helsinki, FI           geofeed  32.0 29.1 27.6
 11  104.16.133.229                               AS13335 CLOUDFLARENET    Helsinki, FI           interp   29.2 27.2 26.9 ⚠ rtt

RTT physics
  ⚠ 104.16.133.229   ipmap says Taipei TW, but 7349 km from Ryazanskiy (seen at 7.7 ms) — 7.7 + 26.9 ms RTT allow at most 3462 km → using interp

reached cloudflare.com in 11 hops, 27.8 ms, TCP probes · AS path AS8359 → AS13335 · saved 261126-011334-wyd

Domain cloudflare.com [rdap rdap.org]
  registrar    Cloudflare, Inc.
  created      2009-02-17
  expires      2033-02-17 (in 2275 days)
  …
IP 104.16.133.229 [rdap]
  ASN          AS13335 CLOUDFLARENET - Cloudflare, Inc., US
  geofeed      https://api.cloudflare.com/local-ip-ranges.csv
```

UDP shows MPLS label stacks and ECMP branches:

```console
$ traced 104.16.132.229 -U -n
  6  212.188.28.102      8.79 8.48 8.93 MPLS 63130
  8  212.188.29.109      33.4 34.2 ECMP×2
  └  212.188.29.23       43.5
```

The SNI probe locates the hop where interference starts:

```console
$ traced sni 104.16.133.229 --sni www.example-blocked.com
  ttl  9  ttl-exceeded   162.158.236.6      34.2 ms
  ttl 10  ttl-exceeded   162.158.236.11     36.3 ms
  ttl 11  rst            —                  28.0 ms    connection reset
SNI www.example-blocked.com → 104.16.133.229:443
  target   www.example-blocked.com  rst            30.3 ms
  control  example.com              server-hello   32.1 ms    TLS 1.3 h2
  path     server is 11 hops away, interference at TTL 11
  verdict  SERVER-REJECTED — … the server (or a box in front of it) refuses this name, no on-path DPI seen
```

A RST or silence that starts before the server's hop is reported as `SNI-BLOCKED … interference starts at TTL k (right after <router>)`.

After a trace the AS on the path and the cable hints are listed:

```console
$ traced speedtest.newark.linode.com
…
AS on the path
  AS8359    Mobile TeleSystems PJSC        Low risk    rank #53 · cone 1.3k AS · Cable/DSL/ISP · 10-20Tbps · 436/57 pfx · 1.0M users RU · 15 IX
  AS1299    Arelion (Twelve99)             Clean       rank #3 · cone 42k AS · NSP · 100+Tbps · 119/12 pfx · 33k users GB
  AS20940   Akamai Technologies            Low risk    rank #2122 · cone 14 AS · Content · 100+Tbps · 3946/776 pfx · 2.0k users JP · 256 IX

Submarine cables (heuristic: cables landing near both ends of a long segment)
  hop 11→12 Copenhagen, DK → New York, US 6188 km: Havfrue/AEC-2, Atlantic Crossing-1 (AC-1)
```

Provider profile and reputation:

```console
$ traced asn AS8359
ASN AS8359 Mobile TeleSystems PJSC
  CAIDA rank     #53
  organization   MTS PJSC Russia
  customer cone  1.3k AS · 30k prefixes · 29.7M addresses
  neighbours     3 upstream · 367 peers · 512 customers · 54 siblings

PeeringDB net 983, updated 2026-03-03
  type           Cable/DSL/ISP
  traffic        10-20Tbps
  ratio          Balanced
  peering policy Selective · locations Preferred · contracts Not Required
  exchanges      15 IX, 14 facilities
                 DE-CIX Frankfurt                       Frankfurt DE           600G
                 AMS-IX                                 Amsterdam NL           200G
  …
BGP (RIPEstat) MTS MTS PJSC
  announced      436 IPv4 · 57 IPv6 · 1.7M IPv4 addresses · 2.0M IPv6 /48s
  visibility     v4 323/323 · v6 313/313 RIS peers
  top upstreams  AS1299 AS20764 AS6939 AS13030 …

Eyeballs (APNIC Labs) 24/11/2026
  users          1.0M ≈ 0.025% of the Internet

sources: peeringdb ✓ cached · caida ✓ · ripestat ✓ · apnic ✓ cached

Reputation AS8359  Low risk (20/100)
  ✓ Spamhaus DROP          no listed networks in the announced space
  ✓ Spamhaus ASN-DROP      not listed
  ✗ Kinetio DTIH           83 entries (83 addresses, 0 subnets): scanner×42, bruteforce×41 [+20]
  …

$ traced rep 185.220.101.1
Reputation 185.220.101.1  AS60729 TORSERVERS-NET … 185.220.101.0/24  Suspicious (45/100)
  ✓ Spamhaus DROP          not listed
  – Spamhaus ZEN (DNSBL)   skipped: DNSBL refuses queries via public/open resolvers (127.255.255.254); set TRACED_DNSBL_RESOLVER to your own resolver
  – AbuseIPDB              skipped: no API key (set ABUSEIPDB_API_KEY)
  ✗ Kinetio DTIH           listed (subnet 185.220.101.0/24): bruteforce×1, scanner×1 [+40]
  • Tor exit               Tor exit node [+15]

$ traced feeds update
  ✓ kinetio           22558 entries 700ms
  ✓ spamhaus-drop4    1737 entries 500ms
  …
  ✓ cables            714 entries 16.2s
```

Other commands:

```sh
traced mtr 1.1.1.1 -T -p 443     # live view
traced history                    # list
traced diff 2 1                   # previous vs newest
traced map 1 2                    # overlay both on the map
traced whois 8.8.8.8 --json
traced asn cloudflare.com --prefixes
traced rep AS13335 --json
traced feeds                      # what is cached, how old
```

## How it works

- **Engine** (`internal/trace`):
  - Probes are sent in rounds. Round *i* sends flow *i* to every TTL, so no router gets a burst, and later rounds stop at the destination.
  - ICMP flows use a different echo id per flow, and the checksum is kept constant inside a flow (the Paris-traceroute trick). NATs keep one mapping per id, so flows that share an id lose their replies.
  - TCP probes are non-blocking `connect()` calls with `IP_TTL` set. UDP flows are bound sockets, and the payload length encodes the TTL.
  - Time-exceeded and unreachable messages are matched through the quoted inner header (TCP/UDP source port, UDP length, ICMP sequence).
- **Geo** (`internal/geo`):
  - Each source produces candidates with a confidence score.
  - The validator walks the path. A candidate is rejected when `dist(anchor, candidate) > (rtt_anchor + rtt_hop) × 100 km/ms + slack`. That is the triangle inequality with light in fibre at about 200 km/ms.
  - An optional `--origin` adds `dist(origin, candidate) ≤ rtt × 100 km`.
- **Feeds** (`internal/feeds`): a registry of datasets with TTLs; downloads are validated by parsing before they replace the old copy (a broken answer never wipes good data), and concurrent refreshes of one feed share a single download. Network lists become a prefix set (deduplicated, types merged) answering longest-prefix lookups and "what lies inside this prefix" queries for AS checks.
- **ASN / reputation** (`internal/asn`, `internal/rep`): every source has its own timeout and cache (PeeringDB 7 days via the bulk feed, CAIDA 7 days, RIPEstat 6–24 h, AbuseIPDB 6 h). During a trace every new AS is profiled in the background while probing continues; the profiles (with up to 40 PoPs nearest to the route) and the cable hints are stored with the trace and published with the map link.
- **Web** (`internal/web`):
  - The server listens on 127.0.0.1.
  - Host and Origin are checked, which blocks DNS rebinding and cross-site requests to `/api/run`.
  - Traces stream over Server-Sent Events.
  - `/api/cables` and `/api/landing` serve the cable map as gzip'ed GeoJSON with an ETag; `/api/asn`, `/api/rep`, `/api/feeds` back the AS card.
- **Share server** (`internal/share`, `traced share-server`): what runs behind https://traced.netkitty.dev.
  - `POST /api/traces` takes a trace (≤ 512 KB), re-decodes it into the fixed schema (unknown fields and local details dropped), stores it under a random 10-char base62 id; `GET /api/traces/<id>` returns the JSON, `GET /t/<id>` the read-only map (same embedded UI).
  - Traces expire after 30 days (`--ttl`), an hourly sweep deletes them; total size is capped (`--max-mb`).
  - It keeps its own copy of the cable map in `<dir>/cache` (refreshed weekly) for the cable layers of shared maps; AS cards on shared maps use the profiles stored with the trace.
  - Rate limit per client IP (`--rate`/`--burst`, IPv6 per /64). `CF-Connecting-IP` is trusted only when the peer is a Cloudflare edge address; behind a local nginx the peer comes from `X-Real-IP`.
  - Run your own: `traced share-server --listen 127.0.0.1:7480 --dir /var/lib/traced-share --public-url https://your.host`, proxy `/t/` and `/api/` to it, then `traced --share-url https://your.host 1.1.1.1`. A systemd unit and nginx snippet are in [`deploy/`](deploy/).

## Platform notes

- **macOS:** everything works without root. Under a VPN or TUN (sing-box, Clash, WireGuard), `--iface auto` binds the probes to the physical interface (`IP_BOUND_IF`). Without that, the tunnel would fake or hide the hops.
- **Linux:** unprivileged ping sockets do not receive the ICMP errors traceroute needs. Run traced as root, or give the binary the capability: `sudo setcap cap_net_raw+ep $(which traced)`. It will then use raw sockets, and that mode also decodes MPLS labels.
- **Rate limits:** the free ip-api endpoint allows 45 requests per minute. Results are cached for 7 days, so repeated traces are instant. Anonymous PeeringDB API access is limited to a few requests per hour (`Retry-After` of ~40 minutes); traced therefore uses the weekly bulk feed and remembers a 429 instead of retrying. RIPEstat `routing-status` can take more than 15 s for very large networks; it is then reported as `partial`.
- **Spamhaus ZEN** does not answer queries that arrive through public resolvers (8.8.8.8, 1.1.1.1, many VPN/Tailscale DNS setups). Point `TRACED_DNSBL_RESOLVER` at a recursive resolver of your own.
- **Data licences:** the submarine cable map is © TeleGeography (CC BY-NC-SA 3.0), PeeringDB data is under its AUP, Spamhaus DROP lists are free for use under their terms, APNIC Labs data is reusable with attribution.

## Development

```sh
make test    # unit tests: packet/MPLS parser, rDNS/IATA, IXP, RFC 8805, RTT physics, ECMP/diff, RDAP/WHOIS, MTR stats, web guard, share server,
             # feed parsers (Kinetio, Spamhaus, netset, APNIC, cables, PeeringDB), IP/CIDR/ASN matching, reputation and ASN aggregation
make build
make cross   # linux/darwin × amd64/arm64 into dist/
```
