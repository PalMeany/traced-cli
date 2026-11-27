// Command traced is a modern traceroute: ICMP/TCP/UDP, ECMP, MPLS, SNI/DPI
// probing, multi-source geolocation validated by RTT physics, WHOIS/RDAP,
// live MTR, history/diff and a local web map.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/backbone"
	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/mtr"
	"github.com/PalMeany/traced-cli/internal/share"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/ui"
	"github.com/PalMeany/traced-cli/internal/web"
	"github.com/PalMeany/traced-cli/internal/whois"
)

const usage = `traced — traceroute with ECMP, MPLS, SNI/DPI probing, validated geo, WHOIS, MTR and a web map

usage:
  traced <target> [flags]          trace (ICMP by default)
  traced mtr <target> [flags]      live MTR view (q quit, p pause, r reset, n names, m map)
  traced sni <host> [--sni name]   TLS ClientHello probe: where does a filter cut the SNI
  traced whois <domain|ip>         RDAP/WHOIS + DNS + ASN + geofeed + reputation
  traced asn <ASN|ip|domain>       provider profile: PeeringDB, CAIDA rank/cone, BGP prefixes, history, eyeballs
  traced bgp <prefix|ip|ASN>       BGP prefix announcements, direct upstreams (RIS/BGPView) and routing history
  traced mtu <target> [-p PORT]    Path MTU probe: ICMP DF + TCP MSS/PMTUD staircase (step 20→5→1)
  traced nat [target]              NAT / double-triple NAT / CGNAT detection
  traced rep <ip|ASN|domain>       reputation: Kinetio, Spamhaus DROP/ZEN, FireHOL, ET, Tor, AbuseIPDB
  traced backbone parse|list|import|remove   terrestrial provider backbones from map pictures (traced backbone help)
  traced feeds [update [name…]]    open data cache: cables, PeeringDB, APNIC, reputation lists
  traced history [--limit N]       stored traces
  traced diff <id1> <id2>          compare two traces (ids, unique prefixes or 1 = newest)
  traced map [id...]               open the local web map (with traces preselected)
  traced serve [--listen addr]     run the web UI without opening a browser
  traced update-ixp                refresh the IXP prefix table from PeeringDB (also done by feeds update)
  traced share-server [flags]      public trace store + read-only map (what runs on traced.netkitty.dev)
  traced version

trace flags:
  -I / -T / -U        ICMP (default) / TCP SYN / UDP probes
  -p PORT             destination port (tcp 443, udp 33434)
  -4 / -6             force address family
  -q N                probes per hop, default 3 (ECMP discovery)
  -m N                max TTL (30)          -w DUR   probe timeout (2s)
  --paris             constant flow id (single path through load balancers)
  --iface IF|auto|none bind to an interface; auto bypasses VPN/TUN routes (default auto)
  --sni NAME          after the trace run an SNI probe against the target IP
  --mtu               after the trace run ICMP DF + TCP MSS/PMTUD path MTU probe (20→5→1)
  --no-nat            skip NAT / CGNAT detection
  -v / --verbose      show BGP prefix upstreams, NAT layers and terrestrial backbones
  --share-ip          show full public IP (by default masked to /16)
  --web               open the result on the web map
  --json              JSON output
  --no-geo            no geolocation/ASN       --offline  local geo sources only
  --mmdb FILE         local GeoLite2/DB-IP city database
  --geofeed FILE|DIR  extra RFC 8805 CSV (also ~/.config/traced/geofeeds/*.csv)
  --origin LAT,LON|CODE  your location (improves RTT physics checks)
  -n                  numeric (no PTR names)   --no-whois  --no-save
  --no-asn            skip AS profiles of the path (rank, traffic, PoPs, reputation)
  --no-share          do not publish the trace (by default it is uploaded and a map
                      link https://traced.netkitty.dev/t/<id> is printed; kept 30 days)
  --share-url URL     your own share server (traced share-server)

asn / rep / whois flags:
  --prefixes          asn: list every announced prefix
  --no-rep            asn/whois: skip the reputation check     --no-dnsbl  skip zen.spamhaus.org
  --force             feeds update: ignore the TTL

env: TRACED_IPINFO_TOKEN, TRACED_MMDB, TRACED_IFACE, TRACED_ORIGIN, TRACED_NO_SHARE=1, TRACED_SHARE_URL, NO_COLOR,
     ABUSEIPDB_API_KEY (optional AbuseIPDB check), PEERINGDB_API_KEY (higher PeeringDB limits),
     TRACED_VISION_API_KEY/_BASE_URL/_MODEL or GEMINI_API_KEY (traced backbone parse --engine llm),
     TRACED_DNSBL_RESOLVER=ip[:port] (own resolver for Spamhaus ZEN), TRACED_DNSBL=0, TRACED_FEEDS_AUTO=0
data: history in ~/.local/share/traced, cache and feeds in ~/.cache/traced
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, ui.C("\x1b[31m", "error: ")+err.Error())
		os.Exit(1)
	}
}

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func run(args []string) error {
	backbone.Version = app.Version
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	cmd := args[0]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "version", "--version":
		fmt.Println("traced", app.Version, runtime.GOOS+"/"+runtime.GOARCH)
		return nil
	case "mtr":
		return cmdMTR(args[1:])
	case "sni":
		return cmdSNI(args[1:])
	case "whois":
		return cmdWhois(args[1:])
	case "history", "ls":
		return cmdHistory(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "map":
		return cmdServe(args[1:], true)
	case "serve":
		return cmdServe(args[1:], false)
	case "feeds":
		return cmdFeeds(args[1:])
	case "asn", "as":
		return cmdASN(args[1:])
	case "bgp":
		return cmdBGP(args[1:])
	case "mtu":
		return cmdMTU(args[1:])
	case "nat":
		return cmdNAT(args[1:])
	case "rep", "reputation":
		return cmdRep(args[1:])
	case "update-ixp":
		ctx, cancel := signalCtx()
		defer cancel()
		n, err := geo.UpdateIXP(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("IXP table updated: %d prefixes from PeeringDB\n", n)
		return nil
	case "trace":
		return cmdTrace(args[1:])
	case "share-server":
		return cmdShareServer(args[1:])
	case "backbone", "backbones", "bb":
		return cmdBackbone(args[1:])
	}
	return cmdTrace(args)
}

func cmdTrace(args []string) error {
	o := newOpts("trace")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced <target> [flags]  (traced --help)")
	}
	target := pos[0]
	gopt, err := o.geoOptions()
	if err != nil {
		return err
	}
	cfg := app.Config{
		Trace: o.traceOptions(target), Geo: !o.noGeo, GeoOpts: gopt,
		Whois: !o.noWhois && !o.noGeo && app.IsDomain(target),
		SNI:   o.sni, ControlSNI: o.controlSNI, MTU: o.mtu, NoNAT: o.noNAT, Save: !o.noSave, ASN: !o.noASN,
	}
	ctx, cancel := signalCtx()
	defer cancel()
	w := os.Stdout
	iface, tun, note := app.ResolveInterface(&cfg.Trace)
	cfg.Tunnel = tun
	if note != "" && !o.jsonOut {
		ui.Note(w, note)
	}
	headerDone := false
	emit := func(e trace.Event) {
		if o.jsonOut {
			return
		}
		switch e.Type {
		case "note":
			ui.Note(w, e.Note)
		case "start":
			ui.Title(w, e.Result, iface)
		case "hop":
			if !headerDone {
				ui.HopHeader(w)
				headerDone = true
			}
			ui.Hop(w, e.Hop, !o.numeric)
		case "sni-step":
			ui.SNIStep(w, e.Step)
		}
	}
	r, err := app.Run(ctx, cfg, emit)
	if r == nil {
		return err
	}
	ex := app.ExtraOf(r)
	if !o.shareIP && ex != nil && ex.NAT != nil {
		ex.NAT = trace.RedactNAT(ex.NAT)
	}
	link := ""
	if !o.noShare && len(r.Hops) > 0 {
		link = publish(o, r)
	}
	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			*trace.Result
			ShareURL string `json:"share_url,omitempty"`
		}{r, link})
	}
	ui.Anomalies(w, r)
	ui.PathIntel(w, r, ui.PathIntelOptions{Verbose: o.verbose, ShareIP: o.shareIP})
	ui.Summary(w, r)
	if ex != nil {
		ui.SNI(w, ex.SNI)
		ui.Whois(w, ex.Whois)
		for _, n := range ex.Notes {
			if n != note && !strings.HasPrefix(n, "SNI probe") {
				ui.Note(w, n)
			}
		}
	}
	if link != "" {
		fmt.Fprintf(w, "\n%s %s\n", ui.C("\x1b[1m", "map:"), ui.C("\x1b[36m", link))
	}
	if o.web && r.ID != "" {
		return serveAndOpen(o, []string{r.ID})
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return nil
}

func cmdWhois(args []string) error {
	o := newOpts("whois")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced whois <domain|ip>")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	wr := whois.Lookup(ctx, pos[0])
	plus := enrichWhois(ctx, wr, !o.noRep, !o.noASN, !o.noDNSBL)
	if o.jsonOut {
		return printJSON(plus)
	}
	ui.Whois(os.Stdout, wr)
	for _, a := range plus.ASNs {
		ui.ASNShort(os.Stdout, a)
	}
	ui.RepLines(os.Stdout, plus.Reputation)
	return nil
}

func cmdSNI(args []string) error {
	o := newOpts("sni")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced sni <host> [--sni name] [-p 443]")
	}
	topt := o.traceOptions(pos[0])
	ifn, _, note := app.ResolveInterface(&topt)
	ctx, cancel := signalCtx()
	defer cancel()
	if note != "" && !o.jsonOut {
		ui.Note(os.Stdout, note)
	}
	so := trace.SNIOptions{Host: pos[0], SNI: o.sni, ControlSNI: o.controlSNI, Port: o.port, IPv4: o.v4, IPv6: o.v6,
		MaxTTL: o.maxTTL, Interface: ifn, NoScan: o.noScan}
	if !o.jsonOut {
		sni := o.sni
		if sni == "" {
			sni = pos[0]
		}
		fmt.Printf("%s TLS ClientHello SNI=%s → %s, TTL scan:\n", ui.C("\x1b[1m", "traced sni"), ui.C("\x1b[36m", sni), pos[0])
	}
	r, err := trace.ProbeSNI(ctx, so, func(s trace.SNIStep) {
		if !o.jsonOut {
			ui.SNIStep(os.Stdout, &s)
		}
	})
	if err != nil {
		return err
	}
	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	ui.SNI(os.Stdout, r)
	return nil
}

func cmdHistory(args []string) error {
	o := newOpts("history")
	if _, err := o.parse(args); err != nil {
		return err
	}
	list := store.Default().List(o.limit)
	if o.jsonOut {
		return json.NewEncoder(os.Stdout).Encode(list)
	}
	ui.History(os.Stdout, list)
	return nil
}

func cmdDiff(args []string) error {
	o := newOpts("diff")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		pos = []string{"2", "1"}
	}
	if len(pos) != 2 {
		return errors.New("usage: traced diff <id1> <id2>")
	}
	st := store.Default()
	a, err := st.Load(pos[0])
	if err != nil {
		return err
	}
	b, err := st.Load(pos[1])
	if err != nil {
		return err
	}
	d := store.Compare(a, b)
	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	ui.Diff(os.Stdout, d)
	return nil
}

func cmdServe(args []string, open bool) error {
	o := newOpts("serve")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if o.noOpen {
		open = false
	}
	st := store.Default()
	var ids []string
	for _, p := range pos {
		id, err := st.Resolve(p)
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if open {
		return serveAndOpen(o, ids)
	}
	return serveOnly(o, ids)
}

func webDefaults(o *opts) (web.Options, error) {
	gopt, err := o.geoOptions()
	if err != nil {
		return web.Options{}, err
	}
	return web.Options{Listen: o.listen, Defaults: app.Config{
		Trace: trace.Options{Probes: o.probes, MaxTTL: o.maxTTL, Timeout: o.timeout, Interface: o.iface},
		Geo:   !o.noGeo, GeoOpts: gopt, Save: true, ControlSNI: o.controlSNI, ASN: !o.noASN,
	}}, nil
}

func serveOnly(o *opts, ids []string) error {
	wo, err := webDefaults(o)
	if err != nil {
		return err
	}
	srv, err := web.Start(wo)
	if err != nil {
		return err
	}
	fmt.Printf("traced web UI on %s%s  (Ctrl-C to stop)\n", srv.URL, web.Fragment(ids))
	ctx, cancel := signalCtx()
	defer cancel()
	<-ctx.Done()
	return srv.Close()
}

func serveAndOpen(o *opts, ids []string) error {
	wo, err := webDefaults(o)
	if err != nil {
		return err
	}
	srv, err := web.Start(wo)
	if err != nil {
		return err
	}
	url := srv.URL + web.Fragment(ids)
	fmt.Printf("\nweb map: %s  (Ctrl-C to stop)\n", ui.C("\x1b[36m", url))
	if !o.noOpen {
		OpenBrowser(url)
	}
	ctx, cancel := signalCtx()
	defer cancel()
	<-ctx.Done()
	return srv.Close()
}

// OpenBrowser opens url with the OS handler.
func OpenBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = c.Start()
}

func cmdMTR(args []string) error {
	o := newOpts("mtr")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced mtr <target> [-T|-U] [-p port]")
	}
	topt := o.traceOptions(pos[0])
	topt.Probes = 1
	if o.timeout == 2*time.Second {
		topt.Timeout = 1500 * time.Millisecond
	}
	_, _, note := app.ResolveInterface(&topt)
	gopt, err := o.geoOptions()
	if err != nil {
		return err
	}
	wo, err := webDefaults(o)
	if err != nil {
		return err
	}
	ctx, cancel := signalCtx()
	defer cancel()
	return mtr.Run(ctx, mtr.Options{
		Trace: topt, Geo: !o.noGeo, GeoOpts: gopt, Interval: o.interval, Numeric: o.numeric, Note: note,
		Final: func(r *trace.Result) {
			if o.noShare {
				return
			}
			if link := publish(o, r); link != "" {
				fmt.Fprintf(os.Stdout, "\n%s %s\n", ui.C("\x1b[1m", "map:"), ui.C("\x1b[36m", link))
			}
		},
		OpenMap: func(r *trace.Result) (string, error) {
			if err := store.Default().Save(r); err != nil {
				return "", err
			}
			srv, err := web.Shared(wo)
			if err != nil {
				return "", err
			}
			url := srv.URL + web.Fragment([]string{r.ID})
			OpenBrowser(url)
			return url, nil
		},
	})
}

// publish uploads the trace to the public map and returns the link. Failures
// are reported as one line on stderr and never fail the command.
func publish(o *opts, r *trace.Result) string {
	var resp *share.Response
	var err error
	if o.shareURL == "" || o.shareURL == share.DefaultURL {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		resp, err = share.UploadAny(ctx, r, 6*time.Second)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err = share.Upload(ctx, o.shareURL, r)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.C("\x1b[90m", "map: failed to upload trace ("+err.Error()+"); --no-share disables upload"))
		return ""
	}
	return resp.URL
}

func cmdShareServer(args []string) error {
	fs := flag.NewFlagSet("share-server", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7480", "listen address")
	dir := fs.String("dir", "/var/lib/traced-share", "storage directory")
	public := fs.String("public-url", share.DefaultURL, "base URL of the links handed out")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "lifetime of a shared trace")
	rate := fs.Int("rate", 30, "uploads per client IP per hour")
	burst := fs.Int("burst", 10, "uploads per client IP at once")
	maxMB := fs.Int64("max-mb", 2048, "total storage cap, MB")
	trust := fs.Bool("trust-proxy", true, "take the peer address from X-Real-IP on loopback connections (local nginx)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Getenv("TRACED_CACHE_DIR") == "" {
		cache.SetDir(filepath.Join(*dir, "cache")) // feeds (cable map) next to the store
	}
	srv, err := share.NewServer(share.ServerOptions{Dir: *dir, PublicURL: *public, TTL: *ttl, Rate: *rate, Burst: *burst,
		MaxBytes: *maxMB << 20, TrustProxy: *trust})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	stop := make(chan struct{})
	go srv.Run(stop)
	ctx, cancel := signalCtx()
	defer cancel()
	go func() {
		<-ctx.Done()
		close(stop)
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		hs.Shutdown(sctx)
	}()
	log.Printf("traced %s share server on %s, dir %s, ttl %s, public %s", app.Version, ln.Addr(), *dir, *ttl, *public)
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
