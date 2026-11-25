// traced web UI. Locally (traced map/serve) traces never leave the machine;
// only map tiles are fetched from the basemap CDN. The same code runs read-only
// on the public share server (traced.netkitty.dev/t/<id>), marked by
// <html data-mode="share"> and <meta name="traced-share" content="<id>">.
const $ = (s, el = document) => el.querySelector(s);
const SHARE = document.documentElement.dataset.mode === 'share';
const SHARE_ID = SHARE ? (document.querySelector('meta[name="traced-share"]')?.content || location.pathname.split('/').pop()) : '';
const PALETTE = ['#5cc8ff', '#ff8a5c', '#b78cff', '#3ddc97', '#ffd35c', '#ff5da8', '#5cffe1', '#c0c8d4'];
const STYLES = [
  'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',
  'https://tiles.openfreemap.org/styles/dark',
];

const state = {
  history: [],
  traces: new Map(),   // id -> result
  selected: [],        // ids shown on the map (order = color)
  active: null,        // id shown in the details panel
  live: null,          // trace being streamed
  colorByTrace: false,
};

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (ms) => !ms || ms <= 0 ? '*' : ms < 10 ? ms.toFixed(2) : ms < 100 ? ms.toFixed(1) : ms.toFixed(0);
const rttClass = (ms) => ms < 30 ? 'rtt-ok' : ms < 120 ? 'rtt-mid' : 'rtt-bad';
const minRTT = (r) => Math.min(...(r.rtts || []).filter((x) => x > 0), Infinity);
const deltaColor = (d) => d < 5 ? '#3ddc97' : d < 25 ? '#c8e25c' : d < 70 ? '#ffb547' : '#ff5d6c';
const colorOf = (id) => id === 'live' ? '#ffffff' : PALETTE[Math.max(0, state.selected.indexOf(id)) % PALETTE.length];

function setStatus(text, cls = '') {
  const s = $('#status');
  s.textContent = text;
  s.className = 'status ' + cls;
}

async function api(path) {
  const r = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

// ---------------- map ----------------
let map = null;
let markers = [];
let mapReady = false;

function initMap() {
  if (!window.maplibregl) {
    $('#mapfail').hidden = false;
    return;
  }
  let styleIdx = 0;
  map = new maplibregl.Map({ container: 'map', style: STYLES[0], center: [30, 50], zoom: 2.3, attributionControl: { compact: true } });
  map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right');
  map.on('error', (e) => {
    if (!mapReady && styleIdx < STYLES.length - 1 && String(e?.error?.message || '').match(/style|fetch|load/i)) {
      styleIdx++;
      map.setStyle(STYLES[styleIdx]);
    }
  });
  map.on('styleimagemissing', (e) => { if (e.id === 'arrow') addArrowImage(); });
  map.on('load', () => {
    mapReady = true;
    addArrowImage();
    const hl = ['boolean', ['feature-state', 'hl'], false];
    const dim = ['boolean', ['feature-state', 'dim'], false];
    const width = ['case', hl, ['*', ['get', 'w'], 2], ['get', 'w']];
    const opacity = (base) => ['case', hl, 1, dim, 0.18, base];
    map.addSource('arcs', { type: 'geojson', data: emptyFC() });
    map.addLayer({ id: 'arcs-glow', type: 'line', source: 'arcs', filter: ['!', ['get', 'dashed']],
      paint: { 'line-color': ['get', 'color'], 'line-width': ['*', width, 4], 'line-opacity': ['case', hl, 0.35, dim, 0.03, 0.12], 'line-blur': 3 } });
    map.addLayer({ id: 'arcs', type: 'line', source: 'arcs', filter: ['!', ['get', 'dashed']],
      layout: { 'line-cap': 'round' }, paint: { 'line-color': ['get', 'color'], 'line-width': width, 'line-opacity': opacity(0.9) } });
    map.addLayer({ id: 'arcs-dashed', type: 'line', source: 'arcs', filter: ['get', 'dashed'],
      paint: { 'line-color': ['get', 'color'], 'line-width': width, 'line-opacity': opacity(0.8), 'line-dasharray': [2, 2] } });
    // one direction arrow in the middle of every segment
    map.addLayer({ id: 'arcs-arrows', type: 'symbol', source: 'arcs',
      layout: { 'symbol-placement': 'line-center', 'icon-image': 'arrow', 'icon-size': ['interpolate', ['linear'], ['get', 'w'], 1.6, 1.2, 2.6, 1.6],
        'icon-allow-overlap': true, 'icon-ignore-placement': true, 'icon-rotation-alignment': 'map', 'icon-keep-upright': false },
      paint: { 'icon-color': ['get', 'color'], 'icon-opacity': opacity(1), 'icon-halo-color': '#0b0f14', 'icon-halo-width': 1.5 } });
    // wide invisible line for hovering / clicking segments
    map.addLayer({ id: 'arcs-hit', type: 'line', source: 'arcs', paint: { 'line-color': '#000', 'line-width': 14, 'line-opacity': 0.001 } });
    map.on('mousemove', 'arcs-hit', (e) => {
      const f = e.features?.[0];
      if (!f) return;
      map.getCanvas().style.cursor = 'pointer';
      highlight([f.id], { lngLat: e.lngLat, source: 'map' });
    });
    map.on('mouseleave', 'arcs-hit', () => { map.getCanvas().style.cursor = ''; highlight(null); });
    map.on('click', 'arcs-hit', (e) => {
      const f = e.features?.[0];
      if (f) pin([f.id], { lngLat: e.lngLat, scroll: true });
    });
    render();
  });
}

function addArrowImage() {
  if (map.hasImage('arrow')) return;
  const n = 32, c = document.createElement('canvas');
  c.width = c.height = n;
  const x = c.getContext('2d');
  x.fillStyle = '#fff';
  x.beginPath(); // chevron pointing east = along the line direction
  x.moveTo(8, 6); x.lineTo(26, 16); x.lineTo(8, 26); x.lineTo(13, 16); x.closePath();
  x.fill();
  map.addImage('arrow', x.getImageData(0, 0, n, n), { sdf: true, pixelRatio: 2 });
}

const emptyFC = () => ({ type: 'FeatureCollection', features: [] });

// segment colours run along the path: start → end
const GRADIENT = ['#3ddc97', '#5cc8ff', '#8f9bff', '#d07cff', '#ff5da8', '#ff8a5c'];
function gradColor(t) {
  t = Math.min(1, Math.max(0, t)) * (GRADIENT.length - 1);
  const i = Math.min(GRADIENT.length - 2, Math.floor(t)), f = t - i;
  const p = (h) => [1, 3, 5].map((o) => parseInt(h.slice(o, o + 2), 16));
  const [a, b] = [p(GRADIENT[i]), p(GRADIENT[i + 1])];
  return '#' + a.map((v, k) => Math.round(v + (b[k] - v) * f).toString(16).padStart(2, '0')).join('');
}

// great-circle interpolation, longitudes unwrapped to avoid antimeridian jumps;
// bend > 0 bows the line to the left of the a→b direction, so the way back
// over the same pair (b→a) bows to the other side and repeated passes nest.
function arc(a, b, bend = 0, n = 48) {
  const toR = Math.PI / 180, toD = 180 / Math.PI;
  const [l1, p1] = [a.lon * toR, a.lat * toR], [l2, p2] = [b.lon * toR, b.lat * toR];
  const d = 2 * Math.asin(Math.sqrt(Math.sin((p2 - p1) / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin((l2 - l1) / 2) ** 2));
  if (d < 1e-6) return [[a.lon, a.lat], [b.lon, b.lat]];
  const pts = [];
  let prevLon = null;
  for (let i = 0; i <= n; i++) {
    const f = i / n;
    const A = Math.sin((1 - f) * d) / Math.sin(d), B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(p1) * Math.cos(l1) + B * Math.cos(p2) * Math.cos(l2);
    const y = A * Math.cos(p1) * Math.sin(l1) + B * Math.cos(p2) * Math.sin(l2);
    const z = A * Math.sin(p1) + B * Math.sin(p2);
    let lon = Math.atan2(y, x) * toD;
    const lat = Math.atan2(z, Math.sqrt(x * x + y * y)) * toD;
    if (prevLon !== null) { while (lon - prevLon > 180) lon -= 360; while (lon - prevLon < -180) lon += 360; }
    prevLon = lon;
    pts.push([lon, lat]);
  }
  if (!bend) return pts;
  const [s, e] = [pts[0], pts[n]];
  const k = Math.cos(((s[1] + e[1]) / 2) * toR); // local scale so the bow is round on screen
  const dx = (e[0] - s[0]) * k, dy = e[1] - s[1], L = Math.hypot(dx, dy) || 1;
  const nx = -dy / L, ny = dx / L;
  return pts.map(([lon, lat], i) => {
    const off = bend * L * Math.sin(Math.PI * i / n);
    return [lon + nx * off / k, lat + ny * off];
  });
}

// cluster key: hops in the same city (or within ~50 km when unnamed) share one node
const keyOf = (g) => g.ixp ? 'ixp:' + g.ixp.name
  : g.city ? `${g.city.toLowerCase()}|${g.country || ''}`
  : `${(Math.round(g.lat * 2) / 2).toFixed(1)},${(Math.round(g.lon * 2) / 2).toFixed(1)}`;

const locLabel = (g) => g.ixp ? g.ixp.name : [g.city, g.country].filter(Boolean).join(', ');

// "1-3,7,9" from a list of hop numbers
function ranges(v) {
  v = [...new Set(v)].sort((a, b) => a - b);
  const out = [];
  for (let i = 0; i < v.length; i++) {
    let j = i;
    while (j + 1 < v.length && v[j + 1] === v[j] + 1) j++;
    out.push(j > i ? `${v[i]}–${v[j]}` : `${v[i]}`);
    i = j;
  }
  return out.join(',');
}

let segs = []; // segment index (= feature id) -> {tid, fromTTL, toTTL, from, to, coords, ...}

function buildMapData() {
  const nodes = new Map();
  segs = [];
  const shown = [...state.selected.map((id) => state.traces.get(id)).filter(Boolean)];
  if (state.live) shown.push(state.live);
  const byOrder = shown.length === 1 && !state.colorByTrace;
  // every located responder belongs to a node; nodes closer than ~60 km merge (metro areas, suburbs)
  const nodeOf = (g) => {
    let k = keyOf(g);
    if (!nodes.has(k)) {
      for (const [nk, n] of nodes) {
        if (Math.abs(n.lat - g.lat) < 0.55 && Math.abs(n.lon - g.lon) < 0.9) { k = nk; break; }
      }
    }
    if (!nodes.has(k)) nodes.set(k, { key: k, lat: g.lat, lon: g.lon, label: locLabel(g), items: [], ixp: false, anom: false, first: Infinity });
    return nodes.get(k);
  };
  for (const tr of shown) {
    const id = tr.id || 'live';
    const color = colorOf(id);
    const hops = tr.hops || [];
    const maxTTL = Math.max(1, ...hops.map((h) => h.ttl));
    let prev = [];
    let lossSince = false;
    for (const h of hops) {
      const locs = new Map();
      for (const r of h.responders || []) {
        const g = r.geo;
        if (!g || !g.located) continue;
        const n = nodeOf(g);
        n.items.push({ id, color, ttl: h.ttl, r, target: tr.target });
        n.ixp ||= !!g.ixp;
        n.anom ||= !!g.rtt_anomaly;
        n.first = Math.min(n.first, byOrder ? (h.ttl - 1) / Math.max(1, maxTTL - 1) : 0);
        const rtt = minRTT(r), cur = locs.get(n.key);
        if (!cur || rtt < cur.rtt) locs.set(n.key, { node: n, rtt, ttl: h.ttl });
      }
      if (h.sent && h.received < h.sent) lossSince = true;
      if (!locs.size) continue;
      const cur = [...locs.values()];
      if (prev.length) {
        const ecmp = prev.length > 1 || cur.length > 1;
        for (const p of prev) for (const c of cur) {
          if (p.node === c.node) continue;
          segs.push({ tid: id, color, from: p.node, to: c.node, fromTTL: p.ttl, toTTL: c.ttl,
            dRtt: c.rtt - p.rtt, dashed: ecmp || lossSince, w: ecmp ? 1.6 : 2.6, target: tr.target });
        }
      }
      prev = cur;
      lossSince = false;
    }
  }
  // order colour + bows. A pair drawn once in one direction gets a faint bow;
  // a pair passed again (either way) bows clearly, the k-th pass further out.
  const total = new Map();
  for (const sg of segs) total.set(sg.from.key + '>' + sg.to.key, (total.get(sg.from.key + '>' + sg.to.key) || 0) + 1);
  const passes = new Map(), perTrace = new Map(), idx = new Map();
  for (const sg of segs) perTrace.set(sg.tid, (perTrace.get(sg.tid) || 0) + 1);
  const features = segs.map((sg, i) => {
    const pair = sg.from.key + '>' + sg.to.key;
    const k = passes.get(pair) || 0;
    passes.set(pair, k + 1);
    const repeated = total.get(pair) > 1 || total.has(sg.to.key + '>' + sg.from.key);
    const j = idx.get(sg.tid) || 0;
    idx.set(sg.tid, j + 1);
    const n = perTrace.get(sg.tid);
    sg.order = j;
    if (byOrder) sg.color = gradColor(n > 1 ? j / (n - 1) : 0);
    sg.coords = arc(sg.from, sg.to, (repeated ? 0.2 : 0.08) + 0.16 * k);
    return { type: 'Feature', id: i, geometry: { type: 'LineString', coordinates: sg.coords },
      properties: { color: sg.color, dashed: sg.dashed, w: sg.w } };
  });
  // label each cluster with its most frequent location
  for (const n of nodes.values()) {
    const cnt = new Map();
    for (const { r } of n.items) {
      const l = locLabel(r.geo || {});
      cnt.set(l, (cnt.get(l) || 0) + 1);
    }
    n.label = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || n.label;
  }
  return { nodes, features, byOrder };
}

function popupHTML(n) {
  const rows = n.items.sort((a, b) => a.id.localeCompare(b.id) || a.ttl - b.ttl).map(({ color, ttl, r, target }) => {
    const g = r.geo || {};
    return `<tr><td><b style="color:${color}">●</b></td><td class="num">${ttl}</td><td class="mono">${esc(r.ip)}<div class="host">${esc(r.host || '')}</div></td>
      <td class="num ${rttClass(minRTT(r))}">${fmt(minRTT(r))}</td><td>${badge(g)}</td><td class="host">${esc(target)}</td></tr>`;
  }).join('');
  return `<div class="pop"><h4>${esc(n.label || 'unknown')}</h4><table>${rows}</table></div>`;
}

function segHTML(sg) {
  const d = sg.dRtt;
  return `<div class="pop seg"><b style="color:${sg.color}">hop ${sg.fromTTL} → ${sg.toTTL}</b>
    <div>${esc(sg.from.label || '?')} → ${esc(sg.to.label || '?')}</div>
    <div class="host">segment ${sg.order + 1} · Δrtt <span style="color:${deltaColor(Math.max(0, d))}">${d < 0 ? '−' : '+'}${Math.abs(d) < 0.005 ? '0' : fmt(Math.abs(d))} ms</span>${sg.dashed ? ' · loss/ECMP' : ''}</div></div>`;
}

// ---------- segment highlight (map ↔ table) ----------
let hlIds = [];   // currently highlighted feature ids
let pinned = [];  // ids pinned by a click (row or segment)
let segPopup = null;

function applyHL(ids) {
  if (!map || !mapReady || !map.getSource('arcs')) return;
  const on = new Set(ids || []);
  segs.forEach((_, i) => map.setFeatureState({ source: 'arcs', id: i }, { hl: on.has(i), dim: on.size > 0 && !on.has(i) }));
  hlIds = [...on];
  // table rows of the highlighted segments' end points
  const box = $('#details');
  box.querySelectorAll('tr.seg-hl').forEach((x) => x.classList.remove('seg-hl'));
  for (const i of on) {
    const sg = segs[i];
    if (!sg || sg.tid !== state.active) continue;
    for (const ttl of [sg.fromTTL, sg.toTTL]) box.querySelectorAll(`tr[data-ttl="${ttl}"]`).forEach((x) => x.classList.add('seg-hl'));
  }
}

let segPopupKey = '';
function showSegPopup(ids, lngLat) {
  const sg = ids?.length ? segs[ids[0]] : null;
  const at = sg && (lngLat || sg.coords[Math.floor(sg.coords.length / 2)]);
  if (sg && segPopup && segPopupKey === ids.join(',')) return void segPopup.setLngLat(at);
  if (segPopup) { segPopup.remove(); segPopup = null; }
  if (!sg || !map) return;
  segPopupKey = ids.join(',');
  segPopup = new maplibregl.Popup({ closeButton: false, closeOnClick: false, offset: 10, className: 'segpop' })
    .setLngLat(at).setHTML(ids.map((i) => segHTML(segs[i])).join('')).addTo(map);
}

// hover: temporary highlight; null restores the pinned one
function highlight(ids, o = {}) {
  if (!ids || !ids.length) {
    applyHL(pinned);
    showSegPopup(pinned);
    return;
  }
  applyHL(ids);
  if (o.source === 'map') showSegPopup(ids, o.lngLat);
}

function pin(ids, o = {}) {
  pinned = ids || [];
  applyHL(pinned);
  showSegPopup(pinned, o.lngLat);
  if (o.scroll && pinned.length) {
    const sg = segs[pinned[0]];
    $(`#details tr[data-ttl="${sg.toTTL}"]`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
  if (o.fit && pinned.length) {
    const b = new maplibregl.LngLatBounds();
    for (const i of pinned) for (const c of segs[i].coords) b.extend(c);
    map.fitBounds(b, { padding: 90, maxZoom: 6, duration: 500 });
  }
}

const segsInto = (tid, ttl) => segs.map((sg, i) => (sg.tid === tid && sg.toTTL === ttl ? i : -1)).filter((i) => i >= 0);

let fitted = '';
function renderMap() {
  if (!map || !mapReady) return;
  const { nodes, features, byOrder } = buildMapData();
  map.getSource('arcs').setData({ type: 'FeatureCollection', features });
  pinned = pinned.filter((i) => i < segs.length);
  markers.forEach((m) => m.remove());
  markers = [];
  const bounds = new maplibregl.LngLatBounds();
  for (const n of nodes.values()) {
    const el = document.createElement('button');
    el.type = 'button';
    el.className = 'node' + (n.ixp ? ' ixp' : '') + (n.anom ? ' anom' : '');
    const traces = [...new Set(n.items.map((i) => i.color))];
    const ttls = ranges(n.items.map((i) => i.ttl));
    el.title = `${n.label} · hop ${ttls}`;
    if (byOrder && !n.ixp && !n.anom) el.style.borderColor = gradColor(n.first);
    el.innerHTML = `<span class="ttl">${esc(ttls.length > 14 ? ttls.slice(0, 13) + '…' : ttls)}</span>${traces.length > 1 ? `<span class="dots">${traces.map((c) => `<b style="background:${c}"></b>`).join('')}</span>` : ''}<span class="cap">${esc((n.label || '').split(',')[0])}</span>`;
    const mk = new maplibregl.Marker({ element: el }).setLngLat([n.lon, n.lat])
      .setPopup(new maplibregl.Popup({ offset: 14, maxWidth: '460px' }).setHTML(popupHTML(n))).addTo(map);
    markers.push(mk);
    bounds.extend([n.lon, n.lat]);
  }
  const sig = state.selected.join(',') + (state.live ? 'L' : '') + ':' + nodes.size;
  if (nodes.size && sig !== fitted) {
    fitted = sig;
    map.fitBounds(bounds, { padding: 70, maxZoom: 6, duration: 600 });
  }
  applyHL(pinned);
}

// ---------------- details panel ----------------
function badge(g) {
  if (!g) return '';
  if (g.private) return '<span class="badge interp">private</span>';
  let s = g.source ? `<span class="badge ${esc(g.source)}" title="confidence ${Math.round((g.confidence || 0) * 100)}%">${esc(g.source)}</span>` : '';
  if (g.rtt_anomaly) s += ` <span class="badge anom" title="${esc(g.anomaly)}">rtt⚠</span>`;
  return s;
}

function kv(pairs) {
  return `<dl class="kv">${pairs.filter(([, v]) => v && (!Array.isArray(v) || v.length)).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(', ') : v)}</dd>`).join('')}</dl>`;
}

const day = (s) => (s || '').slice(0, 10);

function renderDetails() {
  const box = $('#details');
  const tr = state.active === 'live' ? state.live : state.traces.get(state.active);
  if (!tr) {
    box.innerHTML = `<div class="empty">${SHARE ? 'Loading trace…' : 'Select a trace from history or run a new one.'}</div>`;
    return;
  }
  const ex = tr.extra || {};
  const cards = [];
  const last = (tr.hops || []).at(-1);
  const asPath = [];
  for (const h of tr.hops || []) {
    const a = h.responders?.[0]?.net?.asn;
    if (a && asPath.at(-1) !== a) asPath.push(a);
  }
  cards.push(`<div class="card"><h3>Trace ${esc(tr.id || 'live')}</h3>${kv([
    ['target', `${tr.target} (${tr.target_ip || ''})`], ['protocol', `${(tr.protocol || '').toUpperCase()}${tr.port ? ':' + tr.port : ''} · ${tr.privilege || ''}`],
    ['started', tr.started ? new Date(tr.started).toLocaleString() : ''], ['hops', String((tr.hops || []).length)],
    ['reached', tr.reached ? 'yes' : (tr.id ? 'no' : '…')], ['rtt', last ? fmt(avg(last)) + ' ms' : ''],
    ['AS path', asPath.map((a) => 'AS' + a).join(' → ')], ['interface', ex.interface], ['tunnel', ex.tunnel], ['notes', ex.notes]])}</div>`);
  const w = ex.whois;
  if (w?.domain) {
    const d = w.domain;
    cards.push(`<div class="card"><h3>Domain · ${esc(d.source)}</h3>${kv([['domain', d.domain], ['registrar', d.registrar], ['registrant', d.registrant],
      ['created', day(d.created)], ['expires', day(d.expires)], ['updated', day(d.updated)], ['nameservers', d.nameservers], ['status', d.status], ['dnssec', d.dnssec]])}</div>`);
  }
  if (w?.dns) cards.push(`<div class="card"><h3>DNS</h3>${kv([['CNAME', w.dns.cname], ['A', w.dns.a], ['AAAA', w.dns.aaaa], ['NS', w.dns.ns], ['MX', w.dns.mx]])}</div>`);
  for (const ip of w?.ips || []) {
    cards.push(`<div class="card"><h3>IP ${esc(ip.ip)} · ${esc(ip.source)}</h3>${kv([['ASN', ip.asn ? `AS${ip.asn} ${ip.as_name || ''}` : ''], ['prefix', ip.as_prefix],
      ['netname', ip.netname], ['org', ip.org], ['country', ip.country], ['range', ip.range], ['RIR', ip.rir], ['geofeed', ip.geofeed]])}</div>`);
  }
  const s = ex.sni;
  if (s) {
    const ok = s.verdict === 'ok';
    cards.push(`<div class="card"><h3>SNI probe</h3>${kv([['SNI', s.sni], ['target', `${s.target.outcome} ${fmt(s.target.rtt_ms)} ms`],
      ['control', `${s.control.sni}: ${s.control.outcome}`], ['server TTL', s.server_ttl ? String(s.server_ttl) : ''],
      ['block TTL', s.block_ttl ? `${s.block_ttl}${s.block_hop ? ' after ' + s.block_hop : ''}` : '']])}
      <p class="verdict ${ok ? 'ok' : 'bad'}">${esc(s.verdict.toUpperCase())}</p><p>${esc(s.summary)}</p>
      ${(s.steps || []).length ? `<table class="hops"><tr><th>ttl</th><th>outcome</th><th>router</th><th>rtt</th></tr>${s.steps.map((st) =>
        `<tr><td class="num">${st.ttl}</td><td>${esc(st.outcome)}</td><td class="mono">${esc(st.router || '—')}</td><td class="num">${fmt(st.rtt_ms)}</td></tr>`).join('')}</table>` : ''}</div>`);
  }
  const rows = [];
  for (const h of tr.hops || []) {
    const rs = h.responders || [];
    if (!rs.length) {
      rows.push(`<tr data-ttl="${h.ttl}"><td class="num">${h.ttl}</td><td colspan="7" class="host">* * *</td><td class="num rtt-bad">100%</td></tr>`);
      continue;
    }
    rs.forEach((r, i) => {
      const g = r.geo || {};
      const loc = g.ixp ? g.ixp.name : [g.city, g.country].filter(Boolean).join(', ');
      const flags = [];
      if (i === 0 && rs.length > 1) flags.push(`<span class="badge ecmp">ECMP×${rs.length}</span>`);
      if (r.mpls?.length) flags.push(`<span class="badge mpls" title="MPLS label stack">MPLS ${r.mpls.map((l) => l.label).join('/')}</span>`);
      const loss = h.sent ? Math.round(100 * (1 - h.received / h.sent)) : 0;
      rows.push(`<tr class="${i ? 'branch' : ''}" data-ttl="${h.ttl}" data-lat="${g.located ? g.lat : ''}" data-lon="${g.located ? g.lon : ''}">
        <td class="num">${i ? '└' : h.ttl}</td>
        <td class="mono">${esc(r.ip)}${r.final ? ' ◎' : ''}<div class="host">${esc(r.host || '')}</div></td>
        <td>${r.net?.asn ? `AS${r.net.asn}` : ''}<div class="host">${esc((r.net?.name || '').split(/ - |,/)[0])}</div></td>
        <td>${esc(loc)}${g.backbone ? `<div class="host">${esc(g.backbone.name)}</div>` : ''}</td>
        <td>${badge(g)}</td>
        <td class="num">${(r.rtts || []).map((x) => `<span class="${rttClass(x)}">${fmt(x)}</span>`).join(' ')}</td>
        <td>${flags.join(' ')}</td>
        <td class="host" title="${esc(g.anomaly || '')}">${esc(g.anomaly ? '⚠ ' + g.anomaly : '')}</td>
        <td class="num">${i ? '' : loss + '%'}</td></tr>`);
    });
  }
  box.innerHTML = `<div class="cards">${cards.join('')}</div>
    <table class="hops"><thead><tr><th>#</th><th>address</th><th>network</th><th>location</th><th>geo</th><th>rtt ms</th><th>flags</th><th>physics</th><th>loss</th></tr></thead>
    <tbody>${rows.join('')}</tbody></table>`;
  const tid = tr.id || 'live';
  box.querySelectorAll('tr[data-ttl]').forEach((row) => {
    const ttl = +row.dataset.ttl;
    row.addEventListener('mouseenter', () => highlight(segsInto(tid, ttl)));
    row.addEventListener('mouseleave', () => highlight(null));
    row.addEventListener('click', () => {
      if (!map) return;
      box.querySelectorAll('tr.hl').forEach((x) => x.classList.remove('hl'));
      row.classList.add('hl');
      const ids = segsInto(tid, ttl);
      if (ids.length) return pin(ids, { fit: true });
      pin([]);
      if (row.dataset.lat) map.flyTo({ center: [+row.dataset.lon, +row.dataset.lat], zoom: Math.max(map.getZoom(), 5) });
    });
  });
  applyHL(hlIds);
}

function avg(h) {
  const v = (h.probes || []).filter((p) => !p.lost && p.rtt_ms > 0).map((p) => p.rtt_ms);
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : 0;
}

// ---------------- history & diff ----------------
function renderHistory() {
  const ul = $('#history');
  ul.innerHTML = '';
  if (!state.history.length) {
    ul.innerHTML = '<li class="m">no traces yet</li>';
    return;
  }
  for (const h of state.history) {
    const li = document.createElement('li');
    const sel = state.selected.includes(h.id);
    li.className = state.active === h.id ? 'active' : '';
    li.innerHTML = `<input type="checkbox" ${sel ? 'checked' : ''} aria-label="show on map">
      <span class="sw" style="background:${sel ? colorOf(h.id) : 'transparent'}"></span>
      <span class="t" title="${esc(h.id)}">${esc(h.target)}</span>
      <span class="m">${esc(h.protocol)}${h.port ? ':' + h.port : ''} · ${h.hops} hops · ${fmt(h.rtt_ms)} ms · ${new Date(h.started).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}${h.reached ? '' : ' · ✗'}</span>`;
    const cb = li.querySelector('input');
    cb.addEventListener('click', (e) => { e.stopPropagation(); toggle(h.id, cb.checked); });
    li.addEventListener('click', () => { if (!state.selected.includes(h.id)) toggle(h.id, true); state.active = h.id; render(); });
    ul.append(li);
  }
}

async function toggle(id, on) {
  if (on) {
    if (!state.traces.has(id)) state.traces.set(id, await api('/api/traces/' + encodeURIComponent(id)));
    if (!state.selected.includes(id)) state.selected.push(id);
    state.active = id;
  } else {
    state.selected = state.selected.filter((x) => x !== id);
    if (state.active === id) state.active = state.selected.at(-1) || null;
  }
  if (!SHARE) history.replaceState(null, '', state.selected.length ? '#t=' + state.selected.join(',') : '#');
  render();
}

async function renderDiff() {
  const box = $('#diffbox');
  if (state.selected.length !== 2) { box.hidden = true; return; }
  box.hidden = false;
  try {
    const d = await api(`/api/diff?a=${encodeURIComponent(state.selected[0])}&b=${encodeURIComponent(state.selected[1])}`);
    const p = (arr) => (arr || []).map((a) => 'AS' + a).join(' → ') || '—';
    $('#diff').innerHTML = `<div class="kv"><dt style="color:${colorOf(state.selected[0])}">A</dt><dd>${esc(p(d.as_path_a))}</dd>
      <dt style="color:${colorOf(state.selected[1])}">B</dt><dd>${esc(p(d.as_path_b))}</dd></div>
      <p class="${d.as_path_changed ? 'verdict bad' : 'verdict ok'}">${d.as_path_changed ? 'AS path changed' : 'AS path same'}</p>
      <p class="host">${esc(d.summary)}</p>`;
  } catch (e) {
    $('#diff').textContent = e.message;
  }
}

let raf = 0;
function render() {
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(() => {
    if (!SHARE) renderHistory();
    renderMap();
    renderDetails();
    if (!SHARE) renderDiff();
  });
}

async function loadHistory() {
  if (SHARE) return render();
  try {
    state.history = await api('/api/traces?limit=60');
  } catch (e) {
    setStatus(e.message, 'err');
  }
  render();
}

// ---------------- live run (SSE) ----------------
let es = null;
function startRun(form) {
  const fd = new FormData(form);
  const p = new URLSearchParams();
  for (const [k, v] of fd) if (String(v).trim()) p.set(k, String(v).trim());
  if (es) es.close();
  state.live = { target: p.get('target'), hops: [], extra: {}, protocol: p.get('proto') };
  state.active = 'live';
  $('#go').disabled = true;
  setStatus(`tracing ${p.get('target')}…`, 'live');
  es = new EventSource('/api/run?' + p.toString());
  const on = (t, fn) => es.addEventListener(t, (e) => fn(JSON.parse(e.data)));
  on('start', (e) => { Object.assign(state.live, e.result, { hops: [] }); render(); });
  on('note', (e) => setStatus(e.note, 'live'));
  on('hop', (e) => { state.live.hops.push(e.hop); setStatus(`hop ${e.hop.ttl}…`, 'live'); render(); });
  on('whois', (e) => { state.live.extra.whois = e.data; render(); });
  on('sni-step', (e) => setStatus(`SNI ttl ${e.step.ttl}: ${e.step.outcome}`, 'live'));
  on('done', async (e) => {
    es.close();
    $('#go').disabled = false;
    const r = e.result;
    state.live = null;
    if (r.id) {
      state.traces.set(r.id, r);
      if (!state.selected.includes(r.id)) state.selected.push(r.id);
      state.active = r.id;
      history.replaceState(null, '', '#t=' + state.selected.join(','));
    }
    setStatus(`${r.reached ? 'reached' : 'not reached'} ${r.target} in ${r.hops.length} hops`);
    await loadHistory();
  });
  es.addEventListener('error', (e) => {
    let msg = 'connection lost';
    if (e.data) { try { msg = JSON.parse(e.data).error; } catch { /* ignore */ } }
    es.close();
    $('#go').disabled = false;
    if (state.live && !state.live.hops.length) state.live = null;
    setStatus(msg, 'err');
    render();
  });
}

// ---------------- boot ----------------
async function bootShare() {
  $('#run').remove();
  $('#history').closest('section').remove();
  $('#diffbox').remove();
  document.body.classList.add('shared');
  const note = document.createElement('div');
  note.className = 'sharenote';
  note.innerHTML = 'shared trace · run your own: <code>curl -sL traced.netkitty.dev | sh -s -- 1.1.1.1</code> · <a href="/">traced.netkitty.dev</a>';
  $('.bar .brand').after(note);
  api('/api/info').then((i) => { $('#ver').textContent = `v${String(i.version).replace(/^v/, '')}`; }).catch(() => {});
  initMap();
  try {
    const tr = await api('/api/traces/' + encodeURIComponent(SHARE_ID));
    state.traces.set(SHARE_ID, tr);
    state.selected = [SHARE_ID];
    state.active = SHARE_ID;
    const n = (tr.hops || []).length;
    setStatus(`${tr.target} · ${n} hops · ${tr.reached ? 'reached' : 'not reached'}${tr.started ? ' · ' + new Date(tr.started).toLocaleString() : ''}`);
    render();
  } catch (e) {
    setStatus(e.message.startsWith('404') ? 'trace not found or expired' : e.message, 'err');
    $('#details').innerHTML = '<div class="empty">Trace not found or expired.</div>';
  }
}

$('#colorByTrace').addEventListener('change', (e) => { state.colorByTrace = e.target.checked; render(); });
if (SHARE) {
  bootShare();
} else {
$('#run').addEventListener('submit', (e) => { e.preventDefault(); startRun(e.currentTarget); });
$('#refresh').addEventListener('click', loadHistory);
api('/api/info').then((i) => { $('#ver').textContent = `v${String(i.version).replace(/^v/, '')} · ${i.ixp_prefixes} IXP prefixes · ${i.cities} cities`; }).catch(() => {});

initMap();
(async () => {
  const m = location.hash.match(/t=([^&]+)/);
  await loadHistory();
  const ids = m ? decodeURIComponent(m[1]).split(',').filter(Boolean) : [];
  for (const id of ids) {
    try { await toggle(id, true); } catch (e) { setStatus(e.message, 'err'); }
  }
  if (ids.length) { state.active = state.selected[0] || null; render(); }
})();
}
