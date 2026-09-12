package main

// dashboardHTML is the live operator console. It polls /score, /findings,
// /behavior, /containers and /stats once a second and re-renders.
//
// Colour carries meaning in exactly two places and both follow a fixed
// rule. Severity and posture use a reserved status palette (good /
// warning / serious / critical) and always ship with a text label, so a
// reader who cannot separate the hues loses nothing. Byte-flow uses a
// four-slot categorical palette, assigned in fixed order and validated
// for colour-vision separation against this surface, with direct labels
// on every segment. Nothing else is coloured.
const dashboardHTML = `<!doctype html>
<meta charset="utf-8">
<title>warden</title>
<style>
:root{
  color-scheme: dark;
  --surface-0:#0b0e13; --surface-1:#12161d; --surface-2:#1a1f28;
  --line:#262d38; --line-soft:#1d232c;
  --text-1:#e9edf2; --text-2:#9aa4b2; --text-3:#6b7482;

  /* Status palette — reserved for state, never reused as a series colour.
     Always paired with a text label (see the severity chips). */
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;

  /* Categorical slots, fixed order, validated on --surface-1. */
  --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
}
*{box-sizing:border-box}
body{margin:0;background:var(--surface-0);color:var(--text-1);
  font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:var(--series-1)}
header{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;
  gap:18px;align-items:baseline;flex-wrap:wrap;background:var(--surface-1)}
h1{font-size:13px;margin:0;letter-spacing:.18em;text-transform:uppercase;color:var(--text-1)}
.dim{color:var(--text-2)} .dim3{color:var(--text-3)}
main{padding:18px 22px 60px;display:flex;flex-direction:column;gap:16px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(215px,1fr))}
.card{background:var(--surface-1);border:1px solid var(--line);border-radius:10px;padding:13px 15px;min-width:0}
.card h2{font-size:10px;margin:0 0 9px;color:var(--text-3);text-transform:uppercase;
  letter-spacing:.13em;font-weight:600}
.v{font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}
.row{display:flex;justify-content:space-between;gap:10px;padding:2px 0;font-variant-numeric:tabular-nums}
.wide{grid-column:1/-1}

/* Posture banner: the headline. Border + glyph + label carry it, not hue alone. */
.posture{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:10px;
  border:1px solid var(--line);border-left-width:4px;background:var(--surface-1)}
.posture .glyph{font-size:20px;line-height:1}
.posture .tier{font-size:17px;letter-spacing:.1em;text-transform:uppercase}
.posture .why{color:var(--text-2)}
.p-trusted{border-left-color:var(--good)} .p-watch{border-left-color:var(--warning)}
.p-degraded{border-left-color:var(--serious)} .p-quarantine{border-left-color:var(--critical)}

.banner{padding:10px 14px;border-radius:8px;border:1px solid var(--serious);
  border-left-width:4px;background:var(--surface-1);color:var(--text-1)}

/* Findings */
.finding{display:grid;grid-template-columns:88px 1fr auto;gap:12px;align-items:start;
  padding:9px 0;border-top:1px solid var(--line-soft)}
.finding:first-child{border-top:0}
.chip{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;
  letter-spacing:.09em;text-transform:uppercase;border:1px solid currentColor}
.s-critical{color:var(--critical)} .s-high{color:var(--serious)}
.s-medium{color:var(--warning)} .s-low{color:var(--text-2)} .s-info{color:var(--text-3)}
.ftitle{color:var(--text-1)}
.fmeta{color:var(--text-3);font-size:11px}
.ev{color:var(--text-2);font-size:11px;margin-top:4px;white-space:pre-wrap;word-break:break-all}
.count{color:var(--text-3);font-variant-numeric:tabular-nums}

/* Bars: 4px rounded data-end, anchored to a common baseline, 2px surface gap. */
.bar{height:9px;border-radius:0 4px 4px 0;background:var(--series-1)}
.barrow{display:grid;grid-template-columns:150px 1fr 74px;gap:9px;align-items:center;padding:2px 0}
.barrow .lbl{color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.barrow .num{text-align:right;color:var(--text-2);font-variant-numeric:tabular-nums}
.track{background:var(--surface-2);border-radius:4px;height:9px;overflow:hidden}
.stack{display:flex;height:18px;border-radius:4px;overflow:hidden;background:var(--surface-2);gap:2px}
.seg{height:100%}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:9px;font-size:11px;color:var(--text-2)}
.key{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px}

table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th{text-align:left;font-weight:600;color:var(--text-3);font-size:10px;
  text-transform:uppercase;letter-spacing:.1em;padding:0 8px 6px 0;border-bottom:1px solid var(--line)}
td{padding:5px 8px 5px 0;border-bottom:1px solid var(--line-soft);color:var(--text-2)}
td.k{color:var(--text-1)}
.empty{color:var(--text-3);padding:10px 0}
</style>

<header>
  <h1>warden</h1>
  <span class="dim" id="target"></span>
  <span class="dim3" id="digest"></span>
  <span id="ready"></span>
  <span class="dim3" id="uptime"></span>
  <span class="dim3" id="session"></span>
</header>

<main>
  <div id="pipeline"></div>
  <div id="posture"></div>

  <section class="grid" id="tiles"></section>

  <section class="card wide">
    <h2>Behavioural findings</h2>
    <div id="findings"></div>
  </section>

  <section class="grid">
    <div class="card wide">
      <h2>Data flow this session</h2>
      <div id="flow"></div>
    </div>
  </section>

  <section class="grid">
    <div class="card"><h2>Top syscalls</h2><div id="syscalls"></div></div>
    <div class="card"><h2>Failing syscalls</h2><div id="errnos"></div></div>
    <div class="card"><h2>Network destinations</h2><div id="dials"></div></div>
    <div class="card"><h2>Supply chain</h2><div id="chain"></div></div>
  </section>

  <section class="card wide">
    <h2>Containers &mdash; attribution is exact within one, by container across them</h2>
    <div id="containers"></div>
  </section>

  <section class="card wide">
    <h2>Audit chain</h2>
    <div id="audit"></div>
  </section>
</main>

<script>
const SEV_ORDER = ['critical','high','medium','low','info'];
const GLYPH = {trusted:'●', watch:'◐', degraded:'◑', quarantine:'■'};

const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ms = ns => ns == null ? '—' : (ns/1e6 < 1 ? (ns/1e3).toFixed(0)+' µs' : (ns/1e6).toFixed(1)+' ms');
const bytes = n => {
  n = n || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB','MB','GB','TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length-1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
};
const num = n => (n || 0).toLocaleString();

function tile(title, body){ return '<div class="card"><h2>'+title+'</h2>'+body+'</div>'; }
function row(k, v, cls){ return '<div class="row"><span class="dim">'+k+'</span><span class="'+(cls||'dim')+'">'+v+'</span></div>'; }

function hist(h){
  if(!h || !h.count) return '<div class="dim3">no samples yet</div>';
  return row('p50', ms(h.p50_ns)) + row('p95', ms(h.p95_ns)) + row('p99', ms(h.p99_ns))
       + row('max', ms(h.max_ns)) + row('n', num(h.count), 'dim3');
}

// Horizontal bars share one baseline and one scale, so lengths are comparable.
function bars(items, color){
  if(!items || !items.length) return '<div class="dim3">nothing observed</div>';
  const max = Math.max.apply(null, items.map(i => i.count || i.value || 0)) || 1;
  return items.map(i => {
    const v = i.count || i.value || 0;
    const pct = Math.max(1.5, (v/max)*100);
    return '<div class="barrow" title="'+esc(i.name)+': '+num(v)+'">'
      + '<span class="lbl">'+esc(i.name)+'</span>'
      + '<span class="track"><span class="bar" style="width:'+pct+'%;background:'+(color||'var(--series-1)')+'"></span></span>'
      + '<span class="num">'+num(v)+'</span></div>';
  }).join('');
}

function flowPanel(t){
  const parts = [
    {name:'file read',  v:t.file_read_bytes,  c:'var(--series-1)'},
    {name:'file write', v:t.file_write_bytes, c:'var(--series-2)'},
    {name:'net read',   v:t.net_read_bytes,   c:'var(--series-3)'},
    {name:'net write',  v:t.net_write_bytes,  c:'var(--series-4)'},
  ];
  const total = parts.reduce((a,p) => a + (p.v||0), 0);
  if(!total) return '<div class="dim3">no data movement observed yet</div>';
  const segs = parts.filter(p => p.v > 0).map(p =>
    '<span class="seg" style="flex:'+p.v+';background:'+p.c+'" title="'+p.name+': '+bytes(p.v)+'"></span>').join('');
  const legend = parts.map(p =>
    '<span><span class="key" style="background:'+p.c+'"></span>'+p.name+' '+bytes(p.v)+'</span>').join('');
  return '<div class="stack">'+segs+'</div><div class="legend">'+legend+'</div>';
}

function findingsPanel(fs){
  if(!fs.length) return '<div class="empty">No findings. '
    + '<span class="dim3">Deterministic detectors are silent and the trace pipeline is healthy.</span></div>';
  const byFam = {};
  fs.forEach(f => { (byFam[f.family] = byFam[f.family] || []).push(f); });
  return Object.keys(byFam).sort().map(fam => {
    const rows = byFam[fam].sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).map(f =>
      '<div class="finding">'
      + '<span><span class="chip s-'+esc(f.severity)+'">'+esc(f.severity)+'</span></span>'
      + '<span><span class="ftitle">'+esc(f.title)+'</span>'
      +   '<div class="fmeta">'+esc(f.detector)+' · '+esc(f.confidence)+'</div>'
      +   '<div class="ev">'+esc(f.detail)+'</div>'
      +   (f.evidence && f.evidence.length
            ? '<div class="ev dim3">'+f.evidence.slice(0,6).map(esc).join('\n')
              + (f.evidence.length > 6 ? '\n… +'+(f.evidence.length-6)+' more' : '')+'</div>'
            : '')
      + '</span>'
      + '<span class="count">×'+num(f.count)+'</span>'
      + '</div>').join('');
    return '<h2 style="margin-top:14px">'+esc(fam)+'</h2>'+rows;
  }).join('');
}

async function get(url){ const r = await fetch(url); if(!r.ok) throw new Error(url); return r.json(); }

async function tick(){
  let score, findings, behavior, containers, stats;
  try {
    [score, findings, behavior, containers, stats] =
      await Promise.all([get('/score'), get('/findings'), get('/behavior'), get('/containers'), get('/stats')]);
  } catch(e) {
    document.getElementById('ready').innerHTML = '<span class="s-critical">● unreachable</span>';
    return;
  }

  const c = stats.metrics.counters, g = stats.metrics.gauges, h = stats.metrics.histograms;
  const t = behavior.totals, pipe = behavior.pipeline;

  document.getElementById('target').textContent = stats.target;
  document.getElementById('digest').textContent = (stats.profile_digest||'').slice(0,19)+'…';
  document.getElementById('ready').innerHTML = stats.ready
    ? '<span style="color:var(--good)">● serving</span>'
    : '<span style="color:var(--critical)">● draining</span>';
  document.getElementById('uptime').textContent = 'up '+Math.round(behavior.uptime_seconds)+'s';
  document.getElementById('session').textContent = behavior.session;

  // A blind analyzer must say so louder than it says "clean".
  document.getElementById('pipeline').innerHTML = (!behavior.tracing || !score.analysis_healthy)
    ? '<div class="banner">⚠ <b>Analysis degraded.</b> <span class="dim">'
      + (!behavior.tracing
          ? 'Syscall tracing is off (-analyze=off). Confinement is still enforced, but no behaviour is being observed — an empty findings list below means nothing.'
          : 'The trace pipeline dropped events or saw none. Findings below are computed from an incomplete record.')
      + '</span></div>'
    : '';

  document.getElementById('posture').innerHTML =
    '<div class="posture p-'+esc(score.posture)+'">'
    + '<span class="glyph">'+(GLYPH[score.posture]||'●')+'</span>'
    + '<span><div class="tier">'+esc(score.posture)+'</div>'
    + '<div class="why">'+esc(score.posture_reason)+'</div></span>'
    + '<span style="margin-left:auto;text-align:right" class="dim">'
    +   score.deterministic_findings+' kernel-attested · '
    +   score.critical+' critical · '+score.high+' high · '+score.medium+' medium'
    + '</span></div>';

  document.getElementById('tiles').innerHTML = [
    tile('Requests', '<div class="v">'+num(behavior.requests)+'</div>'
      + row('failed', num(behavior.failures), behavior.failures ? 's-high' : 'dim3')
      + row('error rate', ((score.reliability.error_rate||0)*100).toFixed(1)+'%', 'dim3')
      + row('unsolicited', num(c.warden_unsolicited_messages_total||0), 'dim3')),
    tile('Request latency', hist(h.warden_request_seconds)),
    tile('Kernel denials', '<div class="v" style="color:'+(behavior.denials?'var(--critical)':'var(--good)')+'">'
      + num(behavior.denials)+'</div>'
      + row('quarantined', num(c.warden_containers_quarantined_total||0), 'dim3')
      + row('warmup failures', num(c.warden_container_warmup_failures_total||0), 'dim3')),
    tile('Syscalls observed', '<div class="v">'+num(t.syscalls)+'</div>'
      + row('failed', num(t.errors), 'dim3')
      + row('distinct paths', num(t.distinct_paths), 'dim3')
      + row('process spawns', num(t.process_spawns), t.process_spawns ? 's-medium' : 'dim3')),
    tile('Idle activity', '<div class="v">'+num(behavior.idle.syscalls)+'</div>'
      + row('bursts', num(behavior.idle.bursts), 'dim3')
      + row('egress while idle', bytes(behavior.idle.net_write_bytes),
            behavior.idle.net_write_bytes ? 's-critical' : 'dim3')),
    tile('Pool', '<div class="v">'+num(g.warden_pool_idle||0)+' / '+num(g.warden_pool_size||0)+'</div>'
      + row('in use', num(g.warden_pool_in_use||0))
      + row('acquire timeouts', num(c.warden_pool_acquire_timeouts_total||0),
            (c.warden_pool_acquire_timeouts_total||0) ? 's-high' : 'dim3')
      + row('degraded', (g.warden_pool_degraded||0) ? 'yes' : 'no',
            (g.warden_pool_degraded||0) ? 's-high' : 'dim3')),
    tile('Container start', hist(h.warden_container_create_seconds)),
    tile('Trace pipeline', '<div class="v">'+num(pipe.events_ingested)+'</div>'
      + row('dropped', num(pipe.events_dropped), pipe.events_dropped ? 's-high' : 'dim3')
      + row('log truncations', num(pipe.log_truncations), 'dim3')
      + row('read', bytes(pipe.bytes_read), 'dim3')),
  ].join('');

  document.getElementById('findings').innerHTML = findingsPanel(findings.findings || []);
  document.getElementById('flow').innerHTML = flowPanel(t);
  document.getElementById('syscalls').innerHTML = bars(t.top_syscalls, 'var(--series-1)');
  document.getElementById('errnos').innerHTML = bars(t.top_errnos, 'var(--series-2)');

  const dials = Object.keys(t.dials || {}).map(k => ({name:k, count:t.dials[k]}));
  document.getElementById('dials').innerHTML = dials.length
    ? bars(dials, 'var(--series-4)')
    : '<div class="dim3">no connections — the container has no network interfaces</div>';

  const ep = behavior.entrypoint || {};
  document.getElementById('chain').innerHTML =
      row('entrypoint', esc((ep.path||'—').split('/').pop()))
    + row('digest', esc((ep.sha256||'unmeasured').slice(0,26)), 'dim3')
    + row('interpreter', esc((ep.interpreter||'—').split('/').pop()), 'dim3')
    + row('interp digest', esc((ep.interpreter_sha256||'—').slice(0,26)), 'dim3')
    + row('tool manifest', esc((behavior.manifest_hash||'unpinned').slice(0,26)),
          (behavior.manifest_hash||'').indexOf('DRIFT') === 0 ? 's-critical' : 'dim3');

  document.getElementById('containers').innerHTML = containers && containers.length
    ? '<table><tr><th>container</th><th>state</th><th>requests</th><th>denials</th>'
      + '<th>events</th><th>dropped</th><th>paths</th><th>read</th><th>net out</th></tr>'
      + containers.map(x => '<tr>'
        + '<td class="k">'+esc(x.container_id.slice(0,16))+'</td>'
        + '<td style="color:'+(x.live?'var(--good)':'var(--text-3)')+'">'+(x.live?'live':'retired')+'</td>'
        + '<td>'+num(x.requests)+'</td>'
        + '<td'+(x.denials?' class="s-critical"':'')+'>'+num(x.denials)+'</td>'
        + '<td>'+num(x.events)+'</td>'
        + '<td'+(x.dropped?' class="s-high"':'')+'>'+num(x.dropped)+'</td>'
        + '<td>'+num(x.distinct_paths)+'</td>'
        + '<td>'+bytes(x.file_read_bytes)+'</td>'
        + '<td'+(x.net_write_bytes?' class="s-medium"':'')+'>'+bytes(x.net_write_bytes)+'</td>'
        + '</tr>').join('') + '</table>'
    : '<div class="dim3">no containers</div>';

  try {
    const a = await get('/audit?n=6');
    document.getElementById('audit').innerHTML =
        row('entries written', num(a.stats.written))
      + row('dropped (recorded as gaps)', num(a.stats.dropped), a.stats.dropped ? 's-high' : 'dim3')
      + row('backlog', num(a.stats.backlog), 'dim3')
      + row('chain head', esc((a.stats.chain_head||'').slice(0,30)), 'dim3')
      + row('checkpoint key', esc((a.stats.public_key||'').slice(0,24)), 'dim3')
      + '<div class="ev dim3" style="margin-top:8px">verify: warden-audit -verify '+esc(a.stats.path)+'</div>';
  } catch(e) {
    document.getElementById('audit').innerHTML =
      '<div class="dim3">Audit log disabled. Start with <code>-audit &lt;path&gt;</code> for a hash-chained record.</div>';
  }
}

tick();
setInterval(tick, 1000);
</script>
`
