'use strict';
const DATA_URL = 'https://raw.githubusercontent.com/elaysuu/agent-advisory-gate/main/data/mcp-advisories.json';
function fixedOf(v) { for (const a of v.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) return e.fixed; return null; }
// pkgs: [{ecosystem,name,version}] -> Map key "eco|name|ver" -> [{id,summary,severity,fixed}]
async function resolve(pkgs, { fetchImpl = globalThis.fetch, offline = false } = {}) {
  const out = new Map(); const q = pkgs.filter(p => p.ecosystem !== 'docker');
  let ds = require('../data/mcp-advisories.json'); // bundled snapshot (AKRENON CC BY 4.0)
  if (!offline) { try { ds = await (await fetchImpl(DATA_URL)).json(); } catch {} }
  for (const p of q) out.set(key(p), ds.advisories.filter(a => a.package === p.name && a.ecosystem === p.ecosystem && !(p.version && a.fixed && cmp(p.version, a.fixed) >= 0))
    .map(a => ({ id: a.id, summary: a.summary, severity: a.severity, fixed: a.fixed })));
  if (offline || !q.length) return out;
  try {
    const body = { queries: q.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, ...(p.version && /^\d/.test(p.version) ? { version: p.version } : {}) })) };
    const r = await (await fetchImpl('https://api.osv.dev/v1/querybatch', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })).json();
    for (let i = 0; i < q.length; i++) {
      const list = out.get(key(q[i])); const have = new Set(list.map(a => a.id));
      for (const v of (r.results[i] && r.results[i].vulns) || []) {
        if (have.has(v.id)) continue;
        const full = await (await fetchImpl(`https://api.osv.dev/v1/vulns/${v.id}`)).json();
        if (full.withdrawn || (full.aliases || []).some(x => have.has(x))) continue;
        list.push({ id: v.id, summary: full.summary || '', severity: ((full.database_specific || {}).severity || '').toUpperCase(), fixed: fixedOf(full) });
      }
    }
  } catch (e) { process.stderr.write(`OSV lookup failed (${e.message}); dataset-only results\n`); }
  return out;
}
function cmp(a, b) { const pa = String(a).split(/[.-]/).map(Number), pb = String(b).split(/[.-]/).map(Number); for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); return 0; }
const key = p => `${p.ecosystem}|${p.name}|${p.version || ''}`;
module.exports = { resolve, key, cmp };
