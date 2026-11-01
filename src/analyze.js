'use strict';
const SECRET_KEY = /(token|secret|password|passwd|api[_-]?key|private[_-]?key|auth|credential)/i;
const SECRET_VAL = /^(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})$/;
function isPlaceholder(v) { return !v || /^\$\{.*\}$|^\$[A-Z_]+$|^<.*>$|^(your|xxx|changeme|REPLACE)/i.test(v) || /\$\{(env|input):/.test(v); }
// Returns {ecosystem, name, version|null} for npx/uvx/pipx/docker launches.
function packageOf(s) {
  const cmd = (s.command || '').split(/[\\/]/).pop(); const args = (s.args || []).map(String);
  const firstPos = list => list.find(a => !a.startsWith('-'));
  if (/^(npx|bunx|pnpx)$/.test(cmd) || (cmd === 'pnpm' && args[0] === 'dlx')) {
    let a = args.filter(x => x !== 'dlx'); const i = a.findIndex(x => x === '-p' || x === '--package'); const spec = i >= 0 ? a[i + 1] : firstPos(a);
    if (!spec) return null; const m = /^(@?[^@]+)(?:@(.+))?$/.exec(spec); return { ecosystem: 'npm', name: m[1], version: m[2] || null };
  }
  if (/^(uvx|pipx)$/.test(cmd) || (cmd === 'uv' && args[0] === 'tool')) {
    const spec = firstPos(args.filter(x => !['tool', 'run'].includes(x))); if (!spec) return null;
    const m = /^([A-Za-z0-9_.\-\[\]]+?)(?:==(.+))?$/.exec(spec); return m ? { ecosystem: 'PyPI', name: m[1].replace(/\[.*\]/, ''), version: m[2] || null } : null;
  }
  if (cmd === 'docker') { const img = args.find(a => /\//.test(a) && !a.startsWith('-')); if (img) return { ecosystem: 'docker', name: img.split(/[:@]/)[0], version: /[:@]/.test(img) ? img.split(/[:@]/).pop() : null }; }
  return null;
}
function exactVersion(v) { return !!v && /^\d+\.\d+\.\d+([-.+][\w.]+)?$|^sha256:/.test(v) && v !== 'latest'; }
function findings(name, s, advisories) {
  const f = []; const pkg = packageOf(s);
  const url = s.url || s.serverUrl;
  if (url && /^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(url)) f.push({ type: 'http-remote', sev: 'HIGH', msg: `Remote MCP over plain HTTP: ${url}` });
  if (pkg && !exactVersion(pkg.version)) f.push({ type: 'unpinned', sev: 'MEDIUM', msg: `${pkg.name} runs ${pkg.version ? `"${pkg.version}"` : 'latest'} on every launch; pin an exact version` });
  for (const [k, v] of Object.entries(Object.assign({}, s.env, s.headers))) {
    const val = String(v); if (isPlaceholder(val)) continue;
    if (SECRET_VAL.test(val) || (SECRET_KEY.test(k) && val.length >= 12) || /^Bearer\s+\S{12,}/.test(val)) f.push({ type: 'plaintext-secret', sev: 'HIGH', msg: `${k} holds a plaintext secret (${val.slice(0, 4)}…, ${val.length} chars)` });
  }
  // advisories: list already resolved for this package. If the version is pinned they affect that exact version (OSV);
  // if unpinned, the latest release is usually patched, so report as LOW "history" with the fix floor.
  for (const a of advisories) {
    const pinned = exactVersion(pkg && pkg.version);
    f.push({ type: 'advisory', id: a.id, sev: pinned ? (a.severity === 'MODERATE' ? 'MEDIUM' : (a.severity || 'HIGH')) : 'LOW',
      msg: `${a.id}${pinned ? ` affects ${pkg.version}` : ' (past advisory; unpinned, so you may be on a fixed or a vulnerable version)'}: ${a.summary || ''}${a.fixed ? ` | fixed in ${a.fixed}` : ''}` });
  }
  return { name, pkg, findings: f };
}
const W = { CRITICAL: 40, HIGH: 20, MODERATE: 10, MEDIUM: 10, LOW: 3 };
function score(servers) { const pts = servers.flatMap(s => s.findings).reduce((n, f) => n + (W[f.sev] || 5), 0); return Math.min(100, pts); }
function grade(n) { return n === 0 ? 'A' : n < 15 ? 'B' : n < 35 ? 'C' : n < 60 ? 'D' : 'F'; }
module.exports = { packageOf, exactVersion, findings, score, grade, isPlaceholder };
