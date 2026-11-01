'use strict';
const os = require('os');
const { discover } = require('./discover'); const A = require('./analyze'); const { resolve, key } = require('./advisories');
async function audit(opts = {}) {
  const configs = discover(opts);
  const pkgs = []; for (const c of configs) for (const s of Object.values(c.servers)) { const p = A.packageOf(s); if (p) pkgs.push(p); }
  const adv = await resolve(pkgs, opts);
  const out = configs.map(c => ({ source: c.source, file: c.file, error: c.error, servers: Object.entries(c.servers).map(([n, s]) => { const p = A.packageOf(s); return A.findings(n, s, p ? adv.get(key(p)) || [] : []); }) }));
  const all = out.flatMap(c => c.servers); const fs_ = all.flatMap(s => s.findings); const n = t => fs_.filter(f => f.type === t).length;
  const score = A.score(all);
  return { schema: 'https://github.com/elaysuu/agent-config-audit/schema/report.schema.json', version: 1, generated: opts.now || new Date().toISOString(), host: opts.hostLabel || os.hostname(),
    score, grade: A.grade(score), summary: { configs: out.length, servers: all.length, advisory: n('advisory'), unpinned: n('unpinned'), secrets: n('plaintext-secret'), http: n('http-remote') }, configs: out };
}
module.exports = { audit };
