#!/usr/bin/env node
'use strict';
const fs = require('fs'), path = require('path');
const { audit } = require('../src/audit'); const { html } = require('../src/report'); const { verify } = require('../src/license');
const argv = process.argv.slice(2); const flag = n => argv.includes(n); const val = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
if (flag('-h') || flag('--help')) { console.log(`agent-config-audit [--repo DIR] [--no-machine] [--out report.html] [--offline]
Team report pack (license key via --key or AGENT_AUDIT_KEY):
  --brand brand.json   branded, print-to-PDF ready HTML ({"name","client","logo"})
  --json out.json      CI JSON (schema/report.schema.json)
  --fail-on LEVEL      exit 1 if any finding >= LOW|MEDIUM|HIGH|CRITICAL`); process.exit(0); }
(async () => {
  const r = await audit({ repo: path.resolve(val('--repo') || '.'), machine: !flag('--no-machine'), offline: flag('--offline') });
  const wantsTeam = val('--brand') || val('--json') || val('--fail-on');
  let team = false;
  if (wantsTeam) { const l = await verify(val('--key') || process.env.AGENT_AUDIT_KEY); team = l.team; if (!team) console.error(`Team features skipped: ${l.reason}. Get the Team report pack: https://setrov.gumroad.com/l/cpclzn`); }
  const brand = team && val('--brand') ? JSON.parse(fs.readFileSync(val('--brand'), 'utf8')) : null;
  const out = val('--out') || 'mcp-audit-report.html'; fs.writeFileSync(out, html(r, { brand }));
  if (team && val('--json')) fs.writeFileSync(val('--json'), JSON.stringify(r, null, 2));
  console.log(`Risk ${r.score}/100 (grade ${r.grade}) · ${r.summary.servers} servers in ${r.summary.configs} configs · advisories ${r.summary.advisory} · unpinned ${r.summary.unpinned} · secrets ${r.summary.secrets} · http ${r.summary.http}\nReport: ${path.resolve(out)}`);
  if (team && val('--fail-on')) { const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']; const min = order.indexOf(val('--fail-on').toUpperCase());
    if (r.configs.flatMap(c => c.servers).flatMap(s => s.findings).some(f => order.indexOf(f.sev === 'MODERATE' ? 'MEDIUM' : f.sev) >= min)) process.exit(1); }
})().catch(e => { console.error(e.message); process.exit(2); });
