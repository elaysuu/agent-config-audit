'use strict';
const e = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const C = { CRITICAL: '#7f1d1d', HIGH: '#b91c1c', MEDIUM: '#b45309', MODERATE: '#b45309', LOW: '#4b5563' };
function html(r, { brand } = {}) {
  const rows = r.configs.flatMap(c => c.servers.map(s => `<tr><td>${e(c.source)}<br><small>${e(c.file)}</small></td><td><b>${e(s.name)}</b>${s.pkg ? `<br><small>${e(s.pkg.ecosystem)}:${e(s.pkg.name)}@${e(s.pkg.version || 'latest')}</small>` : ''}</td><td>${s.findings.length ? s.findings.map(f => `<div><span style="background:${C[f.sev] || '#555'};color:#fff;border-radius:3px;padding:0 5px;font-size:11px">${e(f.sev)}</span> ${f.id ? `<a href="https://osv.dev/vulnerability/${e(f.id)}">${e(f.msg)}</a>` : e(f.msg)}</div>`).join('') : '<span style="color:#15803d">no findings</span>'}</td></tr>`)).join('');
  const title = brand ? `${e(brand.name)} · MCP configuration audit` : 'MCP configuration audit';
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>body{font:14px system-ui;max-width:1000px;margin:24px auto;color:#111}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px;vertical-align:top;text-align:left}small{color:#666}.score{font-size:40px;font-weight:700}@media print{a{color:#000}}</style></head><body>
${brand && brand.logo ? `<img src="${e(brand.logo)}" style="height:40px">` : ''}<h1>${title}</h1>
<p>Generated ${e(r.generated)} on ${e(r.host)}${brand && brand.client ? ` for ${e(brand.client)}` : ''}</p>
<p class="score">Risk ${r.score}/100 · grade ${r.grade}</p>
<p>${r.summary.configs} config files · ${r.summary.servers} MCP servers · ${r.summary.advisory} advisories · ${r.summary.unpinned} unpinned · ${r.summary.secrets} plaintext secrets · ${r.summary.http} plain-HTTP remotes</p>
<table><tr><th>Config</th><th>Server</th><th>Findings</th></tr>${rows || '<tr><td colspan=3>No MCP configs found.</td></tr>'}</table>
<p><small>Advisory data: OSV.dev and AKRENON Security MCP Security Vulnerabilities Dataset (CC BY 4.0, https://data.akrenon.com/mcp-advisories/) via agent-advisory-gate. Block these in CI: https://github.com/elaysuu/agent-advisory-gate. Secrets are shown truncated; nothing leaves your machine except package names sent to OSV.</small></p></body></html>`;
}
module.exports = { html };
