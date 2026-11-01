const test = require('node:test'), assert = require('node:assert'), path = require('path'), fs = require('fs');
const A = require('../src/analyze'); const { audit } = require('../src/audit'); const { html } = require('../src/report'); const { verify } = require('../src/license'); const { candidates, stripJsonc } = require('../src/discover');
const repo = path.join(__dirname, 'fixtures/repo');
test('packageOf', () => {
  assert.deepEqual(A.packageOf({ command: 'npx', args: ['-y', '@scope/x@1.2.3'] }), { ecosystem: 'npm', name: '@scope/x', version: '1.2.3' });
  assert.deepEqual(A.packageOf({ command: 'uvx', args: ['mcp-server-fetch==2025.1.1'] }), { ecosystem: 'PyPI', name: 'mcp-server-fetch', version: '2025.1.1' });
  assert.equal(A.packageOf({ command: 'node', args: ['server.js'] }), null);
});
test('candidates cover all clients', () => { const c = candidates({ home: '/h', platform: 'darwin', repo: '/r' }).map(x => x[0]).join(); for (const n of ['Claude Desktop', 'Cursor', 'VS Code', 'Windsurf', 'Repo']) assert.ok(c.includes(n), n); });
test('jsonc', () => assert.deepEqual(JSON.parse(stripJsonc('{ // c\n "a": "http://x", }')), { a: 'http://x' }));
test('offline fixture audit', async () => {
  const r = await audit({ repo, machine: false, offline: true, now: 'T', hostLabel: 'h' });
  assert.equal(r.summary.configs, 3); assert.equal(r.summary.servers, 6);
  assert.equal(r.summary.secrets, 1); assert.equal(r.summary.http, 1); assert.equal(r.summary.unpinned, 2);
  const rb = r.configs[0].servers.find(s => s.name === 'remote-bridge');
  assert.ok(rb.findings.some(f => f.id === 'GHSA-6xpm-ggf7-wc3p' && f.sev === 'CRITICAL'));
  const safe = r.configs[0].servers.find(s => s.name === 'safe'); assert.equal(safe.findings.length, 0);
  assert.equal(r.configs.find(c => c.file.includes('.cursor')).servers[0].findings.length, 0); // localhost http ok
  assert.ok(r.score > 0 && r.grade === 'F');
  const h = html(r, { brand: { name: 'Acme <Sec>' } }); assert.ok(h.includes('Acme &lt;Sec&gt;') && !h.includes('FAKEFAKEFAKEFAKE'));
});
test('schema required keys present', async () => { const s = require('../schema/report.schema.json'); const r = await audit({ repo, machine: false, offline: true }); for (const k of s.required) assert.ok(k in r, k); });
test('license gating', async () => {
  assert.equal((await verify('k')).team, false);
  const mk = j => async () => ({ json: async () => j });
  assert.equal((await verify('k', { productId: 'P', fetchImpl: mk({ success: true, purchase: {} }) })).team, true);
  assert.equal((await verify('k', { productId: 'P', fetchImpl: mk({ success: true, purchase: { refunded: true } }) })).team, false);
  assert.equal((await verify('k', { productId: 'P', fetchImpl: async () => { throw new Error('x'); } })).team, false);
});
