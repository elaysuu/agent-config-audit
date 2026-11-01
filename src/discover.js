'use strict';
const fs = require('fs'), path = require('path'), os = require('os');
function candidates({ home = os.homedir(), platform = process.platform, appdata = process.env.APPDATA, repo = process.cwd(), machine = true } = {}) {
  const c = [];
  if (machine) {
    const appSup = platform === 'darwin' ? path.join(home, 'Library/Application Support') : platform === 'win32' ? (appdata || path.join(home, 'AppData/Roaming')) : path.join(home, '.config');
    c.push(['Claude Desktop', path.join(appSup, 'Claude/claude_desktop_config.json')]);
    c.push(['Claude Code (user)', path.join(home, '.claude.json')]);
    c.push(['Cursor (global)', path.join(home, '.cursor/mcp.json')]);
    c.push(['VS Code (user)', path.join(appSup, 'Code/User/mcp.json')]);
    c.push(['VS Code (user settings)', path.join(appSup, 'Code/User/settings.json')]);
    c.push(['Windsurf', path.join(home, '.codeium/windsurf/mcp_config.json')]);
  }
  if (repo) for (const [n, f] of [['Repo .mcp.json', '.mcp.json'], ['Repo Cursor', '.cursor/mcp.json'], ['Repo VS Code', '.vscode/mcp.json'], ['Repo mcp.json', 'mcp.json']]) c.push([n, path.join(repo, f)]);
  return c;
}
function stripJsonc(s) { return s.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str || '').replace(/,(\s*[}\]])/g, '$1'); }
function extractServers(obj) {
  const out = {};
  const take = o => { if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) if (v && typeof v === 'object') out[k] = v; };
  take(obj.mcpServers); take(obj.servers); take(obj.mcp && obj.mcp.servers); take(obj['mcp.servers']);
  if (obj.projects) for (const p of Object.values(obj.projects)) take(p && p.mcpServers);
  return out;
}
function discover(opts) {
  const found = [];
  for (const [source, file] of candidates(opts)) {
    if (!fs.existsSync(file)) continue;
    let obj; try { obj = JSON.parse(stripJsonc(fs.readFileSync(file, 'utf8'))); } catch (e) { found.push({ source, file, error: 'unparseable JSON', servers: {} }); continue; }
    found.push({ source, file, servers: extractServers(obj) });
  }
  return found;
}
module.exports = { candidates, discover, extractServers, stripJsonc };
