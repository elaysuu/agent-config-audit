# agent-config-audit

`npx agent-config-audit` finds every MCP config on your machine and in the current repo and writes a one-page HTML report.

Scans: Claude Desktop, Claude Code (~/.claude.json), Cursor (global + repo .cursor/mcp.json), VS Code (user mcp.json / settings.json + repo .vscode/mcp.json), Windsurf, repo .mcp.json / mcp.json.

Flags:
- Known advisories (OSV + AKRENON MCP dataset via agent-advisory-gate; bundled snapshot for --offline)
- Unpinned packages (npx/uvx without an exact version)
- Plaintext secrets in env/headers (shown truncated, never printed in full)
- Remote MCP over plain http:// (localhost allowed)
- Risk score 0-100 and grade A-F

```
npx agent-config-audit                 # machine + current dir
npx agent-config-audit --repo ./svc --no-machine --out report.html
```
Only package names are sent to OSV. Nothing else leaves your machine.

## Team report pack (paid, license key)

Buy the Team report pack: https://setrov.gumroad.com/l/cpclzn
`--brand brand.json` branded print-to-PDF HTML, `--json out.json` CI JSON (schema/report.schema.json), `--fail-on HIGH` CI exit code. Key via `--key` or `AGENT_AUDIT_KEY`.

MIT. Advisory data: AKRENON Security (CC BY 4.0), OSV.dev.

## Also available as

- VS Code / Open VSX extension: https://open-vsx.org/extension/elaysuu/agent-package-advisory
- RapidAPI (HTTP API): https://rapidapi.com/Elayosetrov/api/agent-package-advisory-check
- Apify actor: https://apify.com/crimson_goby/osv-package-checker




