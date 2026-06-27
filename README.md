# cvelens

A terminal UI for browsing CVEs across multiple intelligence sources (NVD, MITRE,
OSV, CISA KEV, FIRST/EPSS) and seeing exactly which source supplied each field.
Built with [OpenTUI](https://github.com/anomalyco/opentui) + React, ported from
the `CVE TUI` design and wired to **live** data feeds.

![two-pane CVE browser](./docs/preview.txt)

## Run

Requires [Bun](https://bun.sh).

```bash
bun install
bun start          # or: bun run dev   (hot reload)
```

## Live data

cvelens fetches in real time from five public feeds and merges them, recording
which feed supplied each field:

| Source | Provides | Endpoint |
|--------|----------|----------|
| **CISA KEV** | list seed + exploitation status/dates | `cisa.gov/.../known_exploited_vulnerabilities.json` |
| **NVD 2.0** | CVSS v3.1, CWE, CPE, references, dates | `services.nvd.nist.gov/rest/json/cves/2.0` |
| **CVE.org (MITRE)** | canonical description, CNA CVSS/CWE, assigner | `cveawg.mitre.org/api/cve/{id}` |
| **OSV.dev** | package ecosystem version ranges | `api.osv.dev/v1/vulns/{id}` |
| **FIRST EPSS** | exploit-probability score + percentile | `api.first.org/data/v1/epss` |

- The list is **seeded from the CISA KEV catalog** (newest first); typing in the
  search box runs a live **NVD keyword query**.
- Selecting a CVE fans out to NVD/MITRE/OSV/EPSS in parallel and merges the
  results. Each row's severity/score/EPSS fills in once you've visited it.

### NVD API key (optional)

NVD rate-limits keyless clients to 5 requests / 30 s. Set `NVD_API_KEY` to raise
this to 50 / 30 s — cvelens reads it from the environment automatically:

```bash
export NVD_API_KEY=…   # https://nvd.nist.gov/developers/request-an-api-key
```

### Caching & offline

Responses are cached under `~/.cache/cvelens/` (override with `XDG_CACHE_HOME`):
KEV catalog ~6 h, per-CVE records ~24 h. If every source is unreachable, cvelens
falls back to a small bundled seed dataset so the UI always renders — the window
bar shows `⚠ offline` in that case.

## Keys

| Key      | Action                                            |
|----------|---------------------------------------------------|
| `↑`/`↓`  | move selection (also `j`/`k`)                     |
| `/`      | focus fuzzy search · `Esc` to leave               |
| `s`      | cycle source: merged → nvd → mitre → osv → kev    |
| `f`      | toggle KEV-only (exploited) view                  |
| `PgUp`/`PgDn` | scroll the detail pane (also `Ctrl+u`/`Ctrl+d`) |
| `y`      | yank the selected CVE id to the clipboard (OSC 52)|
| `?`      | help overlay                                       |
| `q`      | quit                                              |

## How the "source lens" works

The left pane lists vulnerabilities; the right pane shows the selected CVE.
Switching the **SOURCE** tab re-derives the detail from that source's coverage
map (`src/data.ts` → `COV`). Fields a source does not actually provide are dimmed
and replaced with an explicit gap note — e.g. EPSS only comes from FIRST.org, so
under the NVD lens the EPSS card reads *"✗ Not provided by NVD"*. Under `merged`,
every field is shown with provenance badges noting which feed it came from.

## Structure

| File              | Responsibility                                            |
|-------------------|-----------------------------------------------------------|
| `src/index.tsx`   | Creates the renderer and mounts `<App/>`.                 |
| `src/App.tsx`     | All UI components, layout, keyboard handling, async state. |
| `src/derive.ts`   | Pure view-model derivation (filter + per-source coverage).|
| `src/store.ts`    | Orchestrates list/search/detail across the live sources.  |
| `src/sources/*`   | One fetcher per feed (nvd, mitre, osv, kev, epss) + HTTP. |
| `src/cache.ts`    | TTL'd on-disk response cache.                             |
| `src/data.ts`     | Types, source/coverage tables, palette, offline seed.     |
| `src/util.ts`     | Column fitting and OSC 52 clipboard helpers.              |
