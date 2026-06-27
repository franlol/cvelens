// CISA Known Exploited Vulnerabilities catalog — a single JSON feed. Doubles as
// the seed for the left-hand list (every entry is an actively-exploited CVE) and
// as the source of the exploitation status / dates shown in the KEV card.
//   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

import { getCached, putCached } from "../cache"
import { fetchJson } from "./http"
import type { KevEntry, SearchHit } from "./types"
import type { Severity } from "../data"

const URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const TTL = 6 * 60 * 60 * 1000 // 6h
const CACHE_KEY = "kev-catalog"

export interface KevCatalog {
  map: Map<string, KevEntry>
  // Newest-first list seed for the list pane (id only — enriched lazily).
  order: string[]
}

interface RawKev {
  cveID: string
  dateAdded: string
  dueDate: string
  knownRansomwareCampaignUse: string
  vulnerabilityName: string
}

function build(raw: RawKev[]): KevCatalog {
  // Newest additions first.
  const sorted = [...raw].sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : -1))
  const map = new Map<string, KevEntry>()
  for (const v of sorted) {
    map.set(v.cveID, {
      added: v.dateAdded || "",
      due: v.dueDate || "",
      ransom: v.knownRansomwareCampaignUse || "Unknown",
      title: v.vulnerabilityName || "",
    })
  }
  return { map, order: sorted.map((v) => v.cveID) }
}

let memo: KevCatalog | null = null

export async function fetchKevCatalog(): Promise<KevCatalog> {
  if (memo) return memo
  const cached = await getCached<RawKev[]>(CACHE_KEY, TTL)
  if (cached) {
    memo = build(cached)
    return memo
  }
  const json = await fetchJson<{ vulnerabilities: RawKev[] }>(URL, { timeoutMs: 20000 })
  const raw = json.vulnerabilities || []
  await putCached(CACHE_KEY, raw, TTL)
  memo = build(raw)
  return memo
}

// Local fallback search over the KEV seed (id + vulnerability name).
export function searchKev(cat: KevCatalog, q: string, limit = 40): SearchHit[] {
  const needle = q.toLowerCase()
  const hits: SearchHit[] = []
  for (const id of cat.order) {
    const e = cat.map.get(id)!
    if (id.toLowerCase().includes(needle) || e.title.toLowerCase().includes(needle)) {
      hits.push({ id, title: e.title, sev: "NONE" as Severity, score: "—" })
      if (hits.length >= limit) break
    }
  }
  return hits
}
