// FIRST.org EPSS — Exploit Prediction Scoring System. Supplies the probability
// (0–1) that a CVE will be exploited in the next 30 days, plus its percentile.
//   https://api.first.org/data/v1/epss?cve={id}

import { fetchJson } from "./http"
import type { EpssData } from "./types"

const BASE = "https://api.first.org/data/v1/epss"

export async function fetchEpss(id: string): Promise<EpssData | null> {
  const json = await fetchJson<any>(`${BASE}?cve=${encodeURIComponent(id)}`)
  const row = json.data?.[0]
  if (!row) return null
  const epss = parseFloat(row.epss)
  if (!isFinite(epss)) return null
  const pctl = row.percentile != null ? (parseFloat(row.percentile) * 100).toFixed(0) : ""
  return { epss, pctl }
}
