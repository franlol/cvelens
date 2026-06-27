// OSV.dev — open-source package vulnerability database. Supplies ecosystem
// package names and affected/fixed version ranges. A 404 just means OSV has no
// entry for this CVE (common for non-OSS CVEs) and is treated as "no data".
//   https://api.osv.dev/v1/vulns/{id}

import type { Pkg } from "../data"
import { fetchJson, HttpError } from "./http"

const BASE = "https://api.osv.dev/v1/vulns"

function rangeOf(a: any): { affected: string; fixed: string } {
  let introduced = ""
  let fixed = ""
  let lastAffected = ""
  for (const r of a.ranges || []) {
    for (const e of r.events || []) {
      if (e.introduced && e.introduced !== "0") introduced = e.introduced
      if (e.fixed) fixed = e.fixed
      if (e.last_affected) lastAffected = e.last_affected
    }
  }
  let affected = ""
  if (introduced && fixed) affected = `≥${introduced} <${fixed}`
  else if (fixed) affected = `<${fixed}`
  else if (introduced && lastAffected) affected = `${introduced} – ${lastAffected}`
  else if (a.versions?.length) {
    affected =
      a.versions.length > 3
        ? `${a.versions[0]} … ${a.versions[a.versions.length - 1]}`
        : a.versions.join(", ")
  }
  return { affected: affected || "—", fixed: fixed || "—" }
}

export async function fetchOsv(id: string): Promise<Pkg[]> {
  let json: any
  try {
    json = await fetchJson<any>(`${BASE}/${encodeURIComponent(id)}`)
  } catch (e) {
    if (e instanceof HttpError && e.status === 404) return []
    throw e
  }
  const out: Pkg[] = []
  for (const a of json.affected || []) {
    const pkg = a.package
    if (!pkg?.name) continue
    const name = pkg.ecosystem ? `${pkg.ecosystem}: ${pkg.name}` : pkg.name
    const { affected, fixed } = rangeOf(a)
    out.push({ name, affected, fixed })
    if (out.length >= 6) break
  }
  return out
}
