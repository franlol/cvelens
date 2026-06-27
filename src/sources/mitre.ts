// CVE.org (MITRE) CVE Services API — the authoritative CVE record. Supplies the
// canonical description, the assigning CNA, any CNA-provided CVSS/CWE, and a
// lightweight affected-products list.
//   https://cveawg.mitre.org/api/cve/{id}

import type { Pkg, Ref, Severity } from "../data"
import { fetchJson } from "./http"
import type { MitreData } from "./types"

const BASE = "https://cveawg.mitre.org/api/cve"

function engEn(arr: { lang?: string; value: string }[] | undefined): string {
  if (!arr?.length) return ""
  return (arr.find((d) => d.lang === "en") || arr[0]).value
}

function sevFrom(s: string | undefined): Severity | undefined {
  const u = (s || "").toUpperCase()
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(u) ? (u as Severity) : undefined
}

// CNA metrics can be cvssV3_1 / cvssV3_0 / cvssV4_0 under metrics[].
function cnaCvss(metrics: any[] | undefined): { score?: string; sev?: Severity; vec?: string } {
  for (const m of metrics || []) {
    const c = m.cvssV3_1 || m.cvssV3_0 || m.cvssV4_0
    if (c?.baseScore != null) {
      return {
        score: Number(c.baseScore).toFixed(1),
        sev: sevFrom(c.baseSeverity),
        vec: c.vectorString,
      }
    }
  }
  return {}
}

function cnaCwe(problemTypes: any[] | undefined): { cwe: string; cweName: string } {
  for (const pt of problemTypes || []) {
    for (const d of pt.descriptions || []) {
      if (d.cweId) return { cwe: d.cweId, cweName: d.description || "" }
      if (typeof d.description === "string" && d.description.startsWith("CWE-")) {
        return { cwe: d.description.split(" ")[0], cweName: "" }
      }
    }
  }
  return { cwe: "", cweName: "" }
}

function pkgsFrom(affected: any[] | undefined): Pkg[] {
  const out: Pkg[] = []
  for (const a of affected || []) {
    const name = [a.vendor, a.product].filter((x) => x && x !== "n/a").join(" / ") || a.product
    if (!name) continue
    for (const v of a.versions || []) {
      if (v.status && v.status !== "affected") continue
      const affectedRange = v.lessThan
        ? `${v.version || "0"} – <${v.lessThan}`
        : v.lessThanOrEqual
          ? `${v.version || "0"} – ≤${v.lessThanOrEqual}`
          : v.version || ""
      out.push({ name, affected: affectedRange, fixed: v.fixed || "—" })
      if (out.length >= 6) return out
    }
    if (!a.versions?.length) out.push({ name, affected: "—", fixed: "—" })
  }
  return out
}

export async function fetchMitre(id: string): Promise<MitreData | null> {
  const json = await fetchJson<any>(`${BASE}/${encodeURIComponent(id)}`)
  const cna = json.containers?.cna
  if (!cna) return null
  const cvss = cnaCvss(cna.metrics)
  const cwe = cnaCwe(cna.problemTypes)
  const refs: Ref[] = (cna.references || []).slice(0, 8).map((r: any) => ({
    url: r.url,
    tag: (r.tags && r.tags[0] ? String(r.tags[0]) : "ref").toLowerCase(),
  }))
  return {
    desc: engEn(cna.descriptions),
    cna: json.cveMetadata?.assignerShortName || "—",
    cnaScore: cvss.score,
    cnaSev: cvss.sev,
    cwe: cwe.cwe,
    cweName: cwe.cweName,
    refs,
    pkgs: pkgsFrom(cna.affected),
  }
}
