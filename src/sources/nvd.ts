// NVD 2.0 API. Supplies the analyzed CVSS v3.1 base metrics, CWE, CPE platform
// list, references and dates. Also powers live keyword search for the list pane.
//   https://services.nvd.nist.gov/rest/json/cves/2.0

import type { Ref, Severity } from "../data"
import { fetchJson, nvdLimiter, NVD_API_KEY } from "./http"
import type { NvdData, SearchHit } from "./types"

const BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVD doesn't return CWE names, only ids. Small lookup for common weaknesses;
// anything else falls back to MITRE's name (merged) or an empty string.
const CWE_NAMES: Record<string, string> = {
  "CWE-20": "Improper Input Validation",
  "CWE-78": "OS Command Injection",
  "CWE-79": "Cross-site Scripting",
  "CWE-89": "SQL Injection",
  "CWE-94": "Improper Control of Code Generation",
  "CWE-125": "Out-of-bounds Read",
  "CWE-200": "Exposure of Sensitive Information",
  "CWE-269": "Improper Privilege Management",
  "CWE-285": "Improper Authorization",
  "CWE-287": "Improper Authentication",
  "CWE-352": "Cross-Site Request Forgery",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted Upload of File with Dangerous Type",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-506": "Embedded Malicious Code",
  "CWE-787": "Out-of-bounds Write",
  "CWE-862": "Missing Authorization",
  "CWE-918": "Server-Side Request Forgery",
}

function headers(): Record<string, string> {
  return NVD_API_KEY ? { apiKey: NVD_API_KEY } : {}
}

function sevFrom(s: string | undefined): Severity {
  const u = (s || "").toUpperCase()
  return (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(u) ? u : "NONE") as Severity
}

function engEn(arr: { lang?: string; value: string }[] | undefined): string {
  if (!arr?.length) return ""
  return (arr.find((d) => d.lang === "en") || arr[0]).value
}

function firstCwe(weaknesses: any[] | undefined): string {
  for (const w of weaknesses || []) {
    for (const d of w.description || []) {
      if (typeof d.value === "string" && d.value.startsWith("CWE-")) return d.value
    }
  }
  return ""
}

// Turn the cpeMatch entries into readable "vendor:product version-range" lines.
function cpesFrom(configurations: any[] | undefined): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const cfg of configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        const parts = (m.criteria || "").split(":")
        const vendor = parts[3]
        const product = parts[4]
        if (!vendor || !product) continue
        let label = `${vendor}:${product}`
        const lo = m.versionStartIncluding || m.versionStartExcluding
        const hi = m.versionEndExcluding || m.versionEndIncluding
        if (lo || hi) label += ` ${lo || ""} – ${hi || ""}`.replace(/\s+/g, " ").trimEnd()
        if (!seen.has(label)) {
          seen.add(label)
          out.push(label)
        }
        if (out.length >= 6) return out
      }
    }
  }
  return out
}

function refsFrom(references: any[] | undefined): Ref[] {
  return (references || []).slice(0, 8).map((r) => ({
    url: r.url,
    tag: (r.tags && r.tags[0] ? String(r.tags[0]) : "ref").toLowerCase(),
  }))
}

function parseCve(cve: any): NvdData {
  const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0]
  const d = metric?.cvssData
  const cwe = firstCwe(cve.weaknesses)
  return {
    score: d ? Number(d.baseScore).toFixed(1) : "—",
    sev: sevFrom(d?.baseSeverity),
    vec: d?.vectorString || "",
    cwe,
    cweName: CWE_NAMES[cwe] || "",
    cpes: cpesFrom(cve.configurations),
    refs: refsFrom(cve.references),
    pub: (cve.published || "").slice(0, 10),
    mod: (cve.lastModified || "").slice(0, 10),
    desc: engEn(cve.descriptions),
  }
}

export async function fetchNvd(id: string): Promise<NvdData | null> {
  await nvdLimiter.take()
  const json = await fetchJson<any>(`${BASE}?cveId=${encodeURIComponent(id)}`, {
    headers: headers(),
  })
  const cve = json.vulnerabilities?.[0]?.cve
  return cve ? parseCve(cve) : null
}

// The search box is a single field, so we infer what the user meant from the
// shape of the query and route it to the matching NVD parameter. Anything we
// can't pin down — free text, or a bare number with no year — falls through to
// keyword search, which scans the description text only.
type QueryIntent =
  | { kind: "cve"; id: string } // CVE-2025-55177 | 2025-55177 → cveIds
  | { kind: "cwe"; id: string } // CWE-79                       → cweId
  | { kind: "cpe"; name: string } // cpe:2.3:...                 → cpeName
  | { kind: "keyword"; text: string } // everything else        → keywordSearch

function classify(raw: string): QueryIntent {
  const q = raw.trim()
  const cve = q.match(/^(?:cve-)?((?:19|20)\d{2})-(\d{4,})$/i)
  if (cve) return { kind: "cve", id: `CVE-${cve[1]}-${cve[2]}` }
  const cwe = q.match(/^cwe-(\d+)$/i)
  if (cwe) return { kind: "cwe", id: `CWE-${cwe[1]}` }
  if (/^cpe:2\.3:/i.test(q)) return { kind: "cpe", name: q }
  return { kind: "keyword", text: q }
}

function toHits(json: any): SearchHit[] {
  return (json.vulnerabilities || []).map((v: any) => {
    const cve = v.cve
    const d = parseCve(cve)
    return { id: cve.id, title: d.desc, sev: d.sev, score: d.score }
  })
}

export async function searchNvd(raw: string, limit = 40): Promise<SearchHit[]> {
  const intent = classify(raw)
  const p = new URLSearchParams()
  switch (intent.kind) {
    case "cve":
      // An exact id lookup returns 0 or 1 result; no paging needed.
      p.set("cveIds", intent.id)
      break
    case "cwe":
      p.set("cweId", intent.id)
      break
    case "cpe":
      p.set("cpeName", intent.name)
      break
    case "keyword":
      p.set("keywordSearch", intent.text)
      break
  }
  if (intent.kind !== "cve") p.set("resultsPerPage", String(limit))

  await nvdLimiter.take()
  const json = await fetchJson<any>(`${BASE}?${p}`, { headers: headers() })
  return toHits(json)
}
