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

export async function searchNvd(keyword: string, limit = 40): Promise<SearchHit[]> {
  await nvdLimiter.take()
  const url = `${BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`
  const json = await fetchJson<any>(url, { headers: headers() })
  return (json.vulnerabilities || []).map((v: any) => {
    const cve = v.cve
    const d = parseCve(cve)
    return { id: cve.id, title: d.desc, sev: d.sev, score: d.score }
  })
}
