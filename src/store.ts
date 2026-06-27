// Orchestration layer between the UI and the live sources. Responsibilities:
//   - loadList():  seed the list pane from the CISA KEV catalog
//   - search(q):   live NVD keyword search, falling back to a local KEV filter
//   - loadDetail(id): fan out to NVD/MITRE/OSV/EPSS in parallel, merge with KEV
//                     into a single MergedCve recording per-field provenance
// Everything is best-effort: failed sources are skipped, and if the network is
// entirely unavailable the bundled SEED keeps the UI alive.

import { getCached, putCached } from "./cache"
import {
  P,
  SEED,
  SRC,
  type Field,
  type ListItem,
  type MergedCve,
  type Pkg,
  type Ref,
  type Severity,
} from "./data"
import { fetchKevCatalog, searchKev, type KevCatalog } from "./sources/kev"
import { fetchNvd, searchNvd } from "./sources/nvd"
import { fetchMitre } from "./sources/mitre"
import { fetchOsv } from "./sources/osv"
import { fetchEpss } from "./sources/epss"
import type { KevEntry } from "./sources/types"

const DETAIL_TTL = 24 * 60 * 60 * 1000 // 24h

export interface ListResult {
  list: ListItem[]
  offline: boolean
}

function seedAsList(): ListItem[] {
  return SEED.map((c) => ({
    id: c.id,
    title: c.title,
    sev: c.sev,
    score: c.score,
    epss: c.epss,
    kev: c.kev,
  }))
}

// ---- list ----

export async function loadList(): Promise<ListResult> {
  try {
    const cat = await fetchKevCatalog()
    const list: ListItem[] = cat.order.map((id) => {
      const e = cat.map.get(id)!
      return { id, title: e.title, sev: "NONE" as Severity, score: "—", epss: 0, kev: true }
    })
    return { list, offline: false }
  } catch {
    return { list: seedAsList(), offline: true }
  }
}

// ---- search ----

export async function search(q: string): Promise<ListResult> {
  const query = q.trim()
  if (!query) return loadList()

  let cat: KevCatalog | null = null
  try {
    cat = await fetchKevCatalog()
  } catch {
    /* KEV optional for search */
  }
  const kevMap = cat?.map

  try {
    const hits = await searchNvd(query)
    const list: ListItem[] = hits.map((h) => ({
      id: h.id,
      title: h.title,
      sev: h.sev,
      score: h.score,
      epss: 0,
      kev: kevMap?.has(h.id) ?? false,
    }))
    return { list, offline: false }
  } catch {
    // NVD unreachable — fall back to a local filter over the KEV seed.
    if (cat) {
      const list = searchKev(cat, query).map((h) => ({
        id: h.id,
        title: h.title,
        sev: h.sev,
        score: h.score,
        epss: 0,
        kev: true,
      }))
      return { list, offline: false }
    }
    // Last resort: filter the bundled seed.
    const needle = query.toLowerCase()
    return {
      list: seedAsList().filter(
        (c) => c.id.toLowerCase().includes(needle) || c.title.toLowerCase().includes(needle),
      ),
      offline: true,
    }
  }
}

// ---- detail ----

const NVD_C = SRC.nvd.color
const MITRE_C = SRC.mitre.color
const OSV_C = SRC.osv.color

function merge(
  id: string,
  nvd: Awaited<ReturnType<typeof fetchNvd>>,
  mitre: Awaited<ReturnType<typeof fetchMitre>>,
  osv: Pkg[],
  epss: Awaited<ReturnType<typeof fetchEpss>>,
  kev: KevEntry | undefined,
): MergedCve {
  const origin: NonNullable<MergedCve["origin"]> = {}
  const set = (f: Field, src: string, color: string) => (origin[f] = { src, color })

  const desc = mitre?.desc || nvd?.desc || ""
  if (desc) set("desc", mitre?.desc ? "MITRE" : "NVD", mitre?.desc ? MITRE_C : NVD_C)

  // NVD is authoritative for the base score; the CNA (via MITRE) is the fallback.
  const haveNvdScore = !!nvd && nvd.sev !== "NONE" && nvd.score !== "—"
  if (haveNvdScore) set("cvss", "NVD", NVD_C)
  else if (mitre?.cnaScore) set("cvss", "MITRE·CNA", MITRE_C)

  const cwe = nvd?.cwe || mitre?.cwe || ""
  const cweName = nvd?.cweName || mitre?.cweName || ""
  if (cwe) set("cwe", nvd?.cwe ? "NVD" : "MITRE", nvd?.cwe ? NVD_C : MITRE_C)

  const cpes = nvd?.cpes || []
  if (cpes.length) set("cpe", "NVD", NVD_C)

  const pkgs = osv.length ? osv : mitre?.pkgs || []
  if (pkgs.length) set("pkg", osv.length ? "OSV" : "MITRE", osv.length ? OSV_C : MITRE_C)

  if (kev) set("kev", "CISA", P.red)
  if (epss) set("epss", "FIRST", P.teal)

  const refs: Ref[] = []
  const seen = new Set<string>()
  for (const r of [...(nvd?.refs || []), ...(mitre?.refs || [])]) {
    if (r.url && !seen.has(r.url)) {
      seen.add(r.url)
      refs.push(r)
    }
    if (refs.length >= 8) break
  }

  return {
    id,
    sev: (haveNvdScore ? nvd!.sev : "NONE") as Severity,
    score: haveNvdScore ? nvd!.score : "—",
    title: desc,
    pub: nvd?.pub || "",
    mod: nvd?.mod || "",
    cna: mitre?.cna || "—",
    vec: (haveNvdScore ? nvd!.vec : mitre?.cnaScore ? "" : "") || nvd?.vec || "",
    cwe,
    cweName,
    epss: epss?.epss ?? 0,
    pctl: epss?.pctl ?? "",
    kev: !!kev,
    added: kev?.added || "",
    due: kev?.due || "",
    ransom: kev?.ransom || "",
    cnaScore: mitre?.cnaScore,
    cnaSev: mitre?.cnaSev,
    cpes,
    pkgs,
    refs,
    origin,
  }
}

export async function loadDetail(id: string): Promise<MergedCve> {
  const cached = await getCached<MergedCve>(`cve-${id}`, DETAIL_TTL)
  if (cached) return cached

  let kev: KevEntry | undefined
  try {
    kev = (await fetchKevCatalog()).map.get(id)
  } catch {
    /* ignore */
  }

  const [nvdR, mitreR, osvR, epssR] = await Promise.allSettled([
    fetchNvd(id),
    fetchMitre(id),
    fetchOsv(id),
    fetchEpss(id),
  ])

  const nvd = nvdR.status === "fulfilled" ? nvdR.value : null
  const mitre = mitreR.status === "fulfilled" ? mitreR.value : null
  const osv = osvR.status === "fulfilled" ? osvR.value : []
  const epss = epssR.status === "fulfilled" ? epssR.value : null

  // Everything failed and not in KEV — fall back to the bundled seed if we can.
  if (!nvd && !mitre && !osv.length && !epss && !kev) {
    const seed = SEED.find((c) => c.id === id)
    if (seed) return seed
  }

  const merged = merge(id, nvd, mitre, osv, epss, kev)
  // Only persist records that actually carry network-sourced data.
  if (nvd || mitre || osv.length || epss) await putCached(`cve-${id}`, merged, DETAIL_TTL)
  return merged
}

// Roll a freshly loaded detail back into its list-row summary so the row fills
// in (severity colour, score, EPSS) once a CVE has been visited.
export function summarize(d: MergedCve): Partial<ListItem> {
  const sev = d.sev !== "NONE" ? d.sev : ((d.cnaSev as Severity) ?? "NONE")
  const score = d.score !== "—" ? d.score : (d.cnaScore ?? "—")
  return { sev, score, epss: d.epss, kev: d.kev, title: d.title || undefined }
}
