// Pure view-model derivation. Port of the design mock's `renderVals()`, now fed
// by the live store instead of a static dataset: given the current
// {list, detail, q, src, selId} it computes the filtered list rows and the fully
// resolved detail panel, including per-source "coverage gaps".
//
// Two kinds of gap are distinguished:
//   - structural — the source never provides that field   (COV[src][field] === 0)
//   - data       — the source covers it but hasn't yet     (covered but value empty)

import {
  COV,
  P,
  SEED,
  SRC,
  sevColor,
  type Field,
  type ListItem,
  type MergedCve,
  type SourceKey,
} from "./data"

export interface RowVM {
  id: string
  idPre: string
  idHit: string
  idPost: string
  sevColor: string
  scoreText: string
  title: string
  kevMark: string
  epssText: string
  epssColor: string
  selected: boolean
}

function bar(frac: number, n: number): { filled: string; empty: string } {
  frac = Math.max(0, Math.min(1, frac))
  const f = Math.round(frac * n)
  return { filled: "█".repeat(f), empty: "█".repeat(n - f) }
}

export interface DeriveState {
  list: ListItem[]
  detail: MergedCve | null
  q: string
  src: SourceKey
  selId: string
}

// Synthesize a minimal record from a list row when full detail isn't loaded
// yet, so the detail pane renders gaps rather than crashing.
function placeholder(selId: string, sel: ListItem | undefined): MergedCve {
  return {
    id: selId,
    sev: sel?.sev ?? "NONE",
    score: sel?.score ?? "—",
    title: sel?.title ?? "",
    pub: "",
    mod: "",
    cna: "—",
    vec: "",
    cwe: "",
    cweName: "",
    epss: sel?.epss ?? 0,
    pctl: "",
    kev: sel?.kev ?? false,
    added: "",
    due: "",
    ransom: "",
    cpes: [],
    pkgs: [],
    refs: [],
  }
}

export function derive(state: DeriveState) {
  const src = state.src
  const q = state.q.trim().toLowerCase()
  const srcMeta = SRC[src]
  const cov = COV[src]

  // ---- filter list ----
  // The store already applies the search; here we only apply the KEV-only lens
  // and compute id highlight ranges.
  const list = state.list.filter((c) => !(src === "kev" && !c.kev))
  const ids = list.map((c) => c.id)
  let selId = state.selId
  if (!ids.includes(selId)) selId = ids[0] || state.selId

  const rows: RowVM[] = list.map((c) => {
    const selected = c.id === selId
    const sc = sevColor(c.sev)
    let idPre = c.id
    let idHit = ""
    let idPost = ""
    if (q) {
      const k = c.id.toLowerCase().indexOf(q)
      if (k >= 0) {
        idPre = c.id.slice(0, k)
        idHit = c.id.slice(k, k + q.length)
        idPost = c.id.slice(k + q.length)
      }
    }
    const ep = c.epss
    const epssText = ep > 0 ? (ep * 100).toFixed(0) + "%" : "—"
    const epssColor = ep >= 0.5 ? P.red : ep >= 0.1 ? P.peach : P.faint
    return {
      id: c.id,
      idPre,
      idHit,
      idPost,
      sevColor: sc,
      scoreText: c.score,
      title: c.title,
      kevMark: c.kev ? "●" : "·",
      epssText,
      epssColor,
      selected,
    }
  })

  // ---- detail ----
  const sel = list.find((x) => x.id === selId)
  const c: MergedCve =
    state.detail && state.detail.id === selId
      ? state.detail
      : SEED.find((x) => x.id === selId) || placeholder(selId, sel)
  const sc = sevColor(c.sev)
  const SRCLABEL = srcMeta.label
  const tag = (origin: SourceKey) => (src === "merged" ? SRC[origin].label : SRCLABEL)
  const tagColor = (origin: SourceKey) => (src === "merged" ? SRC[origin].color : srcMeta.color)

  // CVSS section
  const cvssState = cov.cvss
  const cg = bar((parseFloat(c.score) || 0) / 10, 20)
  let cvss: any
  if (c.sev === "NONE") {
    if (src === "nvd") {
      cvss = {
        show: false,
        gap: true,
        gapNote: "⏳ Awaiting NVD analysis — enrichment backlog. CVSS not yet assigned.",
        gapColor: P.peach,
        op: 0.92,
        tag: "NVD",
        tagColor: P.blue,
      }
    } else if (src === "kev") {
      cvss = { show: false, gap: true, gapNote: "Not provided by KEV.", gapColor: P.faint, op: 0.4, tag: "KEV", tagColor: P.red }
    } else if (c.cnaScore) {
      const cn = bar((parseFloat(c.cnaScore) || 0) / 10, 20)
      cvss = {
        show: true,
        score: c.cnaScore,
        sevLabel: c.cnaSev,
        sevColor: sevColor((c.cnaSev as any) || "HIGH"),
        filled: cn.filled,
        empty: cn.empty,
        vector: c.vec,
        op: 1,
        tag: src === "merged" ? "CNA·MITRE" : SRCLABEL,
        tagColor: src === "merged" ? SRC.mitre.color : srcMeta.color,
      }
    } else {
      cvss = {
        show: false,
        gap: true,
        gapNote: "⏳ No CVSS score assigned yet (awaiting analysis).",
        gapColor: P.peach,
        op: 0.92,
        tag: SRCLABEL,
        tagColor: srcMeta.color,
      }
    }
  } else if (cvssState === 0) {
    cvss = { show: false, gap: true, gapNote: "✗ Not provided by " + SRCLABEL + ".", gapColor: P.faint, op: 0.4, tag: SRCLABEL, tagColor: srcMeta.color }
  } else if (cvssState === 0.5) {
    cvss = { show: true, score: c.score, sevLabel: c.sev, sevColor: sc, filled: cg.filled, empty: cg.empty, vector: c.vec, op: 0.96, tag: SRCLABEL + "·if CNA", tagColor: srcMeta.color }
  } else {
    cvss = { show: true, score: c.score, sevLabel: c.sev, sevColor: sc, filled: cg.filled, empty: cg.empty, vector: c.vec, op: 1, tag: tag("nvd"), tagColor: tagColor("nvd") }
  }
  if (cvss.show === undefined) cvss.show = false
  if (cvss.gap === undefined) cvss.gap = false

  // EPSS (FIRST)
  const eg = bar(c.epss, 20)
  let epss: any
  if (cov.epss === 0 || c.epss === 0) {
    epss = {
      show: false,
      gap: true,
      op: 0.4,
      gapColor: P.faint,
      gapNote:
        c.epss === 0
          ? "No EPSS score published yet."
          : "✗ Not provided by " + SRCLABEL + " (EPSS is a FIRST.org feed).",
      tag: src === "merged" ? "FIRST" : SRCLABEL,
      tagColor: src === "merged" ? P.teal : srcMeta.color,
    }
  } else {
    epss = {
      show: true,
      gap: false,
      pct: (c.epss * 100).toFixed(1) + "%",
      pctl: c.pctl,
      filled: eg.filled,
      empty: eg.empty,
      op: 1,
      tag: src === "merged" ? "FIRST" : SRCLABEL,
      tagColor: src === "merged" ? P.teal : srcMeta.color,
    }
  }

  // CWE
  let cwe: any
  if (cov.cwe === 0) {
    cwe = { show: false, gap: true, op: 0.4, gapNote: "✗ Not provided by " + SRCLABEL + ".", gapColor: P.faint, tag: SRCLABEL, tagColor: srcMeta.color }
  } else if (!c.cwe) {
    cwe = { show: false, gap: true, op: 0.92, gapNote: "✗ No CWE mapping assigned yet.", gapColor: P.faint, tag: SRCLABEL, tagColor: srcMeta.color }
  } else if (cov.cwe === 0.5) {
    cwe = { show: true, gap: false, op: 0.96, id: c.cwe, name: c.cweName, tag: SRCLABEL + "·if CNA", tagColor: srcMeta.color }
  } else {
    cwe = { show: true, gap: false, op: 1, id: c.cwe, name: c.cweName, tag: tag("nvd"), tagColor: tagColor("nvd") }
  }

  // Affected
  const showCpe = cov.cpe > 0 && c.cpes.length > 0
  const showPkg = cov.pkg > 0 && c.pkgs.length > 0
  const aff: any = { showCpe, showPkg, cpes: c.cpes, pkgs: c.pkgs, gap: false, gapNote: "", gapColor: P.faint }
  if (!showCpe && !showPkg) {
    aff.gap = true
    aff.gapNote =
      src === "kev"
        ? "KEV lists only vendor/product names, not version ranges."
        : "✗ No affected-product data from " + SRCLABEL + "."
  }

  // KEV
  let kev: any
  if (cov.kev === 0) {
    kev = { op: 0.7, border: P.surface, bg: "#22222b", tag: SRCLABEL, tagColor: srcMeta.color, textColor: P.dim, line: "✗ Exploitation status not provided by " + SRCLABEL + ".", showDates: false }
  } else if (c.kev) {
    kev = { op: 1, border: P.red, bg: "#251c22", tag: src === "merged" ? "CISA KEV" : SRCLABEL, tagColor: P.red, textColor: "#f5b5c4", line: "⚠ Actively exploited in the wild — listed in the CISA Known Exploited Vulnerabilities catalog.", showDates: true, added: c.added, due: c.due, ransom: c.ransom }
  } else {
    kev = { op: 1, border: P.surface, bg: "#1b231d", tag: src === "merged" ? "CISA KEV" : SRCLABEL, tagColor: P.green, textColor: P.sub, line: "✓ Not listed in CISA KEV — no confirmed in-the-wild exploitation on record.", showDates: false }
  }

  // provenance
  let prov: { field: string; src: string; color: string }[]
  let provLabel: string
  if (src === "merged") {
    provLabel = "PROVENANCE"
    if (c.origin && Object.keys(c.origin).length) {
      prov = (Object.keys(c.origin) as Field[]).map((f) => ({
        field: f,
        src: c.origin![f]!.src,
        color: c.origin![f]!.color,
      }))
    } else {
      prov = [
        { field: "desc", src: "MITRE", color: SRC.mitre.color },
        { field: "cvss", src: "NVD", color: SRC.nvd.color },
        { field: "cwe", src: "NVD", color: SRC.nvd.color },
        { field: "cpe", src: "NVD", color: SRC.nvd.color },
        { field: "pkg", src: "OSV", color: SRC.osv.color },
        { field: "kev", src: "CISA", color: P.red },
        { field: "epss", src: "FIRST", color: P.teal },
      ]
    }
  } else {
    provLabel = "SINGLE SOURCE"
    prov = [{ field: "all fields", src: SRCLABEL, color: srcMeta.color }]
  }

  const sevBgMap: Record<string, string> = {
    CRITICAL: "#2a1d24",
    HIGH: "#2a241c",
    MEDIUM: "#2a281c",
    LOW: "#1d2a1d",
    NONE: "#222230",
  }

  return {
    rows,
    ids,
    selId,
    count: list.length,
    total: state.list.length,
    exploited: state.list.filter((x) => x.kev).length,
    srcLabel: SRCLABEL,
    d: {
      id: c.id,
      title: c.title,
      published: c.pub,
      modified: c.mod,
      cna: c.cna,
      sevLabel: c.sev === "NONE" ? "AWAITING" : c.sev,
      sevColor: sc,
      sevBg: sevBgMap[c.sev] || sevBgMap.NONE,
      kevOn: c.kev && cov.kev > 0,
      descOrigin: src === "merged" ? "description · MITRE" : "description · " + SRCLABEL,
      cvss,
      epss,
      cwe,
      aff,
      kev,
      refs: c.refs,
      prov,
      provLabel,
    },
  }
}

export type ViewModel = ReturnType<typeof derive>
