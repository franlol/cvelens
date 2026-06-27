import { useEffect, useMemo, useRef, useState } from "react"
import { useKeyboard, useRenderer, useTerminalDimensions } from "@opentui/react"
import type { ScrollBoxRenderable } from "@opentui/core"
import { P, SRC, SOURCE_ORDER, type ListItem, type MergedCve, type SourceKey } from "./data"
import { derive, type RowVM, type ViewModel } from "./derive"
import { loadList, loadDetail, search, summarize } from "./store"
import { fit, truncate, osc52Copy } from "./util"

const EMPTY_BAR = "#45475a"
const SPIN_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".split("")

export function App() {
  const renderer = useRenderer()
  const { width, height } = useTerminalDimensions()

  const [q, setQ] = useState("")
  const [src, setSrc] = useState<SourceKey>("merged")
  const [selId, setSelId] = useState("")
  const [searchFocused, setSearchFocused] = useState(false)
  const [spinner, setSpinner] = useState(SPIN_FRAMES[0])
  const [help, setHelp] = useState(false)
  const [status, setStatus] = useState("")

  // live data state
  const [list, setList] = useState<ListItem[]>([])
  const [detail, setDetail] = useState<MergedCve | null>(null)
  const [listLoading, setListLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [offline, setOffline] = useState(false)

  const vm = useMemo(() => derive({ list, detail, q, src, selId }), [list, detail, q, src, selId])
  const detailRef = useRef<ScrollBoxRenderable>(null)
  const detailReady = detail?.id === vm.selId

  // ---- load / search the list (debounced) ----
  useEffect(() => {
    let cancelled = false
    const run = async () => {
      setListLoading(true)
      const res = await (q.trim() ? search(q) : loadList())
      if (cancelled) return
      setOffline(res.offline)
      setList(res.list)
      setListLoading(false)
    }
    const t = setTimeout(run, q.trim() ? 280 : 0)
    return () => {
      cancelled = true
      clearTimeout(t)
    }
  }, [q])

  // keep selection valid as the list changes
  useEffect(() => {
    if (list.length && !list.some((it) => it.id === selId)) setSelId(list[0].id)
  }, [list, selId])

  // ---- load the selected CVE's detail ----
  useEffect(() => {
    if (!selId) return
    let cancelled = false
    setDetailLoading(true)
    loadDetail(selId)
      .then((d) => {
        if (cancelled) return
        setDetail(d)
        const s = summarize(d)
        setList((prev) => prev.map((it) => (it.id === d.id ? { ...it, ...s } : it)))
      })
      .catch(() => setStatus("detail fetch failed"))
      .finally(() => {
        if (!cancelled) setDetailLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selId])

  // jump the detail pane back to the top whenever the selection changes
  useEffect(() => {
    detailRef.current?.scrollTo(0)
  }, [vm.selId])

  // Latest values for the (stable) keyboard handler closure.
  const vmRef = useRef<ViewModel>(vm)
  vmRef.current = vm
  const focusRef = useRef(searchFocused)
  focusRef.current = searchFocused

  // animated sync spinner
  useEffect(() => {
    let i = 0
    const t = setInterval(() => {
      i = (i + 1) % SPIN_FRAMES.length
      setSpinner(SPIN_FRAMES[i])
    }, 110)
    return () => clearInterval(t)
  }, [])

  // transient status messages (e.g. yank)
  useEffect(() => {
    if (!status) return
    const t = setTimeout(() => setStatus(""), 1600)
    return () => clearTimeout(t)
  }, [status])

  function move(delta: number) {
    const { ids, selId: cur } = vmRef.current
    if (!ids.length) return
    const i = ids.indexOf(cur)
    const ni = Math.max(0, Math.min(ids.length - 1, (i < 0 ? 0 : i) + delta))
    setSelId(ids[ni])
  }

  useKeyboard((key) => {
    const name = key.name
    const ch = key.sequence

    if (focusRef.current) {
      if (name === "escape" || name === "return") setSearchFocused(false)
      return
    }
    if (help) {
      setHelp(false)
      return
    }

    if (name === "down" || ch === "j") move(1)
    else if (name === "up" || ch === "k") move(-1)
    else if (name === "pagedown" || (key.ctrl && name === "d")) detailRef.current?.scrollBy(8)
    else if (name === "pageup" || (key.ctrl && name === "u")) detailRef.current?.scrollBy(-8)
    else if (ch === "/") setSearchFocused(true)
    else if (ch === "s")
      setSrc((p) => SOURCE_ORDER[(SOURCE_ORDER.indexOf(p) + 1) % SOURCE_ORDER.length])
    else if (ch === "f") setSrc((p) => (p === "kev" ? "merged" : "kev"))
    else if (ch === "y") {
      const id = vmRef.current.selId
      osc52Copy(id)
      setStatus(`yanked ${id}`)
    } else if (ch === "?") setHelp(true)
    else if (ch === "q" || name === "escape") renderer.destroy()
  })

  // ---- responsive sizing ----
  const leftW = Math.max(46, Math.min(64, Math.round(width * 0.44)))
  const titleW = Math.max(10, leftW - 34)
  const rightInner = Math.max(20, width - leftW - 7)

  const syncing = listLoading || detailLoading

  return (
    <box flexDirection="column" width="100%" height="100%" backgroundColor={P.base}>
      <WindowBar width={width} spinner={spinner} syncing={syncing} offline={offline} />
      <HeaderTabs src={src} setSrc={setSrc} />
      <box flexDirection="row" flexGrow={1} paddingLeft={1} paddingRight={1}>
        <ListPane vm={vm} width={leftW} titleW={titleW} q={q} setQ={setQ} focused={searchFocused} onSelect={setSelId} loading={listLoading && !list.length} spinner={spinner} />
        <box width={1} />
        <DetailPane vm={vm} inner={rightInner} scrollRef={detailRef} loading={detailLoading && !detailReady} spinner={spinner} />
      </box>
      <Footer status={status} />
      {help ? <HelpOverlay width={width} height={height} /> : null}
    </box>
  )
}

// ───────────────────────── window chrome ─────────────────────────
function WindowBar({
  width,
  spinner,
  syncing,
  offline,
}: {
  width: number
  spinner: string
  syncing: boolean
  offline: boolean
}) {
  const title = `cvelens — ~/security — ${width}×${useTerminalDimensions().height}`
  return (
    <box
      flexDirection="row"
      alignItems="center"
      height={1}
      paddingLeft={2}
      paddingRight={2}
      backgroundColor={P.mantle}
    >
      <text>
        <span fg={P.red}>●</span> <span fg={P.yellow}>●</span> <span fg={P.green}>●</span>
      </text>
      <box flexGrow={1} alignItems="center">
        <text fg={P.dim}>{title}</text>
      </box>
      {offline ? (
        <text>
          <span fg={P.peach}>⚠ offline</span> <span fg={P.dim}>— seed data</span>
        </text>
      ) : syncing ? (
        <text>
          <span fg={P.green}>{spinner}</span> <span fg={P.dim}>syncing…</span>
        </text>
      ) : (
        <text>
          <span fg={P.green}>●</span> <span fg={P.dim}>synced</span>
        </text>
      )}
    </box>
  )
}

// ───────────────────────── brand + source tabs ─────────────────────────
function HeaderTabs({ src, setSrc }: { src: SourceKey; setSrc: (s: SourceKey) => void }) {
  return (
    <box flexDirection="row" alignItems="center" height={1} paddingLeft={2} paddingRight={2} paddingTop={0}>
      <text>
        <strong>
          <span fg={P.text}>cve</span>
          <span fg={P.lav}>lens</span>
        </strong>
        <span fg={P.faint}>  v0.5.0</span>
      </text>
      <box flexGrow={1} />
      <text fg={P.dim}>SOURCE </text>
      {SOURCE_ORDER.map((k) => {
        const active = k === src
        const m = SRC[k]
        return (
          <box
            key={k}
            marginLeft={1}
            paddingLeft={1}
            paddingRight={1}
            backgroundColor={active ? m.color : undefined}
            onMouseDown={() => setSrc(k)}
          >
            <text fg={active ? P.crust : m.color}>
              {active ? "●" : "○"} {m.label}
            </text>
          </box>
        )
      })}
    </box>
  )
}

// ───────────────────────── list pane ─────────────────────────
function ListPane(props: {
  vm: ViewModel
  width: number
  titleW: number
  q: string
  setQ: (v: string) => void
  focused: boolean
  onSelect: (id: string) => void
  loading: boolean
  spinner: string
}) {
  const { vm, width, titleW, q, setQ, focused, onSelect, loading, spinner } = props
  return (
    <box
      width={width}
      flexDirection="column"
      borderStyle="rounded"
      borderColor={P.surface}
      title="VULNERABILITIES"
      titleColor={P.blue}
    >
      {/* search */}
      <box flexDirection="row" alignItems="center" height={1} paddingLeft={1} paddingRight={1}>
        <text fg={P.lav}>› </text>
        <box flexGrow={1}>
          <input
            value={q}
            onInput={setQ}
            focused={focused}
            placeholder="fuzzy search id, product, CWE…"
            backgroundColor={P.base}
            textColor={P.text}
            cursorColor={P.lav}
          />
        </box>
        <text fg={P.faint}> {vm.count} hits</text>
      </box>

      {/* divider separating the search from the list */}
      <box height={1} marginLeft={1} marginRight={1} border={["bottom"]} borderColor="#262638" />

      {/* column header */}
      <box height={1} marginTop={1} paddingLeft={1} paddingRight={1}>
        <text fg={P.faint}>
          {"  "}
          {fit("CVE ID", 14)} {fit("CVSS", 4, "right")}
          {"  "}
          {fit("SUMMARY", titleW)} {"K"} {fit("EPSS", 4, "right")}
        </text>
      </box>

      {/* rows */}
      <scrollbox flexGrow={1} paddingLeft={1} paddingRight={1}>
        {loading ? (
          <text fg={P.dim}>
            {spinner} loading catalog…
          </text>
        ) : vm.rows.length ? (
          vm.rows.map((r) => <Row key={r.id} r={r} titleW={titleW} onSelect={onSelect} />)
        ) : (
          <text fg={P.faint}>no matches</text>
        )}
      </scrollbox>

      {/* status bar */}
      <box flexDirection="row" height={1} paddingLeft={1} paddingRight={1}>
        <text>
          <span fg={P.green}>●</span> <span fg={P.dim}>{vm.total} indexed</span>
          <span fg={P.surface}> │ </span>
          <span fg={P.red}>{vm.exploited} exploited</span>
        </text>
        <box flexGrow={1} />
        <text fg={P.faint}>{vm.srcLabel} backend</text>
      </box>
    </box>
  )
}

function Row({ r, titleW, onSelect }: { r: RowVM; titleW: number; onSelect: (id: string) => void }) {
  const idLen = r.id.length
  const idPad = " ".repeat(Math.max(0, 14 - idLen))
  const idColor = r.selected ? "#ffffff" : P.lav
  return (
    <box
      height={1}
      marginBottom={0}
      backgroundColor={r.selected ? "#2c2c44" : undefined}
      onMouseDown={() => onSelect(r.id)}
    >
      <text>
        <span fg={r.sevColor}>▌ </span>
        {r.idHit ? (
          <>
            <span fg={idColor}>{r.idPre}</span>
            <span fg="#f5e0a3" bg="#3a3a55">
              {r.idHit}
            </span>
            <span fg={idColor}>{r.idPost}</span>
            <span>{idPad}</span>
          </>
        ) : (
          <span fg={idColor}>{fit(r.id, 14)}</span>
        )}
        <span> </span>
        <span fg={r.sevColor}>{fit(r.scoreText, 4, "right")}</span>
        <span>  </span>
        <span fg={P.sub}>{fit(r.title, titleW)}</span>
        <span> </span>
        <span fg={r.kevMark === "●" ? P.red : P.faint}>{r.kevMark}</span>
        <span> </span>
        <span fg={r.epssColor}>{fit(r.epssText, 4, "right")}</span>
      </text>
    </box>
  )
}

// ───────────────────────── detail pane ─────────────────────────
function DetailPane({
  vm,
  inner,
  scrollRef,
  loading,
  spinner,
}: {
  vm: ViewModel
  inner: number
  scrollRef: React.Ref<ScrollBoxRenderable>
  loading: boolean
  spinner: string
}) {
  const d = vm.d
  if (loading) {
    return (
      <box flexGrow={1} flexDirection="column" alignItems="center" justifyContent="center" border borderColor={P.surface} title={d.id} titleColor={P.mauve} borderStyle="rounded">
        <text fg={P.dim}>
          {spinner} fetching {d.id} from sources…
        </text>
      </box>
    )
  }
  return (
    <box flexGrow={1} flexDirection="column" border borderColor={P.surface} title={d.id} titleColor={P.mauve} borderStyle="rounded">
      <scrollbox ref={scrollRef} flexGrow={1} paddingLeft={1} paddingRight={1}>
        {/* header */}
        <box flexDirection="row" alignItems="center" height={1}>
          <text>
            <strong>
              <span fg={P.text}>{d.id}</span>
            </strong>
            {"  "}
            <span fg={d.sevColor} bg={d.sevBg}>
              {" "}
              {d.sevLabel}{" "}
            </span>
            {d.kevOn ? (
              <span fg={P.red} bg="#3a1f28">
                {"  "}⚠ KEV · EXPLOITED{" "}
              </span>
            ) : null}
          </text>
        </box>
        <box paddingTop={1} paddingBottom={1}>
          <text fg={P.sub}>{truncate(d.title, inner * 2)}</text>
        </box>

        {/* meta strip */}
        <Meta d={d} />

        {/* CVSS + EPSS */}
        <box flexDirection="row" paddingTop={1}>
          <CvssCard cvss={d.cvss} />
          <box width={1} />
          <EpssCard epss={d.epss} />
        </box>

        {/* CWE */}
        <Card title="WEAKNESS (CWE)" tag={d.cwe.tag} tagColor={d.cwe.tagColor} op={d.cwe.op}>
          {d.cwe.show ? (
            <text>
              <span fg={P.yellow}>
                <strong>{d.cwe.id}</strong>
              </span>
              {"  "}
              <span fg={P.text}>{d.cwe.name}</span>
            </text>
          ) : (
            <text fg={d.cwe.gapColor}>{d.cwe.gapNote}</text>
          )}
        </Card>

        {/* Affected */}
        <Affected aff={d.aff} inner={inner} />

        {/* KEV */}
        <KevCard kev={d.kev} />

        {/* References */}
        <Card title="REFERENCES">
          {d.refs.map((ref, i) => (
            <text key={i}>
              <span fg={P.faint}>↗ </span>
              <span fg={P.blue}>{truncate(ref.url, inner - 14)}</span>
              <span fg={P.faint}> [{ref.tag}]</span>
            </text>
          ))}
        </Card>
      </scrollbox>

      {/* provenance bar */}
      <box height={1} paddingLeft={1} paddingRight={1} backgroundColor="#191926">
        <text>
          <span fg={P.faint}>{d.provLabel}  </span>
          {d.prov.map((pv, i) => (
            <span key={i}>
              <span fg={pv.color}>■ </span>
              <span fg={P.sub}>{pv.field} </span>
              <span fg={pv.color}>
                <strong>{pv.src}</strong>
              </span>
              {i < d.prov.length - 1 ? "  " : ""}
            </span>
          ))}
        </text>
      </box>
    </box>
  )
}

function Meta({ d }: { d: ViewModel["d"] }) {
  const Item = ({ label, value, color }: { label: string; value: string; color?: string }) => (
    <box flexDirection="column" marginRight={3}>
      <text fg={P.faint}>{label}</text>
      <text fg={color || P.sub}>{value}</text>
    </box>
  )
  return (
    <box flexDirection="row" paddingBottom={1}>
      <Item label="PUBLISHED" value={d.published} />
      <Item label="MODIFIED" value={d.modified} />
      <Item label="ASSIGNER (CNA)" value={d.cna} />
      <box flexGrow={1} />
      <box flexDirection="column">
        <text fg={P.faint}>ORIGIN</text>
        <text fg={P.dim}>{d.descOrigin}</text>
      </box>
    </box>
  )
}

function Card(props: {
  title: string
  tag?: string
  tagColor?: string
  op?: number
  children: React.ReactNode
}) {
  return (
    <box border borderColor={P.surface} paddingLeft={1} paddingRight={1} marginTop={1} opacity={props.op ?? 1}>
      <box flexDirection="row" height={1}>
        <text fg={P.faint}>{props.title}</text>
        <box flexGrow={1} />
        {props.tag ? <text fg={props.tagColor}>{props.tag}</text> : null}
      </box>
      {props.children}
    </box>
  )
}

function CvssCard({ cvss }: { cvss: any }) {
  return (
    <box flexGrow={1} border borderColor={P.surface} paddingLeft={1} paddingRight={1} opacity={cvss.op}>
      <box flexDirection="row" height={1}>
        <text fg={P.faint}>CVSS 3.1 BASE</text>
        <box flexGrow={1} />
        <text fg={cvss.tagColor}>{cvss.tag}</text>
      </box>
      {cvss.show ? (
        <>
          <text>
            <strong>
              <span fg={cvss.sevColor}>{cvss.score}</span>
            </strong>
            {"  "}
            <span fg={cvss.sevColor}>{cvss.sevLabel}</span>
          </text>
          <text>
            <span fg={cvss.sevColor}>{cvss.filled}</span>
            <span fg={EMPTY_BAR}>{cvss.empty}</span>
          </text>
          <text fg={P.dim}>{truncate(cvss.vector, 40)}</text>
        </>
      ) : (
        <text fg={cvss.gapColor}>{cvss.gapNote}</text>
      )}
    </box>
  )
}

function EpssCard({ epss }: { epss: any }) {
  return (
    <box flexGrow={1} border borderColor={P.surface} paddingLeft={1} paddingRight={1} opacity={epss.op}>
      <box flexDirection="row" height={1}>
        <text fg={P.faint}>EPSS EXPLOIT PROB.</text>
        <box flexGrow={1} />
        <text fg={epss.tagColor}>{epss.tag}</text>
      </box>
      {epss.show ? (
        <>
          <text>
            <strong>
              <span fg={P.teal}>{epss.pct}</span>
            </strong>
            {"  "}
            <span fg={P.dim}>{epss.pctl} pctl</span>
          </text>
          <text>
            <span fg={P.teal}>{epss.filled}</span>
            <span fg={EMPTY_BAR}>{epss.empty}</span>
          </text>
        </>
      ) : (
        <text fg={epss.gapColor}>{epss.gapNote}</text>
      )}
    </box>
  )
}

function Affected({ aff, inner }: { aff: any; inner: number }) {
  return (
    <Card title="AFFECTED">
      {aff.gap ? (
        <text fg={aff.gapColor}>{aff.gapNote}</text>
      ) : (
        <>
          {aff.showCpe ? (
            <box flexDirection="column">
              <text>
                <span fg={P.dim}>CPE PLATFORMS </span>
                <span fg={P.blue}>[NVD]</span>
              </text>
              {aff.cpes.map((c: string, i: number) => (
                <text key={i} fg={P.sub} bg="#262638">
                  {" "}
                  {truncate(c, inner - 4)}{" "}
                </text>
              ))}
            </box>
          ) : null}
          {aff.showPkg ? (
            <box flexDirection="column" marginTop={aff.showCpe ? 1 : 0}>
              <text>
                <span fg={P.dim}>PACKAGE VERSIONS </span>
                <span fg={P.green}>[OSV]</span>
              </text>
              {aff.pkgs.map((p: any, i: number) => (
                <text key={i}>
                  <span fg={P.text}>{fit(p.name, Math.min(34, inner - 24))}</span>
                  <span fg={P.red}> {p.affected}</span>
                  <span fg={P.faint}> → </span>
                  <span fg={P.green}>{p.fixed}</span>
                </text>
              ))}
            </box>
          ) : null}
        </>
      )}
    </Card>
  )
}

function KevCard({ kev }: { kev: any }) {
  return (
    <box border borderColor={kev.border} backgroundColor={kev.bg} paddingLeft={1} paddingRight={1} marginTop={1} opacity={kev.op}>
      <box flexDirection="row" height={1}>
        <text fg={P.faint}>EXPLOITATION — CISA KEV</text>
        <box flexGrow={1} />
        <text fg={kev.tagColor}>{kev.tag}</text>
      </box>
      <text fg={kev.textColor}>{kev.line}</text>
      {kev.showDates ? (
        <text>
          <span fg={P.faint}>Added </span>
          <span fg={P.red}>{kev.added}</span>
          <span fg={P.faint}>   Due </span>
          <span fg={P.peach}>{kev.due}</span>
          <span fg={P.faint}>   Ransomware </span>
          <span fg={P.sub}>{kev.ransom}</span>
        </text>
      ) : null}
    </box>
  )
}

// ───────────────────────── footer ─────────────────────────
const HINTS: [string, string][] = [
  ["↑↓", "move"],
  ["⏎", "open"],
  ["/", "search"],
  ["s", "cycle source"],
  ["f", "KEV only"],
  ["y", "yank id"],
  ["?", "help"],
  ["q", "quit"],
]

function Footer({ status }: { status: string }) {
  return (
    <box flexDirection="row" alignItems="center" height={1} paddingLeft={2} paddingRight={2} backgroundColor={P.mantle}>
      <text>
        {HINTS.map(([k, label], i) => (
          <span key={i}>
            <span fg={P.text} bg={P.surface}>
              {" "}
              {k}{" "}
            </span>
            <span fg={P.dim}> {label}</span>
            {i < HINTS.length - 1 ? "   " : ""}
          </span>
        ))}
      </text>
      <box flexGrow={1} alignItems="center">
        {status ? <text fg={P.green}>{status}</text> : null}
      </box>
      <text fg={P.faint}>★ star on github</text>
    </box>
  )
}

// ───────────────────────── help overlay ─────────────────────────
function HelpOverlay({ width, height }: { width: number; height: number }) {
  return (
    <box
      position="absolute"
      left={Math.max(0, Math.floor(width / 2) - 24)}
      top={Math.max(0, Math.floor(height / 2) - 7)}
      width={48}
      border
      borderColor={P.mauve}
      backgroundColor={P.mantle}
      title="HELP — cvelens"
      titleColor={P.mauve}
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
      flexDirection="column"
    >
      {HINTS.map(([k, label], i) => (
        <text key={i}>
          <span fg={P.lav}>
            <strong>{fit(k, 4)}</strong>
          </span>
          <span fg={P.sub}>{label}</span>
        </text>
      ))}
      <text> </text>
      <text fg={P.dim}>Sources cycle: merged → nvd → mitre → osv → kev.</text>
      <text fg={P.dim}>Each source shows only the fields it actually covers.</text>
      <text> </text>
      <text fg={P.faint}>press any key to close</text>
    </box>
  )
}
