// CVE data, source/coverage tables and the Catppuccin-Mocha palette.
// Ported 1:1 from the cvelens design mock so the TUI shows identical content.

export const P = {
  red: "#f38ba8",
  peach: "#fab387",
  yellow: "#f9e2af",
  green: "#a6e3a1",
  teal: "#94e2d5",
  blue: "#89b4fa",
  mauve: "#cba6f7",
  lav: "#b4befe",
  sub: "#a6adc8",
  dim: "#6c7086",
  faint: "#585b70",
  text: "#cdd6f4",
  surface: "#313244",
  base: "#1e1e2e",
  mantle: "#181825",
  crust: "#11111b",
} as const

export type SourceKey = "merged" | "nvd" | "mitre" | "osv" | "kev"

export const SRC: Record<SourceKey, { label: string; color: string }> = {
  merged: { label: "MERGED", color: P.lav },
  nvd: { label: "NVD", color: P.blue },
  mitre: { label: "MITRE", color: P.mauve },
  osv: { label: "OSV", color: P.green },
  kev: { label: "KEV", color: P.red },
}

// coverage per source: 1 full, .5 partial (only if CNA supplied), 0 none
export const COV: Record<SourceKey, Record<string, number>> = {
  merged: { cvss: 1, epss: 1, cwe: 1, cpe: 1, pkg: 1, kev: 1 },
  nvd: { cvss: 1, epss: 0, cwe: 1, cpe: 1, pkg: 0, kev: 1 },
  mitre: { cvss: 0.5, epss: 0, cwe: 0.5, cpe: 0, pkg: 0, kev: 0 },
  osv: { cvss: 0.5, epss: 0, cwe: 0, cpe: 0, pkg: 1, kev: 0 },
  kev: { cvss: 0, epss: 0, cwe: 0, cpe: 0, pkg: 0, kev: 1 },
}

export const SOURCE_ORDER: SourceKey[] = ["merged", "nvd", "mitre", "osv", "kev"]

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"

export interface Pkg {
  name: string
  affected: string
  fixed: string
}
export interface Ref {
  url: string
  tag: string
}
export interface Cve {
  id: string
  sev: Severity
  score: string
  title: string
  pub: string
  mod: string
  cna: string
  vec: string
  cwe: string
  cweName: string
  epss: number
  pctl: string
  kev: boolean
  added: string
  due: string
  ransom: string
  cnaScore?: string
  cnaSev?: string
  cpes: string[]
  pkgs: Pkg[]
  refs: Ref[]
}

// Fields whose provenance the merged-view lens tracks.
export type Field = "desc" | "cvss" | "cwe" | "cpe" | "pkg" | "kev" | "epss"

// A CVE assembled from several live sources. `origin` records which feed
// actually supplied each field so the merged-view provenance bar reflects
// reality (a field a source didn't return simply won't appear).
export interface MergedCve extends Cve {
  origin?: Partial<Record<Field, { src: string; color: string }>>
}

// Lightweight row summary for the list pane. Seeded from CISA KEV (id/title
// only); sev/score/epss fill in once a CVE's detail has been fetched.
export interface ListItem {
  id: string
  title: string
  sev: Severity
  score: string
  epss: number
  kev: boolean
}

export function sevColor(s: Severity): string {
  return (
    { CRITICAL: P.red, HIGH: P.peach, MEDIUM: P.yellow, LOW: P.green, NONE: P.dim }[s] ||
    P.dim
  )
}

// Offline fallback dataset. Used only when every live source is unreachable so
// the UI always has something to render. Online, real records replace these.
export const SEED: Cve[] = [
  {
    id: "CVE-2021-44228",
    sev: "CRITICAL",
    score: "10.0",
    title: "Apache Log4j2 JNDI lookup remote code execution (Log4Shell).",
    pub: "2021-12-10",
    mod: "2024-04-03",
    cna: "Apache Software Foundation",
    vec: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cwe: "CWE-502",
    cweName: "Deserialization of Untrusted Data",
    epss: 0.944,
    pctl: "100",
    kev: true,
    added: "2021-12-10",
    due: "2021-12-24",
    ransom: "Known",
    cpes: ["apache:log4j 2.0 – 2.14.1"],
    pkgs: [
      {
        name: "org.apache.logging.log4j:log4j-core",
        affected: "≥2.0-beta9 <2.15.0",
        fixed: "2.17.1",
      },
    ],
    refs: [
      { url: "https://logging.apache.org/log4j/2.x/security.html", tag: "vendor" },
      { url: "https://github.com/apache/logging-log4j2", tag: "patch" },
      { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", tag: "analysis" },
    ],
  },
  {
    id: "CVE-2024-3094",
    sev: "CRITICAL",
    score: "10.0",
    title: "XZ Utils (liblzma) supply-chain backdoor enabling SSH auth bypass.",
    pub: "2024-03-29",
    mod: "2024-12-18",
    cna: "Red Hat",
    vec: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cwe: "CWE-506",
    cweName: "Embedded Malicious Code",
    epss: 0.702,
    pctl: "98",
    kev: false,
    added: "",
    due: "",
    ransom: "",
    cpes: ["tukaani:xz 5.6.0 – 5.6.1"],
    pkgs: [{ name: "xz / liblzma (source tarball)", affected: "5.6.0 – 5.6.1", fixed: "5.6.2" }],
    refs: [
      { url: "https://www.openwall.com/lists/oss-security/2024/03/29/4", tag: "disclosure" },
      { url: "https://access.redhat.com/security/cve/CVE-2024-3094", tag: "vendor" },
    ],
  },
  {
    id: "CVE-2014-0160",
    sev: "HIGH",
    score: "7.5",
    title: "OpenSSL TLS heartbeat out-of-bounds read leaks memory (Heartbleed).",
    pub: "2014-04-07",
    mod: "2023-11-07",
    cna: "Red Hat",
    vec: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cwe: "CWE-125",
    cweName: "Out-of-bounds Read",
    epss: 0.944,
    pctl: "100",
    kev: true,
    added: "2022-05-04",
    due: "2022-05-25",
    ransom: "Unknown",
    cpes: ["openssl:openssl 1.0.1 – 1.0.1f"],
    pkgs: [{ name: "openssl", affected: "1.0.1 – 1.0.1f", fixed: "1.0.1g" }],
    refs: [
      { url: "https://www.openssl.org/news/secadv/20140407.txt", tag: "vendor" },
      { url: "https://heartbleed.com", tag: "analysis" },
    ],
  },
  {
    id: "CVE-2017-5638",
    sev: "CRITICAL",
    score: "10.0",
    title: "Apache Struts2 Jakarta Multipart parser RCE (Equifax breach vector).",
    pub: "2017-03-10",
    mod: "2024-08-12",
    cna: "Apache Software Foundation",
    vec: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cwe: "CWE-20",
    cweName: "Improper Input Validation",
    epss: 0.975,
    pctl: "100",
    kev: true,
    added: "2021-11-03",
    due: "2022-05-03",
    ransom: "Known",
    cpes: ["apache:struts 2.3.5 – 2.3.31", "apache:struts 2.5 – 2.5.10"],
    pkgs: [{ name: "org.apache.struts:struts2-core", affected: "<2.3.32", fixed: "2.5.10.1" }],
    refs: [{ url: "https://cwiki.apache.org/confluence/display/WW/S2-045", tag: "vendor" }],
  },
  {
    id: "CVE-2022-22965",
    sev: "CRITICAL",
    score: "9.8",
    title: "Spring Framework data-binding RCE on JDK 9+ (Spring4Shell).",
    pub: "2022-04-01",
    mod: "2023-02-09",
    cna: "VMware",
    vec: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-94",
    cweName: "Improper Control of Code Generation",
    epss: 0.974,
    pctl: "100",
    kev: true,
    added: "2022-04-04",
    due: "2022-04-25",
    ransom: "Known",
    cpes: ["vmware:spring_framework <5.2.20", "vmware:spring_framework 5.3.0 – 5.3.17"],
    pkgs: [
      { name: "org.springframework:spring-beans", affected: "<5.2.20, 5.3.0–5.3.17", fixed: "5.3.18" },
    ],
    refs: [{ url: "https://spring.io/blog/2022/03/31/spring-framework-rce", tag: "vendor" }],
  },
  {
    id: "CVE-2014-6271",
    sev: "CRITICAL",
    score: "9.8",
    title: "GNU Bash environment variable command injection (Shellshock).",
    pub: "2014-09-24",
    mod: "2023-11-07",
    cna: "Red Hat",
    vec: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-78",
    cweName: "OS Command Injection",
    epss: 0.975,
    pctl: "100",
    kev: true,
    added: "2021-11-03",
    due: "2022-05-03",
    ransom: "Unknown",
    cpes: ["gnu:bash <=4.3"],
    pkgs: [{ name: "bash", affected: "≤4.3", fixed: "4.3 patch 25" }],
    refs: [{ url: "https://seclists.org/oss-sec/2014/q3/650", tag: "disclosure" }],
  },
  {
    id: "CVE-2023-44487",
    sev: "HIGH",
    score: "7.5",
    title: "HTTP/2 rapid-reset stream cancellation enables DDoS amplification.",
    pub: "2023-10-10",
    mod: "2024-06-21",
    cna: "CISA ADP",
    vec: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    cwe: "CWE-400",
    cweName: "Uncontrolled Resource Consumption",
    epss: 0.901,
    pctl: "99",
    kev: true,
    added: "2023-10-10",
    due: "2023-10-31",
    ransom: "Unknown",
    cpes: ["ietf:http2 (protocol-level)", "nginx, envoy, netty — many impls"],
    pkgs: [{ name: "golang.org/x/net/http2", affected: "<0.17.0", fixed: "0.17.0" }],
    refs: [
      { url: "https://www.cloudflare.com/blog/http-2-rapid-reset-ddos-attack", tag: "analysis" },
    ],
  },
  {
    id: "CVE-2026-23048",
    sev: "NONE",
    score: "—",
    title:
      "Argo CD API improper authorization allows project escalation (recent — NVD analysis pending).",
    pub: "2026-06-18",
    mod: "2026-06-18",
    cna: "GitHub (Akamai)",
    vec: "CNA: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    cwe: "CWE-285",
    cweName: "Improper Authorization",
    epss: 0,
    pctl: "",
    kev: false,
    added: "",
    due: "",
    ransom: "",
    cnaScore: "8.8",
    cnaSev: "HIGH",
    cpes: [],
    pkgs: [{ name: "argoproj/argo-cd", affected: "<2.13.4", fixed: "2.13.4" }],
    refs: [{ url: "https://github.com/argoproj/argo-cd/security/advisories", tag: "advisory" }],
  },
]
