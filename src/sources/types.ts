// Normalized partials returned by each source fetcher. Each is intentionally a
// subset of the full Cve shape — the store merges them into a MergedCve and
// records which source supplied each field.

import type { Pkg, Ref, Severity } from "../data"

export interface NvdData {
  score: string
  sev: Severity
  vec: string
  cwe: string
  cweName: string
  cpes: string[]
  refs: Ref[]
  pub: string
  mod: string
  desc: string
}

export interface MitreData {
  desc: string
  cna: string
  cnaScore?: string
  cnaSev?: Severity
  cwe: string
  cweName: string
  refs: Ref[]
  pkgs: Pkg[]
}

export interface KevEntry {
  added: string
  due: string
  ransom: string
  title: string
}

export interface EpssData {
  epss: number
  pctl: string
}

export interface SearchHit {
  id: string
  title: string
  sev: Severity
  score: string
}
