// Tiny TTL'd disk cache under ~/.cache/cvelens. Each entry is a JSON file
// `{ fetchedAt, ttl, data }`; reads past their TTL are treated as misses.
// Best-effort: any IO error degrades to "no cache" rather than throwing.

import { homedir } from "os"
import { join } from "path"

const DIR = join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "cvelens")

interface Entry<T> {
  fetchedAt: number
  ttl: number
  data: T
}

// Map an arbitrary key to a safe, collision-resistant filename.
function pathFor(key: string): string {
  const safe = key.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80)
  const hash = Bun.hash(key).toString(36)
  return join(DIR, `${safe}-${hash}.json`)
}

export async function getCached<T>(key: string, ttlMs: number): Promise<T | null> {
  try {
    const file = Bun.file(pathFor(key))
    if (!(await file.exists())) return null
    const entry = (await file.json()) as Entry<T>
    if (Date.now() - entry.fetchedAt > ttlMs) return null
    return entry.data
  } catch {
    return null
  }
}

export async function putCached<T>(key: string, data: T, ttlMs: number): Promise<void> {
  try {
    const entry: Entry<T> = { fetchedAt: Date.now(), ttl: ttlMs, data }
    await Bun.write(pathFor(key), JSON.stringify(entry))
  } catch {
    /* ignore — cache is best-effort */
  }
}

export const CACHE_DIR = DIR
