// Pad / truncate a string to an exact terminal-cell width. Truncation appends
// an ellipsis. Used to keep list columns aligned without text wrapping.
export function fit(s: string | undefined, n: number, align: "left" | "right" = "left"): string {
  s = s ?? ""
  if (n <= 0) return ""
  if (s.length > n) return s.slice(0, Math.max(0, n - 1)) + "…"
  const pad = " ".repeat(n - s.length)
  return align === "right" ? pad + s : s + pad
}

export function truncate(s: string | undefined, n: number): string {
  s = s ?? ""
  return s.length > n ? s.slice(0, Math.max(0, n - 1)) + "…" : s
}

// Copy text to the system clipboard via the OSC 52 escape sequence. Works over
// SSH and in most modern terminals without any native dependency.
export function osc52Copy(text: string): void {
  try {
    const b64 = Buffer.from(text, "utf8").toString("base64")
    process.stdout.write(`\x1b]52;c;${b64}\x07`)
  } catch {
    /* ignore — clipboard is best-effort */
  }
}
