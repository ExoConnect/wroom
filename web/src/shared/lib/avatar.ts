// Avatar helpers — initials + deterministic gradient per display name.
// Extracted from VideoTile so lobby, tiles, and participant list share one
// implementation. Visuals unchanged; the redesign pass will restyle avatars
// in one place.

/** Up to 2 uppercase initials from a display label ("Ada Lovelace" → "AL").
 *  Parenthetical suffixes ("Ada (you)") never contribute initials. */
export function initialsFor(label: string): string {
  return label
    .replace(/\([^)]*\)/g, " ")
    .split(/\s+/)
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase()
}

/**
 * Deterministic hue (0-359) from a string — stable per name, spreads callers
 * across the wheel without storing per-user state.
 */
export function hueFor(label: string): number {
  let h = 0
  for (let i = 0; i < label.length; i++) {
    h = (h * 31 + label.charCodeAt(i)) % 360
  }
  return h
}
