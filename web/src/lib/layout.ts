// Tile-grid packing: given each tile's real video aspect, find the column
// count that maximizes total tile area inside a w×h box.
//
// Each row gets a single uniform cell height; a tile's width is
// `cellH × aspect`, so rows may freely mix landscape and portrait sources.
// Row heights are first width-limited (row must fit horizontally), then all
// rows are uniformly scaled to fit the box height. Tiles never shrink below
// MIN_TILE_W wide — column counts that violate the floor are disqualified;
// when nothing qualifies the best layout is clamped up and the grid is
// allowed to scroll (CallScreen renders `overflow-y-auto`).

/** Per-tile box produced by packTiles, in input order. */
export interface PackedTile {
  w: number
  h: number
}

export interface PackedGrid {
  tiles: PackedTile[]
  /** True when the packed rows exceed the box — grid should scroll. */
  overflow: boolean
}

/** Hard floor for a tile's rendered width (px). */
export const MIN_TILE_W = 120

/** Fallback aspect when a stream hasn't reported dimensions yet (16:9). */
export const DEFAULT_ASPECT = 16 / 9

// Results are memoized — the packer runs on every resize and every aspect
// report. The map is small (keyed by inputs) and FIFO-bounded.
const MEMO_LIMIT = 64
const memo = new Map<string, PackedGrid>()

const sane = (a: number): number => (a > 0 && Number.isFinite(a) ? a : DEFAULT_ASPECT)

export function packTiles(
  aspects: readonly number[],
  w: number,
  h: number,
  gap = 12,
): PackedGrid {
  const n = aspects.length
  if (n === 0 || w <= 0 || h <= 0) return { tiles: [], overflow: false }

  const key =
    `${n}:${w.toFixed(1)}:${h.toFixed(1)}:${gap}:` +
    aspects.map((a) => sane(a).toFixed(4)).join(",")
  const hit = memo.get(key)
  if (hit) return hit

  interface Candidate {
    /** Total tile area after height-scaling — the quantity being maximized. */
    area: number
    /** Narrowest tile width after scaling (min-width floor check). */
    minW: number
    cols: number
    scale: number
    /** Per-row unscaled cell height. */
    cellH: number[]
  }
  let best: Candidate | null = null
  let bestFit: Candidate | null = null // best candidate honoring MIN_TILE_W

  for (let cols = 1; cols <= n; cols++) {
    const rows = Math.ceil(n / cols)
    const cellH: number[] = []
    let sumCellH = 0
    let areaSum = 0 // Σ_r cellH_r² · Σaspects_r (pre-scale)
    for (let r = 0; r < rows; r++) {
      const start = r * cols
      const k = Math.min(cols, n - start)
      let s = 0
      for (let i = start; i < start + k; i++) s += sane(aspects[i])
      // Widest row fits: cellH · Σaspects + gaps ≤ w.
      const ch = Math.max(0, (w - gap * (k - 1)) / s)
      cellH.push(ch)
      sumCellH += ch
      areaSum += ch * ch * s
    }
    // Uniform shrink so rows + gaps fit the box height exactly.
    const availH = h - gap * (rows - 1)
    const scale = Math.min(1, availH > 0 ? availH / sumCellH : 0)
    let minW = Infinity
    for (let r = 0; r < rows; r++) {
      const hh = cellH[r] * scale
      const start = r * cols
      const k = Math.min(cols, n - start)
      for (let i = start; i < start + k; i++) {
        minW = Math.min(minW, hh * sane(aspects[i]))
      }
    }
    const cand: Candidate = { area: scale * scale * areaSum, minW, cols, scale, cellH }
    if (!best || cand.area > best.area) best = cand
    if (minW >= MIN_TILE_W && (!bestFit || cand.area > bestFit.area)) bestFit = cand
  }

  const chosen = bestFit ?? best!
  const tiles: PackedTile[] = new Array(n)
  let overflow = false
  let totalH = gap * (chosen.cellH.length - 1)
  let idx = 0
  for (let r = 0; r < chosen.cellH.length; r++) {
    const hh = chosen.cellH[r] * chosen.scale
    const k = Math.min(chosen.cols, n - r * chosen.cols)
    let rowW = gap * (k - 1)
    let rowH = 0
    for (let i = 0; i < k; i++, idx++) {
      const a = sane(aspects[idx])
      let tw = hh * a
      if (tw < MIN_TILE_W) tw = Math.min(MIN_TILE_W, w) // floor → may scroll
      tw = Math.max(1, Math.floor(tw))
      const th = Math.max(1, Math.floor(tw / a))
      tiles[idx] = { w: tw, h: th }
      rowW += tw
      rowH = Math.max(rowH, th)
    }
    if (rowW > w + 0.5) overflow = true
    totalH += rowH
  }
  if (totalH > h + 0.5) overflow = true

  const grid: PackedGrid = { tiles, overflow }
  if (memo.size >= MEMO_LIMIT) memo.delete(memo.keys().next().value!)
  memo.set(key, grid)
  return grid
}
