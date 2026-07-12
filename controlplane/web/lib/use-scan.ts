"use client"

import { useCallback, useEffect, useState } from "react"
import { artifacts as mockArtifacts, type Artifact } from "@/lib/scan-data"

export interface ScanState {
  artifacts: Artifact[]
  loading: boolean
  live: boolean // true once data came from the Go /api/scan endpoint
  error: string | null
  demo: boolean // true when the backend is serving synthetic demo data (EYEBROW_DEMO=1)
}

// ---------------------------------------------------------------------------
// Request coalescing. Several components call useScan() on the same page
// (e.g. DashboardHeader and Dashboard), and /api/scan runs the full scan
// pipeline server-side — so concurrent callers must share ONE fetch, not
// issue one each. The fetch promise is cached at module level, keyed by a
// shared reload generation: a caller mounting while a fetch for the current
// generation is in flight (or already resolved) reuses it. reload() from any
// caller bumps the generation, drops the cache, and notifies every mounted
// hook, so exactly one fresh fetch happens and all instances observe it.
// ---------------------------------------------------------------------------

type FetchOutcome =
  | { live: true; artifacts: Artifact[]; demo: boolean }
  | { live: false; error: string }

let generation = 0
const generationListeners = new Set<() => void>()
const fetchCache = new Map<number, Promise<FetchOutcome>>()

function fetchScan(gen: number): Promise<FetchOutcome> {
  const cached = fetchCache.get(gen)
  if (cached) return cached
  const p: Promise<FetchOutcome> = fetch("/api/scan", { headers: { Accept: "application/json" } })
    .then((r) => {
      if (!r.ok) throw new Error(`/api/scan → ${r.status}`)
      return r.json()
    })
    .then((data: { artifacts?: Artifact[]; demo?: boolean }) => ({
      live: true as const,
      artifacts: data.artifacts ?? [],
      demo: data.demo ?? false,
    }))
    .catch((err: unknown) => ({ live: false as const, error: String(err) }))
  fetchCache.set(gen, p)
  return p
}

function bumpGeneration() {
  fetchCache.clear() // stale generations are never re-requested
  generation++
  generationListeners.forEach((notify) => notify())
}

/**
 * useScan fetches the live inventory from the eyebrow backend (/api/scan,
 * served by `eyebrow dashboard`). When that endpoint is unreachable — e.g.
 * during `next dev` with no backend running — it falls back to the bundled
 * mock data so the UI is still demoable. The returned `reload` re-fetches,
 * e.g. after a write action mutates the lockfile; every mounted useScan()
 * instance observes the reloaded result (one shared fetch, see above).
 */
export function useScan(): ScanState & { reload: () => void } {
  const [gen, setGen] = useState(generation)
  const [state, setState] = useState<ScanState>({
    artifacts: [],
    loading: true,
    live: false,
    error: null,
    demo: false,
  })

  // Track the shared generation so a reload() from any other caller
  // re-renders this instance with the fresh (coalesced) result too.
  useEffect(() => {
    const notify = () => setGen(generation)
    generationListeners.add(notify)
    return () => {
      generationListeners.delete(notify)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    fetchScan(gen).then((out) => {
      if (cancelled) return
      if (out.live) {
        setState({
          artifacts: out.artifacts,
          loading: false,
          live: true,
          error: null,
          demo: out.demo,
        })
      } else {
        // Backend not present (dev/demo): use mock data, surface why.
        setState({
          artifacts: mockArtifacts,
          loading: false,
          live: false,
          error: out.error,
          demo: false,
        })
      }
    })
    return () => {
      cancelled = true
    }
  }, [gen])

  const reload = useCallback(() => bumpGeneration(), [])
  return { ...state, reload }
}
