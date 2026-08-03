import { Skeleton } from "@/components/ui/skeleton"

// Deterministic width variation (no Math.random — the static export prerenders
// these, so hydration must produce identical markup).
const LINE_WIDTHS = ["w-3/4", "w-1/2", "w-2/3", "w-5/6", "w-2/5", "w-3/5"]

export function StatCardSkeleton() {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <Skeleton className="h-3 w-20" />
      <Skeleton className="mt-3 h-8 w-12" />
      <Skeleton className="mt-2 h-3 w-24" />
    </div>
  )
}

// Card rows, the shape of the Changes / Drift / Alerts lists.
export function ListRowsSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-3"
        >
          <Skeleton className="h-4 w-4 rounded" />
          <div className="min-w-0 flex-1 space-y-2">
            <Skeleton className={`h-3.5 ${LINE_WIDTHS[i % LINE_WIDTHS.length]}`} />
            <Skeleton className="h-3 w-1/3" />
          </div>
          <Skeleton className="h-5 w-16 rounded-md" />
        </div>
      ))}
    </div>
  )
}

// The Inventory table: filter bar, header row, then data rows.
export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <Skeleton className="h-9 flex-1" />
        <Skeleton className="h-9 w-32" />
        <Skeleton className="h-9 w-32" />
      </div>
      <div className="mt-4 overflow-hidden rounded-lg border border-border">
        <div className="border-b border-border bg-muted/40 px-4 py-2.5">
          <Skeleton className="h-3 w-2/3" />
        </div>
        {Array.from({ length: rows }, (_, i) => (
          <div
            key={i}
            className="flex items-center gap-4 border-b border-border px-4 py-3 last:border-0"
          >
            <Skeleton className="h-4 w-4 rounded" />
            <div className="min-w-0 flex-1 space-y-2">
              <Skeleton className={`h-3.5 ${LINE_WIDTHS[i % LINE_WIDTHS.length]}`} />
              <Skeleton className="h-3 w-1/4" />
            </div>
            <Skeleton className="hidden h-4 w-20 md:block" />
            <Skeleton className="hidden h-5 w-16 rounded-md md:block" />
            <Skeleton className="h-4 w-6" />
          </div>
        ))}
      </div>
    </div>
  )
}

// Compact log lines, the shape of the audit/activity feeds.
export function FeedSkeleton({ lines = 8 }: { lines?: number }) {
  return (
    <div className="flex flex-col gap-4">
      <Skeleton className="h-3 w-1/2" />
      <div className="overflow-hidden rounded-lg border border-border">
        {Array.from({ length: lines }, (_, i) => (
          <div
            key={i}
            className="flex items-baseline gap-3 border-b border-border/60 px-4 py-2 last:border-0"
          >
            <Skeleton className="h-3 w-28 shrink-0" />
            <Skeleton className={`h-3 flex-none ${LINE_WIDTHS[i % LINE_WIDTHS.length]}`} />
            <Skeleton className="ml-auto h-3 w-10 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  )
}

// The Policy tab: intro line plus label + textarea blocks and a save button.
export function PolicySkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-4 w-3/4" />
      {Array.from({ length: 3 }, (_, i) => (
        <div key={i}>
          <Skeleton className="mb-1.5 h-3 w-48" />
          <Skeleton className="h-16 w-full" />
        </div>
      ))}
      <Skeleton className="h-8 w-28" />
    </div>
  )
}

// The Fleet tab: summary line, conformance card, then exposure rows.
export function FleetSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-baseline justify-between gap-2">
        <Skeleton className="h-3 w-64" />
        <Skeleton className="h-3 w-40" />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <Skeleton className="h-3 w-40" />
        <Skeleton className="mt-3 h-4 w-2/3" />
      </div>
      <ListRowsSkeleton rows={4} />
    </div>
  )
}

// Source code lines with a gutter, for the CodeView while /api/source loads.
export function CodeSkeleton({ lines = 18 }: { lines?: number }) {
  return (
    <div className="space-y-2 px-2 py-3">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="flex items-center gap-3 px-2">
          <Skeleton className="h-3 w-8 shrink-0" />
          <Skeleton className={`h-3 ${LINE_WIDTHS[(i * 5 + 1) % LINE_WIDTHS.length]}`} />
        </div>
      ))}
    </div>
  )
}
