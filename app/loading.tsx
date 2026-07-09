import { Skeleton } from "@/components/ui/Primitives";

/**
 * Root loading UI (T1.6). Wraps the force-dynamic dashboard (and, as the root
 * boundary, any child route without its own loading.tsx) in a Suspense
 * fallback so slow data reads stream a skeleton instead of flashing blank.
 * Shaped to mirror the dashboard (hero + KPI tiles + list rows), which also
 * generalizes to the other hero-topped pages.
 */
export default function Loading() {
  return (
    <>
      <span className="sr-only" role="status">
        Loading…
      </span>
      <div className="grid gap-6" aria-hidden>
        <div className="glass-strong p-7 md:p-9 grid md:grid-cols-[1fr_auto] gap-6">
          <div className="grid gap-3 content-start">
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-10 w-full max-w-xl" />
            <Skeleton className="h-10 w-2/3" />
            <div className="flex gap-2 mt-2">
              <Skeleton className="h-12 w-44" />
              <Skeleton className="h-12 w-40" />
            </div>
          </div>
          <Skeleton className="h-44 w-full md:w-[300px]" />
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>

        <div className="grid gap-2">
          <Skeleton className="h-6 w-40" />
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      </div>
    </>
  );
}
