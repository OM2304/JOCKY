import React from 'react';

export default function Loading() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8 space-y-8 animate-pulse">
      {/* Header Skeleton */}
      <div className="border-b border-border pb-6">
        <div className="h-4 w-40 bg-muted rounded mb-3" />
        <div className="h-8 w-64 bg-muted rounded mb-2" />
        <div className="h-4 w-96 bg-muted rounded" />
      </div>

      {/* Metrics Header Skeleton */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 rounded-xl border border-border bg-card p-5">
            <div className="flex justify-between">
              <div className="h-3 w-24 bg-muted rounded" />
              <div className="h-6 w-6 bg-muted rounded" />
            </div>
            <div className="mt-3 h-7 w-14 bg-muted rounded" />
            <div className="mt-2 h-3 w-32 bg-muted rounded" />
          </div>
        ))}
      </div>

      {/* Table Skeleton */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="flex justify-between items-center">
          <div className="h-4 w-32 bg-muted rounded" />
          <div className="h-4 w-20 bg-muted rounded" />
        </div>
        <div className="space-y-3 pt-4">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-10 bg-muted/60 rounded-lg" />
          ))}
        </div>
      </div>
    </div>
  );
}
