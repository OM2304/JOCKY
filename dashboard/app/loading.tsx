import React from 'react';
import { Radar } from 'lucide-react';

export default function Loading() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8 space-y-8 animate-pulse">
      {/* Header Skeleton */}
      <div className="border-b border-[#1e2638] pb-6">
        <div className="h-4 w-48 bg-[#18202e] rounded mb-3" />
        <div className="h-8 w-72 bg-[#1f293d] rounded mb-2" />
        <div className="h-4 w-96 bg-[#18202e] rounded" />
      </div>

      {/* Metrics Header Skeleton */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-32 rounded-xl border border-[#1e2638] bg-[#0c0e14] p-5">
            <div className="flex justify-between">
              <div className="h-3 w-28 bg-[#18202e] rounded" />
              <div className="h-7 w-7 bg-[#18202e] rounded-lg" />
            </div>
            <div className="mt-4 h-8 w-16 bg-[#1f293d] rounded" />
            <div className="mt-3 h-3 w-36 bg-[#18202e] rounded" />
          </div>
        ))}
      </div>

      {/* Table Skeleton */}
      <div className="rounded-2xl border border-[#1e2638] bg-[#0c0e14] p-6 space-y-4">
        <div className="flex justify-between items-center">
          <div className="h-4 w-36 bg-[#18202e] rounded" />
          <div className="h-4 w-24 bg-[#18202e] rounded" />
        </div>
        <div className="space-y-3 pt-4">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-12 bg-[#121622] rounded-xl border border-[#1a2232]" />
          ))}
        </div>
      </div>
    </div>
  );
}
