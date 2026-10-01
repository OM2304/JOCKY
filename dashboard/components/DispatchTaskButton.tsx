'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Play } from 'lucide-react';
import DispatchModal from '@/components/DispatchModal';

interface DispatchTaskButtonProps {
  knownAgents?: string[];
}

export default function DispatchTaskButton({ knownAgents = [] }: DispatchTaskButtonProps) {
  const router = useRouter();
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handleSuccess = () => {
    // Refresh the current route to fetch latest reports from the filesystem
    router.refresh();
  };

  return (
    <>
      <button
        onClick={() => setIsModalOpen(true)}
        className="flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors shadow-xs cursor-pointer"
      >
        <Play className="h-3.5 w-3.5 fill-primary-foreground" />
        <span>Dispatch New Task</span>
      </button>

      <DispatchModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={handleSuccess}
        knownAgents={knownAgents}
      />
    </>
  );
}
