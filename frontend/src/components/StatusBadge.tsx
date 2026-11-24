import React from 'react';

export function StatusBadge({ status }: { status: string }) {
  const s = (status || '').toUpperCase();
  if (s === 'ATTACK') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
        ATTACK
      </span>
    );
  }
  if (s === 'BUFFERING') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
        BUFFERING
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
      BENIGN
    </span>
  );
}

export function ProtocolBadge({ protocol }: { protocol: number }) {
  const map: Record<number, string> = { 6: 'TCP (6)', 17: 'UDP (17)', 1: 'ICMP (1)' };
  return (
    <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-cyan-300 border border-slate-700">
      {map[protocol] || `PROTO-${protocol}`}
    </span>
  );
}

export function SourceBadge({ source }: { source: string }) {
  const s = (source || '').toUpperCase();
  const colors: Record<string, string> = {
    LIVE: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    PCAP_REPLAY: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
    CSV_REPLAY: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  };
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-medium border ${
        colors[s] || 'bg-slate-800 text-slate-300 border-slate-700'
      }`}
    >
      {s || 'N/A'}
    </span>
  );
}
