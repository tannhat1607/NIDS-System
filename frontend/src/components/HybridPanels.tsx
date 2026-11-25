import { DetectionAlert, ModelProfileInfo, MonitoringStatus } from '../types/nids';
import { StatusBadge } from './StatusBadge';

export const MODEL_IDS = ['CIC-IDS2017', 'CIC-DDoS2019'] as const;

// shortcut: historic decisions are stored as notes; use structured fields if the API adds them.
export function modelDecision(record: DetectionAlert, model: typeof MODEL_IDS[number]) {
  if (record.dataset_profile !== 'AUTO') {
    return record.dataset_profile === model
      ? { status: record.detection_status, label: record.predicted_attack_type, score: record.class_score, attack: record.attack_score }
      : null;
  }
  const match = record.note?.match(new RegExp(model + ': (ATTACK|BENIGN)/([^;]+?) \\(class=([0-9.]+), attack=([0-9.]+)(?:, window end=[^;]+)?\\);'));
  if (match) return { status: match[1], label: match[2], score: Number(match[3]), attack: Number(match[4]) };
  if (model === 'CIC-DDoS2019' && record.note?.includes('CIC-DDoS2019:') && record.note.includes('; primary decision;')) {
    return { status: 'BUFFERING', label: `${record.buffered_flows}/${record.required_window_size} flows`, score: null, attack: null };
  }
  return null;
}

export function selectedModel(record: DetectionAlert) {
  if (record.dataset_profile !== 'AUTO') return record.dataset_profile;
  return record.note?.match(/Displayed scores and label: (CIC-IDS2017|CIC-DDoS2019)$/)?.[1] ?? 'Unavailable';
}

export function ModelResult({ record, model }: { record: DetectionAlert; model: typeof MODEL_IDS[number] }) {
  const result = modelDecision(record, model);
  if (!result) return <span className="text-slate-400">{record.dataset_profile === 'AUTO' ? 'Unavailable' : 'Not used'}</span>;
  return <div className="space-y-1 min-w-[130px]">
    <StatusBadge status={result.status} />
    <div className="text-slate-200 break-words">{result.label}</div>
    {result.status !== 'BUFFERING' && result.score !== null && result.attack !== null && <div className="text-slate-400 font-mono">Class {(result.score * 100).toFixed(2)}% · Attack {(result.attack * 100).toFixed(2)}%</div>}
  </div>;
}

export function HybridDecision({ record }: { record?: DetectionAlert }) {
  return <section className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
    <div className="flex flex-wrap justify-between items-center gap-2">
      <h2 className="text-sm font-semibold text-slate-200">Latest hybrid decision</h2>
      <span className="text-xs text-slate-400">{record ? record.detected_at.replace('T', ' ').slice(0, 19) + ' UTC · ' + record.source_ip : 'No hybrid records yet'}</span>
    </div>
    {record && <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
      {MODEL_IDS.map(model => <div key={model} className="rounded-lg border border-slate-700 bg-slate-900 p-3 space-y-2">
        <div className="font-semibold text-cyan-300">{model}</div>
        <ModelResult record={record} model={model} />
      </div>)}
      <div className="rounded-lg border border-cyan-500/40 bg-slate-900 p-3 space-y-2">
        <div className="font-semibold text-cyan-300">Final decision</div>
        <StatusBadge status={record.detection_status} />
        <div className="text-slate-200">{record.predicted_attack_type}</div>
        <div className="text-slate-400">Selected model: {selectedModel(record)}</div>
      </div>
    </div>}
    <p className="text-xs text-slate-400">Either model can raise an alert. When both alert, CIC-IDS2017 supplies the label and scores. Temporal results describe the completed source-IP window.</p>
  </section>;
}

export function ModelStatusPanel({ profiles, mode, monitoring }: { profiles: ModelProfileInfo[]; mode: string; monitoring: boolean }) {
  return <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
    {MODEL_IDS.map((model, index) => {
      const profile = profiles.find(p => p.profile_id === model);
      const enabled = mode === 'AUTO' || mode === model;
      return <div key={model} className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-2">
        <div className="flex flex-wrap justify-between items-center gap-2">
          <h2 className="text-sm font-bold text-slate-100">{model}</h2>
          <span className={profile?.is_loaded ? 'text-xs text-emerald-400' : 'text-xs text-amber-300'}>{profile ? profile.is_loaded ? 'Loaded' : 'Not loaded' : 'Load status unavailable'}</span>
        </div>
        <p className="text-xs text-cyan-300">{index === 0 ? 'Primary · Every flow' : 'Temporal · 8 flows per source IP'}</p>
        <p className="text-xs text-slate-400">{profile ? `${profile.n_features} features · ${profile.n_classes} classes · Window ${profile.window_size}` : 'Model configuration unavailable'}</p>
        <p className="text-xs text-slate-300">{!enabled ? 'Excluded in current mode' : !profile?.is_loaded ? 'Selected · Readiness unavailable' : monitoring ? 'Enabled in monitoring session' : 'Selected · Standby'}</p>
      </div>;
    })}
  </section>;
}

export function TemporalBufferPanel({ status }: { status: MonitoringStatus | null }) {
  const entries = Object.entries(status?.buffered_ips ?? {});
  return <section className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-3">
    <div className="flex justify-between items-center gap-2">
      <h2 className="text-sm font-semibold text-slate-200">Temporal buffer · CIC-DDoS2019</h2>
      <span className="text-xs text-amber-300">{status ? `${entries.length} source IPs` : 'Status unavailable'}</span>
    </div>
    <p className="text-xs text-slate-400">8 valid flows per source IP · Stride 8 · Maximum window 300 seconds</p>
    {entries.length === 0 && <p className="text-xs text-slate-400">{status ? 'No pending windows' : 'Waiting for monitoring status'}</p>}
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-64 overflow-y-auto">
      {entries.map(([ip, count]) => <div key={ip} className="bg-slate-900 rounded-lg border border-slate-700 p-3">
        <div className="flex justify-between gap-2 text-xs font-mono text-slate-300"><span>{ip}</span><span>{count}/8</span></div>
        <progress className="w-full h-2 mt-2 accent-amber-400" max={8} value={count} aria-label={`Temporal buffer for ${ip}`} />
      </div>)}
    </div>
  </section>;
}
