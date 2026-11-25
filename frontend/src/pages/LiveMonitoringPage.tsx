import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  FileSpreadsheet,
  Play,
  Radio,
  Square,
  Upload,
} from 'lucide-react';
import { nidsApi } from '../services/api';
import {
  DetectionAlert,
  ModelProfileInfo,
  MonitoringStatus,
  NetworkInterfaceInfo,
} from '../types/nids';
import { ProtocolBadge, SourceBadge, StatusBadge } from '../components/StatusBadge';
import { HybridDecision, ModelResult, ModelStatusPanel, TemporalBufferPanel, selectedModel } from '../components/HybridPanels';

interface LiveMonitoringPageProps {
  wsConnected: boolean;
  liveStatus: MonitoringStatus | null;
  liveFeed: DetectionAlert[];
  clearLiveFeed: () => void;
}

export function LiveMonitoringPage({
  wsConnected,
  liveStatus,
  liveFeed,
  clearLiveFeed,
}: LiveMonitoringPageProps) {
  const [profiles, setProfiles] = useState<ModelProfileInfo[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('AUTO');
  const [selectedSource, setSelectedSource] = useState<'CSV_REPLAY' | 'PCAP_REPLAY' | 'LIVE'>('PCAP_REPLAY');
  const [selectedInterface, setSelectedInterface] = useState<string>('eth0');
  const [replayDelayMs, setReplayDelayMs] = useState<number>(80);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [statusData, setStatusData] = useState<MonitoringStatus | null>(null);
  const [tableRecords, setTableRecords] = useState<DetectionAlert[]>([]);
  const [showModelDetails, setShowModelDetails] = useState(false);
  const [busy, setBusy] = useState<boolean>(false);
  const [message, setMessage] = useState<{ type: 'info' | 'error'; text: string } | null>(null);

  const loadConfigAndStatus = async () => {
    try {
      const [pRes, iRes, sRes] = await Promise.all([
        nidsApi.getProfiles(),
        nidsApi.getInterfaces(),
        nidsApi.getMonitoringStatus(),
      ]);
      setProfiles(pRes.profiles);
      setSelectedProfile(pRes.active_profile);
      if (sRes.is_monitoring && (sRes.data_source === 'LIVE' || sRes.data_source === 'PCAP_REPLAY' || sRes.data_source === 'CSV_REPLAY')) setSelectedSource(sRes.data_source);
      setInterfaces(iRes.interfaces);
      if (iRes.interfaces.length > 0 && !selectedInterface) {
        setSelectedInterface(iRes.interfaces[0].id);
      }
      setStatusData(sRes);
      if (sRes.recent_detections && sRes.recent_detections.length > 0 && liveFeed.length === 0) {
        setTableRecords(sRes.recent_detections);
      }
    } catch (err: any) {
      setMessage({ type: 'error', text: err?.message || 'Không thể tải cấu hình giám sát.' });
    }
  };

  useEffect(() => {
    loadConfigAndStatus();
    const timer = window.setInterval(async () => {
      try {
        const s = await nidsApi.getMonitoringStatus();
        setStatusData(s);
        if (s.recent_detections && s.recent_detections.length > 0) {
          setTableRecords(s.recent_detections);
        }
      } catch {
        // ignore poll error
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (liveFeed.length > 0) {
      setTableRecords(liveFeed);
    }
  }, [liveFeed]);

  const effectiveStatus = (wsConnected ? liveStatus : null) || statusData;
  const isMonitoring = effectiveStatus?.is_monitoring ?? false;

  const handleProfileChange = async (newProfile: string) => {
    setSelectedProfile(newProfile);
    setUploadFile(null);
    if (newProfile === 'AUTO' && selectedSource === 'CSV_REPLAY') setSelectedSource('PCAP_REPLAY');
    if (!isMonitoring) {
      try {
        await nidsApi.selectProfile(newProfile);
        setMessage({
          type: 'info',
          text: `Đã chuyển model profile sang ${newProfile}.`,
        });
      } catch (err: any) {
        setMessage({ type: 'error', text: err?.message || 'Lỗi chuyển profile.' });
      }
    }
  };

  const handleStartMonitoring = async () => {
    setBusy(true);
    setMessage(null);
    clearLiveFeed();
    setTableRecords([]);
    try {
      const res = await nidsApi.startMonitoring({
        profile_id: selectedProfile,
        data_source: selectedSource,
        interface: selectedSource === 'LIVE' ? selectedInterface : undefined,
        replay_delay_ms: replayDelayMs,
        max_rows: 150,
      });
      setStatusData(res);
      setMessage({
        type: 'info',
        text: `Đã bắt đầu phiên giám sát (${selectedSource}) với profile ${selectedProfile}.`,
      });
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err?.message || 'Không thể bắt đầu phiên giám sát.',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleStopMonitoring = async () => {
    setBusy(true);
    try {
      const res = await nidsApi.stopMonitoring();
      setStatusData(res);
      setMessage({ type: 'info', text: 'Đã dừng phiên giám sát an toàn.' });
    } catch (err: any) {
      setMessage({ type: 'error', text: err?.message || 'Lỗi khi dừng giám sát.' });
    } finally {
      setBusy(false);
    }
  };

  const handleUploadAndRun = async () => {
    if (!uploadFile) return;
    if (selectedSource === 'LIVE') {
      setMessage({
        type: 'error',
        text: 'Hãy chọn nguồn CSV_REPLAY hoặc PCAP_REPLAY để upload file.',
      });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const res = await nidsApi.uploadReplayFile(
        uploadFile,
        selectedProfile,
        selectedSource,
        200
      );
      setTableRecords(res.records || []);
      setMessage({
        type: 'info',
        text: `Đã xử lý file ${res.file_name}: ${res.flows_processed} flows, ${res.inferences_completed} inferences (${res.attack_count} ATTACK, ${res.benign_count} BENIGN, ${res.buffering_count} BUFFERING).`,
      });
    } catch (err: any) {
      setMessage({ type: 'error', text: err?.message || 'Upload & Replay thất bại.' });
    } finally {
      setBusy(false);
    }
  };

  const latestHybrid = tableRecords.find(record => record.dataset_profile === 'AUTO');

  return (
    <div className="space-y-4 min-w-0 max-w-full">
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Radio className={`w-5 h-5 ${isMonitoring ? 'text-emerald-400 animate-pulse' : 'text-cyan-400'}`} />
              Live Monitoring
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              {isMonitoring ? 'Monitoring active' : 'Ready to monitor'}
              {isMonitoring && ` | ${effectiveStatus?.active_profile} | ${effectiveStatus?.data_source}`}
              {isMonitoring && effectiveStatus?.data_source === 'LIVE' && effectiveStatus.interface && ` | ${effectiveStatus.interface}`}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${wsConnected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-300 border-amber-500/30'}`}>
              WebSocket: {wsConnected ? 'CONNECTED' : 'RECONNECTING'}
            </span>
            <button
              type="button"
              onClick={isMonitoring ? handleStopMonitoring : handleStartMonitoring}
              disabled={busy}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold text-white shadow transition disabled:opacity-50 ${isMonitoring ? 'bg-red-600 hover:bg-red-500' : 'bg-cyan-600 hover:bg-cyan-500'}`}
            >
              {isMonitoring ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 border-t border-slate-800 pt-3">
          <label className="min-w-0 text-xs font-semibold text-slate-300">
            Monitoring model
            <select
              value={selectedProfile}
              disabled={isMonitoring || busy}
              onChange={(e) => handleProfileChange(e.target.value)}
              className="mt-1.5 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
            >
              <option value="AUTO">Hybrid Multi-Model (AUTO)</option>
              <optgroup label="Single-model experiment">
                {profiles.map((p) => (
                  <option key={p.profile_id} value={p.profile_id}>{p.profile_id}</option>
                ))}
                {profiles.length === 0 && (
                  <>
                    <option value="CIC-IDS2017">CIC-IDS2017</option>
                    <option value="CIC-DDoS2019">CIC-DDoS2019</option>
                  </>
                )}
              </optgroup>
            </select>
          </label>
          <label className="min-w-0 text-xs font-semibold text-slate-300">
            Data source
            <select
              value={selectedSource}
              disabled={isMonitoring || busy}
              onChange={(e) => {
                setSelectedSource(e.target.value as typeof selectedSource);
                setUploadFile(null);
              }}
              className="mt-1.5 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
            >
              <option value="LIVE">LIVE - Network interface</option>
              <option value="PCAP_REPLAY">PCAP Replay</option>
              <option value="CSV_REPLAY" disabled={selectedProfile === 'AUTO'}>CSV Replay (single model)</option>
            </select>
          </label>
          {selectedSource === 'LIVE' ? (
            <label className="min-w-0 text-xs font-semibold text-slate-300">
              Network interface
              <select
                value={selectedInterface}
                disabled={isMonitoring || busy}
                onChange={(e) => setSelectedInterface(e.target.value)}
                className="mt-1.5 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
              >
                {interfaces.map((iface) => (
                  <option key={iface.id} value={iface.id}>{iface.name} ({iface.ip || 'no-ip'})</option>
                ))}
              </select>
            </label>
          ) : (
            <label className="min-w-0 text-xs font-semibold text-slate-300">
              Replay delay (ms / flow)
              <input
                type="number"
                min={0}
                max={2000}
                step={20}
                value={replayDelayMs}
                disabled={isMonitoring || busy}
                onChange={(e) => setReplayDelayMs(Number(e.target.value))}
                className="mt-1.5 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
              />
            </label>
          )}
        </div>

        {selectedSource === 'LIVE' ? (
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
            <span>Live capture: <strong className="text-amber-300 font-mono">{effectiveStatus?.live_validation_status || 'READY FOR LINUX VALIDATION'}</strong></span>
            <span>Session packets: <strong className="text-slate-200">{effectiveStatus?.data_source === 'LIVE' ? effectiveStatus.packets_processed : '-'}</strong></span>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-3 border-t border-slate-800 pt-3 text-xs">
            <label className="flex items-center gap-2 text-slate-300 shrink-0" htmlFor="replay-file">
              <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
              Custom replay file
            </label>
            <input
              key={`${selectedProfile}:${selectedSource}`}
              id="replay-file"
              type="file"
              disabled={busy || isMonitoring}
              accept={selectedProfile === 'AUTO' ? '.pcap,.pcapng' : '.csv,.pcap,.pcapng'}
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              className="min-w-0 max-w-full text-xs text-slate-400 file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-300 hover:file:bg-slate-700 disabled:opacity-60"
            />
            {uploadFile && (
              <button
                type="button"
                onClick={handleUploadAndRun}
                disabled={busy || isMonitoring}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition disabled:opacity-50"
              >
                <Upload className="w-3.5 h-3.5" /> Run File
              </button>
            )}
          </div>
        )}

        {effectiveStatus?.last_error && <p className="text-xs text-red-300" role="alert">{effectiveStatus.last_error}</p>}
        {message && (
          <div role={message.type === 'error' ? 'alert' : 'status'} className={`px-3 py-2 rounded-lg text-xs flex items-center gap-2 border ${message.type === 'error' ? 'bg-red-500/10 border-red-500/30 text-red-300' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-200'}`}>
            {message.type === 'error' ? <AlertCircle className="w-4 h-4 shrink-0" /> : <CheckCircle2 className="w-4 h-4 shrink-0" />}
            <span>{message.text}</span>
          </div>
        )}
      </section>

      <section className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden min-w-0">
        <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Realtime Detection Stream</h2>
            <p className="text-xs text-slate-400 mt-1">{tableRecords.length} recent records | {isMonitoring ? 'Monitoring active' : 'Standby'}</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" checked={showModelDetails} onChange={(e) => setShowModelDetails(e.target.checked)} className="accent-cyan-500" />
            Show per-model results
          </label>
        </div>
        <div className="px-4 pt-3 pb-2 text-xs text-slate-400">Cumulative detection totals</div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 px-4 pb-3">
          {[
            { label: 'Inferences', value: effectiveStatus?.total_inferences, color: 'text-cyan-300' },
            { label: 'Alerts', value: effectiveStatus?.total_attacks, color: 'text-red-400' },
            { label: 'Benign', value: effectiveStatus?.total_benign, color: 'text-emerald-400' },
            { label: 'Buffering', value: effectiveStatus?.total_buffering, color: 'text-amber-300' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 flex flex-wrap items-center justify-between gap-1">
              <span className="text-xs text-slate-400">{label}</span>
              <strong className={`text-lg tabular-nums ${color}`}>{value?.toLocaleString() ?? '-'}</strong>
            </div>
          ))}
        </div>

        <div className="overflow-auto max-h-[min(60vh,640px)] min-w-0 border-t border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-900 text-slate-400 border-b border-slate-800 uppercase z-10">
              <tr>
                <th scope="col" className="py-3 px-3">Time</th>
                <th scope="col" className="py-3 px-3">Source IP</th>
                <th scope="col" className="py-3 px-3">Destination IP</th>
                <th scope="col" className="py-3 px-3">Protocol</th>
                <th scope="col" className="py-3 px-3">Final status</th>
                <th scope="col" className="py-3 px-3">Prediction</th>
                <th scope="col" className="py-3 px-3">Score / Window</th>
                <th scope="col" className="py-3 px-3">Source</th>
                <th scope="col" className="py-3 px-3 text-right">Latency</th>
                {showModelDetails && (
                  <>
                    <th scope="col" className="py-3 px-3">CIC-IDS2017</th>
                    <th scope="col" className="py-3 px-3">CIC-DDoS2019</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {tableRecords.map((rec) => (
                <tr key={rec.alert_id} className={`transition ${rec.detection_status === 'ATTACK' ? 'bg-red-950/20 hover:bg-red-950/30' : rec.detection_status === 'BUFFERING' ? 'bg-amber-950/10 hover:bg-amber-950/20' : 'hover:bg-slate-800/40'}`}>
                  <td className="py-3 px-3 font-mono text-slate-300 whitespace-nowrap">{rec.detected_at.replace('T', ' ').slice(11, 23)}</td>
                  <td className="py-3 px-3 font-mono text-slate-200 whitespace-nowrap">{rec.source_ip}:{rec.source_port}</td>
                  <td className="py-3 px-3 font-mono text-slate-200 whitespace-nowrap">{rec.destination_ip}:{rec.destination_port}</td>
                  <td className="py-3 px-3"><ProtocolBadge protocol={rec.protocol} /></td>
                  <td className="py-3 px-3"><StatusBadge status={rec.detection_status} /></td>
                  <td className="py-3 px-3 font-semibold text-slate-100">
                    {rec.predicted_attack_type}
                    <div className="mt-1 text-xs font-normal text-slate-400">{selectedModel(rec)}</div>
                  </td>
                  <td className="py-3 px-3 font-mono whitespace-nowrap">
                    {rec.detection_status === 'BUFFERING' ? (
                      <span className="text-amber-300">{rec.buffered_flows}/{rec.required_window_size} flows</span>
                    ) : (
                      <span className="text-cyan-300">{(rec.class_score * 100).toFixed(2)}%</span>
                    )}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <SourceBadge source={rec.data_source} />
                    <div className="mt-1 text-slate-400">{rec.dataset_profile}</div>
                  </td>
                  <td className="py-3 px-3 text-right font-mono text-slate-300 whitespace-nowrap">
                    {rec.detection_status === 'BUFFERING' ? '-' : `${rec.inference_latency_ms.toFixed(2)} ms`}
                  </td>
                  {showModelDetails && (
                    <>
                      <td className="py-3 px-3"><ModelResult record={rec} model="CIC-IDS2017" /></td>
                      <td className="py-3 px-3"><ModelResult record={rec} model="CIC-DDoS2019" /></td>
                    </>
                  )}
                </tr>
              ))}
              {tableRecords.length === 0 && (
                <tr>
                  <td colSpan={showModelDetails ? 11 : 9} className="py-12 text-center text-slate-400">
                    <Radio className="mx-auto w-6 h-6 mb-2 text-cyan-400" />
                    {isMonitoring ? 'Waiting for completed flows and inference results...' : 'Start monitoring or run a replay file to view detection results.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <details className="bg-[#111827] border border-slate-800 rounded-xl p-4">
        <summary className="cursor-pointer text-sm font-semibold text-slate-200">
          Model diagnostics <span className="ml-2 text-xs font-normal text-slate-400">Model status, temporal buffer, hybrid decision</span>
        </summary>
        <div className="mt-4 space-y-3">
          <ModelStatusPanel profiles={profiles} mode={effectiveStatus?.is_monitoring ? effectiveStatus.active_profile : selectedProfile} monitoring={isMonitoring} />
          {(selectedProfile === 'AUTO' || selectedProfile === 'CIC-DDoS2019') && <TemporalBufferPanel status={effectiveStatus} />}
          {selectedProfile === 'AUTO' && <HybridDecision record={latestHybrid} />}
        </div>
      </details>
    </div>
  );
}
