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
    <div className="space-y-6">
      {/* Control Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Radio className={`w-5 h-5 ${isMonitoring ? 'text-emerald-400 animate-pulse' : 'text-cyan-400'}`} />
              Hybrid Multi-Model Monitoring
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Chọn profile CNN-LSTM, nguồn dữ liệu (LIVE / CSV Replay / PCAP Replay) và theo dõi kết quả phát hiện thời gian thực
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                wsConnected
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
              }`}
            >
              WebSocket: {wsConnected ? 'CONNECTED' : 'RECONNECTING...'}
            </span>

            {!isMonitoring ? (
              <button
                onClick={handleStartMonitoring}
                disabled={busy}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white shadow transition disabled:opacity-50"
              >
                <Play className="w-4 h-4" />
                Start Monitoring
              </button>
            ) : (
              <button
                onClick={handleStopMonitoring}
                disabled={busy}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-500 text-white shadow transition disabled:opacity-50"
              >
                <Square className="w-4 h-4" />
                Stop Monitoring
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <button type="button" disabled={busy || isMonitoring} onClick={() => handleProfileChange('AUTO')} aria-pressed={selectedProfile === 'AUTO'} className={`rounded-xl border p-4 text-left disabled:opacity-60 ${selectedProfile === 'AUTO' ? 'border-cyan-500 bg-cyan-500/10' : 'border-slate-700 bg-slate-900'}`}>
            <span className="text-sm font-bold text-slate-100">Hybrid Multi-Model</span>
            <span className="block text-xs text-slate-400 mt-1">Automatic fusion · Single-flow + temporal · LIVE / PCAP</span>
          </button>
          <button type="button" disabled={busy || isMonitoring} onClick={() => handleProfileChange(selectedProfile === 'AUTO' ? 'CIC-IDS2017' : selectedProfile)} aria-pressed={selectedProfile !== 'AUTO'} className={`rounded-xl border p-4 text-left disabled:opacity-60 ${selectedProfile !== 'AUTO' ? 'border-cyan-500 bg-cyan-500/10' : 'border-slate-700 bg-slate-900'}`}>
            <span className="text-sm font-bold text-slate-100">Single-model experiment</span>
            <span className="block text-xs text-slate-400 mt-1">Independent evaluation · CSV / PCAP / LIVE</span>
          </button>
        </div>
        {/* Form Controls */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              1. Model profile
            </label>
            <select
              value={selectedProfile}
              disabled={isMonitoring || busy || selectedProfile === 'AUTO'}
              onChange={(e) => handleProfileChange(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
            >
              {selectedProfile === 'AUTO' && <option value="AUTO">Both models · AUTO</option>}
              {profiles.map((p) => (
                <option key={p.profile_id} value={p.profile_id}>
                  {p.profile_id} ({p.n_features} features, {p.n_classes} classes, window={p.window_size})
                </option>
              ))}
              {profiles.length === 0 && (
                <>
                  <option value="CIC-IDS2017">CIC-IDS2017 (70 features, 12 classes, window=1)</option>
                  <option value="CIC-DDoS2019">CIC-DDoS2019 (66 features, 17 classes, window=8)</option>
                </>
              )}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              2. Nguồn dữ liệu (Data Source)
            </label>
            <select
              value={selectedSource}
              disabled={isMonitoring}
              onChange={(e) => setSelectedSource(e.target.value as any)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
            >
              <option value="CSV_REPLAY" disabled={selectedProfile === 'AUTO'}>CSV_REPLAY (Single model)</option>
              <option value="PCAP_REPLAY">PCAP_REPLAY (Scapy Flow Extractor)</option>
              <option value="LIVE">LIVE (Scapy Live Interface Sniffer)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              3. Network Interface (Dành cho LIVE)
            </label>
            <select
              value={selectedInterface}
              disabled={isMonitoring || selectedSource !== 'LIVE'}
              onChange={(e) => setSelectedInterface(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
            >
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.name} ({iface.ip || 'no-ip'})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              4. Tốc độ Replay (Delay ms / flow)
            </label>
            <input
              type="number"
              min={0}
              max={2000}
              step={20}
              value={replayDelayMs}
              disabled={isMonitoring || selectedSource === 'LIVE'}
              onChange={(e) => setReplayDelayMs(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
            />
          </div>
        </div>

        {/* Upload Custom CSV / PCAP */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 text-xs">
            <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300">Upload file CSV hoặc PCAP tùy chỉnh:</span>
            <input
              type="file"
              accept={selectedProfile === 'AUTO' ? '.pcap,.pcapng' : '.csv,.pcap,.pcapng'}
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-400 file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-300 hover:file:bg-slate-700"
            />
            {uploadFile && (
              <button
                onClick={handleUploadAndRun}
                disabled={busy || isMonitoring}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition disabled:opacity-50"
              >
                <Upload className="w-3.5 h-3.5" />
                Chạy File Upload
              </button>
            )}
          </div>

          <div className="text-xs text-slate-400">
            Trạng thái kiểm chứng Live Capture:{' '}
            <span className="text-amber-300 font-mono font-semibold">
              {effectiveStatus?.live_validation_status || 'READY FOR LINUX VALIDATION'}
            </span>
          </div>
        </div>

        {effectiveStatus?.last_error && <p className="text-xs text-red-300">{effectiveStatus.last_error}</p>}
        {message && (
          <div
            className={`px-4 py-2.5 rounded-lg text-xs flex items-center gap-2 border ${
              message.type === 'error'
                ? 'bg-red-500/10 border-red-500/30 text-red-300'
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {message.type === 'error' ? (
              <AlertCircle className="w-4 h-4 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 shrink-0" />
            )}
            <span>{message.text}</span>
          </div>
        )}
      </div>

      <ModelStatusPanel profiles={profiles} mode={effectiveStatus?.is_monitoring ? effectiveStatus.active_profile : selectedProfile} monitoring={isMonitoring} />
      {(selectedProfile === 'AUTO' || selectedProfile === 'CIC-DDoS2019') && <TemporalBufferPanel status={effectiveStatus} />}
      {selectedProfile === 'AUTO' && <HybridDecision record={latestHybrid} />}

      {/* Realtime Stream Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              Luồng giám sát và kết quả suy luận thời gian thực (Realtime Detection Stream)
            </h2>
            <p className="text-xs text-slate-400">
              Hiển thị trực tiếp kết quả từ CNN-LSTM Detection Engine qua WebSocket ({tableRecords.length} bản ghi)
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs text-slate-400">
            <span>
              Inferences: <strong className="text-slate-200">{effectiveStatus?.total_inferences || 0}</strong>
            </span>
            <span>
              Alerts: <strong className="text-red-400">{effectiveStatus?.total_attacks || 0}</strong>
            </span>
            <span>
              Buffering: <strong className="text-amber-300">{effectiveStatus?.total_buffering || 0}</strong>
            </span>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[520px]">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-900 text-slate-400 border-b border-slate-800 uppercase z-10">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">CIC-IDS2017</th>
                <th className="py-3 px-4">CIC-DDoS2019</th>
                <th className="py-3 px-4">Final Status</th>
                <th className="py-3 px-4">Predicted Attack Type</th>
                <th className="py-3 px-4">Model Score</th>
                <th className="py-3 px-4">Window / Source</th>
                <th className="py-3 px-4 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {tableRecords.map((rec) => (
                <tr
                  key={rec.alert_id}
                  className={`transition ${
                    rec.detection_status === 'ATTACK'
                      ? 'bg-red-950/20 hover:bg-red-950/30'
                      : rec.detection_status === 'BUFFERING'
                      ? 'bg-amber-950/10 hover:bg-amber-950/20'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-2.5 px-4 font-mono text-slate-300">
                    {rec.detected_at.replace('T', ' ').slice(11, 23)}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-200">
                    {rec.source_ip}:{rec.source_port}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-200">
                    {rec.destination_ip}:{rec.destination_port}
                  </td>
                  <td className="py-2.5 px-4">
                    <ProtocolBadge protocol={rec.protocol} />
                  </td>
                  <td className="py-2.5 px-4"><ModelResult record={rec} model="CIC-IDS2017" /></td>
                  <td className="py-2.5 px-4"><ModelResult record={rec} model="CIC-DDoS2019" /></td>
                  <td className="py-2.5 px-4">
                    <StatusBadge status={rec.detection_status} />
                  </td>
                  <td className="py-2.5 px-4 font-semibold text-slate-100">
                    {rec.predicted_attack_type}
                    <div className="mt-1 text-xs font-normal text-slate-400">{selectedModel(rec)}</div>
                  </td>
                  <td className="py-2.5 px-4 font-mono">
                    {rec.detection_status === 'BUFFERING' ? (
                      <span className="text-amber-300">
                        {rec.buffered_flows}/{rec.required_window_size} flows
                      </span>
                    ) : (
                      <span className="text-cyan-300">{(rec.class_score * 100).toFixed(2)}%</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 space-x-1.5">
                    <span className="text-slate-400">{rec.dataset_profile}</span>
                    <SourceBadge source={rec.data_source} />
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono text-slate-300">
                    {rec.detection_status === 'BUFFERING'
                      ? '—'
                      : `${rec.inference_latency_ms.toFixed(2)} ms`}
                  </td>
                </tr>
              ))}
              {tableRecords.length === 0 && (
                <tr>
                  <td colSpan={11} className="py-10 text-center text-slate-500">
                    Nhấn "Start Monitoring" để bắt đầu luồng suy luận trực tiếp.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
