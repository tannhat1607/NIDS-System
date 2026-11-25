import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, ArrowRight, Gauge, Layers, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { nidsApi } from '../services/api';
import { AttackStatsResponse, DetectionAlert, MonitoringStatus } from '../types/nids';
import { SourceBadge } from '../components/StatusBadge';
import { selectedModel } from '../components/HybridPanels';

interface OverviewPageProps {
  wsConnected: boolean;
  liveStatus: MonitoringStatus | null;
  onNavigate: (page: string) => void;
}

export function OverviewPage({ wsConnected, liveStatus, onNavigate }: OverviewPageProps) {
  const [runtime, setRuntime] = useState<MonitoringStatus | null>(null);
  const [runtimeError, setRuntimeError] = useState(false);
  const [profileFilter, setProfileFilter] = useState('AUTO');
  const [history, setHistory] = useState<{ profile: string; stats: AttackStatsResponse; alerts: DetectionAlert[] } | null>(null);
  const [historyError, setHistoryError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const result = await nidsApi.getMonitoringStatus();
        if (!cancelled) {
          setRuntime(result);
          setRuntimeError(false);
        }
      } catch {
        if (!cancelled) setRuntimeError(true);
      } finally {
        busy = false;
      }
    };
    load();
    const timer = window.setInterval(load, 4000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    let busy = false;
    setHistoryError(false);
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const [stats, alerts] = await Promise.all([
          nidsApi.getAttackStats(profileFilter),
          nidsApi.getAlerts({ dataset_profile: profileFilter, detection_status: 'ATTACK', page: 1, page_size: 5 }),
        ]);
        if (!cancelled) {
          setHistory({ profile: profileFilter, stats, alerts: alerts.items });
          setHistoryError(false);
        }
      } catch {
        if (!cancelled) setHistoryError(true);
      } finally {
        busy = false;
      }
    };
    load();
    const timer = window.setInterval(load, 4000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [profileFilter]);

  const status = (wsConnected ? liveStatus : null) || (runtimeError ? null : runtime);
  const isMonitoring = status?.is_monitoring ?? false;
  const mode = status?.active_profile === 'AUTO' ? 'Hybrid Multi-Model' : status?.active_profile ?? '—';
  const currentHistory = history?.profile === profileFilter ? history : null;
  const stats = currentHistory?.stats;
  const topAttacks = (stats?.distribution ?? []).filter(item => item.detection_status === 'ATTACK').slice(0, 5);
  const number = (value?: number) => value?.toLocaleString() ?? '—';
  const state = !status ? 'Chưa có trạng thái' : isMonitoring ? 'Đang giám sát' : status.last_error ? 'Đã dừng · Có lỗi' : 'Đang chờ';
  const cards = [
    { label: 'Luồng đã xử lý', value: number(status?.total_flows_seen), detail: 'Packets (phiên giám sát): ' + number(status?.packets_processed), icon: Layers, color: 'text-cyan-400' },
    { label: 'Cảnh báo ATTACK', value: number(status?.total_attacks), detail: 'Tích lũy qua các phiên', icon: ShieldAlert, color: 'text-red-400' },
    { label: 'Kết quả BENIGN', value: number(status?.total_benign), detail: 'Tích lũy qua các phiên', icon: ShieldCheck, color: 'text-emerald-400' },
    { label: 'Độ trễ trung bình', value: status?.total_inferences ? status.latency_avg_ms.toFixed(2) + ' ms' : '—', detail: 'P95: ' + (status?.total_inferences ? status.latency_p95_ms.toFixed(2) + ' ms' : '—') + ' · Tối đa 5.000 mẫu gần nhất', icon: Gauge, color: 'text-slate-100' },
  ];

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3 pr-10">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Overview</h1>
          <p className="mt-1 text-xs text-slate-400">Tổng quan an ninh mạng · Hybrid Multi-Model NIDS</p>
        </div>
        <button onClick={() => onNavigate('live')} className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-xs font-semibold text-white">
          <Activity className="h-4 w-4" /> Live Monitoring <ArrowRight className="h-4 w-4" />
        </button>
      </header>

      <section className="space-y-3" aria-label="Trạng thái giám sát">
        <div className="bg-[#111827] rounded-xl border border-slate-800 p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={'h-2.5 w-2.5 shrink-0 rounded-full ' + (isMonitoring ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500')} />
            <div>
              <h2 className="text-sm font-bold text-slate-100">{state}</h2>
              <p className="mt-1 text-xs text-slate-400">{mode}{status?.data_source ? ' · ' + status.data_source : ''}{status?.interface ? ' · ' + status.interface : ''}</p>
            </div>
          </div>
          <span className={'text-xs font-medium ' + (wsConnected ? 'text-emerald-400' : 'text-amber-300')}>
            WebSocket {wsConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        {status?.last_error && <p className="text-xs text-red-300">{status.last_error}</p>}
        {!status && runtimeError && <p className="text-xs text-red-300">Không thể lấy trạng thái từ backend.</p>}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-200">Thống kê hoạt động</h2>
          <span className="text-xs text-slate-400">Tích lũy từ lần reset bộ đếm</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {cards.map(({ label, value, detail, icon: Icon, color }) => (
            <div key={label} className="bg-[#111827] rounded-xl border border-slate-800 p-4 min-w-0">
              <div className="flex items-center justify-between gap-2 text-xs text-slate-400">
                <span>{label}</span><Icon className={'h-4 w-4 shrink-0 ' + color} />
              </div>
              <p className={'mt-2 text-2xl font-bold tabular-nums ' + color}>{value}</p>
              <p className="mt-1 text-xs text-slate-400">{detail}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-3" aria-label="Thống kê lịch sử">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Lịch sử phát hiện</h2>
            <p className="mt-1 text-xs text-slate-400">Tất cả phiên đã lưu · cập nhật mỗi 4 giây</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-400">
            Profile
            <select value={profileFilter} onChange={e => setProfileFilter(e.target.value)} className="bg-slate-900 rounded-lg border border-slate-700 px-3 py-2 text-slate-200">
              <option value="AUTO">Hybrid (AUTO)</option>
              <option value="ALL">Tất cả profiles</option>
              <option value="CIC-IDS2017">CIC-IDS2017</option>
              <option value="CIC-DDoS2019">CIC-DDoS2019</option>
            </select>
          </label>
        </div>
        {historyError && <p className="flex items-center gap-2 text-xs text-amber-300"><AlertTriangle className="h-4 w-4" /> Không thể cập nhật lịch sử. {currentHistory ? 'Đang hiển thị dữ liệu lần tải gần nhất.' : 'Chưa có dữ liệu.'}</p>}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
          <div className="xl:col-span-2 bg-[#111827] rounded-xl border border-slate-800 p-4 min-w-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-slate-200">Diễn biến phát hiện</h3>
              <div className="flex flex-wrap gap-3 text-xs">
                <span className="text-emerald-400">BENIGN {number(stats?.total_benign)}</span>
                <span className="text-red-400">ATTACK {number(stats?.total_attacks)}</span>
              </div>
            </div>
            <p className="mt-1 text-xs text-slate-400">30 mốc phút có dữ liệu gần nhất · UTC</p>
            <div className="h-52 mt-3">
              {stats?.timeline.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={stats.timeline} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
                    <XAxis dataKey="time_bucket" tickFormatter={value => String(value).slice(11, 16)} stroke="#94a3b8" fontSize={11} minTickGap={24} />
                    <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8, color: '#e2e8f0', fontSize: 12 }} />
                    <Area type="monotone" dataKey="benign_count" name="BENIGN" stroke="#10b981" fill="#10b981" fillOpacity={0.12} isAnimationActive={false} />
                    <Area type="monotone" dataKey="attack_count" name="ATTACK" stroke="#ef4444" fill="#ef4444" fillOpacity={0.2} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-400">{stats ? 'Chưa có dữ liệu phát hiện.' : historyError ? 'Không tải được dữ liệu.' : 'Đang tải dữ liệu...'}</div>
              )}
            </div>
          </div>

          <div className="bg-[#111827] rounded-xl border border-slate-800 p-4 space-y-3 min-w-0">
            <h3 className="text-sm font-semibold text-slate-200">Tấn công thường gặp</h3>
            <div>
              <p className="text-2xl font-bold text-red-400">{stats?.total_records ? (stats.attack_ratio * 100).toFixed(1) + '%' : '—'}</p>
              <p className="mt-1 text-xs text-slate-400">Tỷ lệ bản ghi được dự đoán ATTACK</p>
            </div>
            <div className="border-t border-slate-800 pt-3 space-y-3">
              {topAttacks.map(item => (
                <div key={item.attack_type}>
                  <div className="flex justify-between gap-2 text-xs text-slate-300"><span className="break-all">{item.attack_type}</span><span className="font-mono">{number(item.count)}</span></div>
                  <div className="mt-1.5 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full rounded-full bg-red-400" style={{ width: (item.count / Math.max(1, stats?.total_attacks ?? 0) * 100) + '%' }} />
                  </div>
                </div>
              ))}
              {topAttacks.length === 0 && <p className="text-xs text-slate-400">{stats ? 'Chưa ghi nhận ATTACK.' : 'Chưa có dữ liệu.'}</p>}
            </div>
          </div>
        </div>

        <div className="bg-[#111827] rounded-xl border border-slate-800 overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 p-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200">5 cảnh báo gần nhất</h3>
            <button onClick={() => onNavigate('history')} className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 hover:text-cyan-300">Xem lịch sử <ArrowRight className="h-3.5 w-3.5" /></button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400">
                <tr className="border-b border-slate-800">
                  <th scope="col" className="px-4 py-3">Thời gian (UTC)</th>
                  <th scope="col" className="px-4 py-3">Source IP</th>
                  <th scope="col" className="px-4 py-3">Loại tấn công</th>
                  <th scope="col" className="px-4 py-3">Mô hình</th>
                  <th scope="col" className="px-4 py-3">Nguồn</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {currentHistory?.alerts.map(alert => (
                  <tr key={alert.alert_id} className="hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-mono whitespace-nowrap text-slate-300">{alert.detected_at.replace('T', ' ').slice(0, 19)}</td>
                    <td className="px-4 py-3 font-mono text-slate-200">{alert.source_ip}</td>
                    <td className="px-4 py-3 font-semibold text-red-400">{alert.predicted_attack_type}</td>
                    <td className="px-4 py-3 text-slate-300">{selectedModel(alert)}</td>
                    <td className="px-4 py-3"><SourceBadge source={alert.data_source} /></td>
                  </tr>
                ))}
                {!currentHistory?.alerts.length && <tr><td colSpan={5} className="px-4 py-8 text-center text-slate-400">{currentHistory ? 'Chưa có cảnh báo tấn công.' : historyError ? 'Không tải được lịch sử.' : 'Đang tải lịch sử...'}</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
