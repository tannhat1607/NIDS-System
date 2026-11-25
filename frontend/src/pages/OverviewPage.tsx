import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Cpu,
  Gauge,
  Layers,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { nidsApi } from '../services/api';
import { AttackStatsResponse, MonitoringStatus, TrafficStats } from '../types/nids';
import { ProtocolBadge, SourceBadge, StatusBadge } from '../components/StatusBadge';

interface OverviewPageProps {
  wsConnected: boolean;
  liveStatus: MonitoringStatus | null;
  onNavigate: (page: string) => void;
}

export function OverviewPage({ wsConnected, liveStatus, onNavigate }: OverviewPageProps) {
  const [traffic, setTraffic] = useState<TrafficStats | null>(null);
  const [attackStats, setAttackStats] = useState<AttackStatsResponse | null>(null);
  const [profileFilter, setProfileFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setError(null);
      const [tRes, aRes] = await Promise.all([
        nidsApi.getTrafficStats(profileFilter),
        nidsApi.getAttackStats(profileFilter),
      ]);
      setTraffic(tRes);
      setAttackStats(aRes);
    } catch (err: any) {
      setError(err?.message || 'Không thể tải dữ liệu tổng quan từ Backend API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = window.setInterval(loadData, 4000);
    return () => window.clearInterval(interval);
  }, [profileFilter]);

  const activeProfile = liveStatus?.active_profile || traffic?.active_profile || 'AUTO';
  const isMonitoring = liveStatus?.is_monitoring ?? traffic?.is_monitoring ?? false;
  const totalPackets = liveStatus?.packets_processed || traffic?.packets_processed || 0;
  const totalFlows = liveStatus?.total_flows_seen || traffic?.total_flows_seen || 0;
  const totalInferences = traffic?.total_inferences || 0;
  const totalAttacks = traffic?.total_attacks || 0;
  const totalBenign = traffic?.total_benign || 0;
  const latencyAvg = liveStatus?.latency_avg_ms || traffic?.latency_avg_ms || 0;
  const latencyP95 = liveStatus?.latency_p95_ms || traffic?.latency_p95_ms || 0;

  const pieData = [
    { name: 'BENIGN', value: totalBenign, color: '#10b981' },
    { name: 'ATTACK', value: totalAttacks, color: '#ef4444' },
  ];

  const barData = (attackStats?.distribution || []).slice(0, 10).map((item) => ({
    name: item.attack_type,
    count: item.count,
    isAttack: item.detection_status === 'ATTACK',
  }));

  return (
    <div className="space-y-6">
      {/* Header Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#111827] border border-slate-800 rounded-xl p-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Security Operations Center — System Overview
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Giám sát lưu lượng mạng, phân bố cảnh báo CNN-LSTM và hiệu năng suy luận theo thời gian thực
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5">
            <span className="text-slate-400">Filter Profile:</span>
            <select
              value={profileFilter}
              onChange={(e) => setProfileFilter(e.target.value)}
              className="bg-transparent text-cyan-300 font-semibold focus:outline-none"
            >
              <option value="ALL" className="bg-slate-900">Tất cả Profiles</option>
              <option value="AUTO" className="bg-slate-900">AUTO (Hybrid)</option>
              <option value="CIC-IDS2017" className="bg-slate-900">CIC-IDS2017 (70 Features)</option>
              <option value="CIC-DDoS2019" className="bg-slate-900">CIC-DDoS2019 (8x66 Temporal)</option>
            </select>
          </div>

          <button
            onClick={loadData}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Làm mới
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-xl text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* System Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase tracking-wider">Active Model Profile</p>
            <p className="text-lg font-bold text-cyan-400 mt-1">{activeProfile}</p>
            <p className="text-xs text-slate-400 mt-0.5">
              {activeProfile === 'AUTO' ? 'Hybrid CNN-LSTM (Single Flow + Temporal Window)' : activeProfile === 'CIC-IDS2017'
                ? 'Feature-sequence CNN-LSTM (12 Classes, Single Flow)'
                : 'Temporal CNN-LSTM (17 Classes, Window 8 Flows)'}
            </p>
          </div>
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Cpu className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase tracking-wider">System & WebSocket State</p>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  isMonitoring ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'
                }`}
              />
              <span className="text-lg font-bold text-slate-100">
                {isMonitoring ? `MONITORING (${liveStatus?.data_source})` : 'STANDBY / READY'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              WebSocket: {wsConnected ? 'Connected (Realtime)' : 'Disconnected'} •{' '}
              {traffic?.live_validation_status || 'READY FOR LINUX VALIDATION'}
            </p>
          </div>
          <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Network className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase tracking-wider">CPU Inference Latency</p>
            <p className="text-lg font-bold text-slate-100 mt-1">
              {latencyAvg.toFixed(2)} ms{' '}
              <span className="text-xs font-normal text-slate-400">(P95: {latencyP95.toFixed(2)} ms)</span>
            </p>
            <p className="text-xs text-slate-400 mt-0.5">
              TorchScript CPU • model.eval() + inference_mode()
            </p>
          </div>
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Gauge className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* 4 Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>TỔNG PACKETS & FLOWS</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">
            {totalFlows.toLocaleString()} <span className="text-sm font-normal text-slate-400">flows</span>
          </p>
          <p className="text-xs text-slate-400 mt-1">
            Packets đã xử lý: <span className="text-slate-200 font-medium">{totalPackets.toLocaleString()}</span>
          </p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>TỔNG SỐ AI INFERENCES</span>
            <Cpu className="w-4 h-4 text-blue-400" />
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">{totalInferences.toLocaleString()}</p>
          <p className="text-xs text-slate-400 mt-1">
            Đang đệm (Buffering):{' '}
            <span className="text-amber-300 font-medium">{traffic?.total_buffering || 0}</span>
          </p>
        </div>

        <div className="bg-[#111827] border border-red-500/30 rounded-xl p-4">
          <div className="flex items-center justify-between text-red-400 text-xs font-medium">
            <span>CẢNH BÁO TẤN CÔNG (ATTACK)</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold text-red-400 mt-2">{totalAttacks.toLocaleString()}</p>
          <p className="text-xs text-slate-400 mt-1">
            Tỷ lệ ATTACK:{' '}
            <span className="text-red-300 font-semibold">
              {((traffic?.attack_ratio || 0) * 100).toFixed(1)}%
            </span>
          </p>
        </div>

        <div className="bg-[#111827] border border-emerald-500/30 rounded-xl p-4">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-medium">
            <span>LƯU LƯỢNG BÌNH THƯỜNG (BENIGN)</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400 mt-2">{totalBenign.toLocaleString()}</p>
          <p className="text-xs text-slate-400 mt-1">
            Tỷ lệ BENIGN:{' '}
            <span className="text-emerald-300 font-semibold">
              {((traffic?.benign_ratio || 0) * 100).toFixed(1)}%
            </span>
          </p>
        </div>
      </div>

      {/* Charts Row: Attack Distribution & BENIGN/ATTACK Ratio */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                Phân bố các lớp dự đoán (Predicted Class Distribution)
              </h2>
              <p className="text-xs text-slate-400">
                Thống kê số lượng cảnh báo theo từng nhóm tấn công và lưu lượng BENIGN
              </p>
            </div>
          </div>

          {loading ? (
            <div className="h-64 flex items-center justify-center text-slate-400 text-sm">
              Đang tải biểu đồ phân bố...
            </div>
          ) : barData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-slate-500 text-sm">
              Chưa có dữ liệu suy luận. Hãy chạy Replay hoặc Live Monitoring.
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 10, right: 20, left: 0, bottom: 25 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="name"
                    stroke="#94a3b8"
                    fontSize={11}
                    angle={-18}
                    textAnchor="end"
                    interval={0}
                  />
                  <YAxis stroke="#94a3b8" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {barData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.isAttack ? '#ef4444' : '#10b981'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Tỷ lệ BENIGN / ATTACK</h2>
            <p className="text-xs text-slate-400">Quyết định bởi CNN-LSTM</p>
          </div>

          <div className="h-52 my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={78}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs border-t border-slate-800 pt-3">
            <div className="flex items-center justify-between bg-slate-900/70 px-3 py-2 rounded-lg">
              <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                BENIGN
              </span>
              <span className="font-mono text-slate-200">{totalBenign}</span>
            </div>
            <div className="flex items-center justify-between bg-slate-900/70 px-3 py-2 rounded-lg">
              <span className="flex items-center gap-1.5 text-red-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-red-400" />
                ATTACK
              </span>
              <span className="font-mono text-slate-200">{totalAttacks}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Timeline */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              Attack & Traffic Timeline
            </h2>
            <p className="text-xs text-slate-400">
              Diễn biến số lượng cảnh báo ATTACK và lưu lượng BENIGN theo mốc thời gian phát hiện
            </p>
          </div>
        </div>
        <div className="h-52">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={attackStats?.timeline || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time_bucket" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Area
                type="monotone"
                dataKey="attack_count"
                name="ATTACK"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.2}
              />
              <Area
                type="monotone"
                dataKey="benign_count"
                name="BENIGN"
                stroke="#06b6d4"
                fill="#06b6d4"
                fillOpacity={0.15}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Latest Alerts Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Cảnh báo và kết quả phát hiện mới nhất</h2>
            <p className="text-xs text-slate-400">10 bản ghi gần nhất từ cơ sở dữ liệu SQLite</p>
          </div>
          <button
            onClick={() => onNavigate('history')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
          >
            Xem toàn bộ lịch sử →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase">
                <th className="py-3 px-4">Thời gian</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Predicted Class</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Gaussian</th>
                <th className="py-3 px-4">Profile / Nguồn</th>
                <th className="py-3 px-4 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {(traffic?.latest_alerts || []).map((al) => (
                <tr key={al.alert_id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-4 font-mono text-slate-300">
                    {al.detected_at.replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-200">
                    {al.source_ip}:{al.source_port}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-200">
                    {al.destination_ip}:{al.destination_port}
                  </td>
                  <td className="py-2.5 px-4">
                    <ProtocolBadge protocol={al.protocol} />
                  </td>
                  <td className="py-2.5 px-4">
                    <StatusBadge status={al.detection_status} />
                  </td>
                  <td className="py-2.5 px-4 font-semibold text-slate-100">
                    {al.predicted_attack_type}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-cyan-300">
                    {(al.class_score * 100).toFixed(1)}%
                  </td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`font-mono px-2 py-0.5 rounded text-xs ${
                        al.gaussian_is_anomalous
                          ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          : 'text-slate-400'
                      }`}
                    >
                      {al.gaussian_anomaly_score.toFixed(1)}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 space-x-1.5">
                    <span className="text-slate-300 font-medium">{al.dataset_profile}</span>
                    <SourceBadge source={al.data_source} />
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono text-slate-400">
                    {al.inference_latency_ms.toFixed(2)} ms
                  </td>
                </tr>
              ))}
              {(!traffic?.latest_alerts || traffic.latest_alerts.length === 0) && (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-slate-500">
                    Chưa có cảnh báo nào được ghi nhận.
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
