import React, { useEffect, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  Filter,
  History,
  Search,
  X,
} from 'lucide-react';
import { nidsApi } from '../services/api';
import { DetectionAlert, PaginatedAlertsResponse } from '../types/nids';
import { ProtocolBadge, SourceBadge, StatusBadge } from '../components/StatusBadge';

export function AttackHistoryPage() {
  const [data, setData] = useState<PaginatedAlertsResponse | null>(null);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [profileFilter, setProfileFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('');
  const [ipFilter, setIpFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<DetectionAlert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await nidsApi.getAlerts({
        page,
        page_size: pageSize,
        detection_status: statusFilter,
        dataset_profile: profileFilter,
        data_source: sourceFilter,
        attack_type: attackTypeFilter || undefined,
        ip: ipFilter || undefined,
        search: searchQuery || undefined,
      });
      setData(res);
    } catch (err: any) {
      setError(err?.message || 'Lỗi tải lịch sử cảnh báo.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, statusFilter, profileFilter, sourceFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAlerts();
  };

  const exportUrl = nidsApi.getExportAlertsUrl({
    detection_status: statusFilter,
    dataset_profile: profileFilter,
    attack_type: attackTypeFilter || undefined,
    ip: ipFilter || undefined,
  });

  return (
    <div className="space-y-6">
      {/* Header & Export */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" />
            Attack & Detection History (SQLite Log)
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Tra cứu, lọc theo IP, loại tấn công, model profile, nguồn dữ liệu và xuất báo cáo CSV
          </p>
        </div>

        <a
          href={exportUrl}
          download="nids_alerts_export.csv"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow transition"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </a>
      </div>

      {/* Filter Bar */}
      <form
        onSubmit={handleSearchSubmit}
        className="bg-[#111827] border border-slate-800 rounded-xl p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3"
      >
        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Trạng thái (Status)</label>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="ALL">Tất cả (ALL)</option>
            <option value="ATTACK">ATTACK</option>
            <option value="BENIGN">BENIGN</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Model Profile</label>
          <select
            value={profileFilter}
            onChange={(e) => {
              setProfileFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="ALL">Tất cả Profiles</option>
            <option value="CIC-IDS2017">CIC-IDS2017</option>
            <option value="CIC-DDoS2019">CIC-DDoS2019</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Nguồn (Data Source)</label>
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
          >
            <option value="ALL">Tất cả nguồn</option>
            <option value="LIVE">LIVE</option>
            <option value="PCAP_REPLAY">PCAP_REPLAY</option>
            <option value="CSV_REPLAY">CSV_REPLAY</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Lọc địa chỉ IP</label>
          <input
            type="text"
            placeholder="VD: 172.16.0.1"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
          />
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Loại tấn công / Từ khóa</label>
          <input
            type="text"
            placeholder="VD: DDoS, PortScan, Bot..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100"
          />
        </div>

        <div className="flex items-end gap-2">
          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-semibold transition"
          >
            <Search className="w-3.5 h-3.5" />
            Tìm kiếm / Lọc
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-xl text-xs">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            Tổng số bản ghi khớp: <strong className="text-slate-100">{data?.total || 0}</strong>
          </span>
          <span>
            Trang {data?.page || 1} / {data?.total_pages || 1}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase">
                <th className="py-3 px-4">Thời gian phát hiện</th>
                <th className="py-3 px-4">Source IP:Port</th>
                <th className="py-3 px-4">Destination IP:Port</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Predicted Attack</th>
                <th className="py-3 px-4">Class Score</th>
                <th className="py-3 px-4">Attack Score</th>
                <th className="py-3 px-4">Gaussian</th>
                <th className="py-3 px-4">Profile / Nguồn</th>
                <th className="py-3 px-4 text-right">Chi tiết</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={11} className="py-10 text-center text-slate-400">
                    Đang truy vấn SQLite...
                  </td>
                </tr>
              ) : (
                (data?.items || []).map((item) => (
                  <tr key={item.alert_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-4 font-mono text-slate-300">
                      {item.detected_at.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-200">
                      {item.source_ip}:{item.source_port}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-200">
                      {item.destination_ip}:{item.destination_port}
                    </td>
                    <td className="py-2.5 px-4">
                      <ProtocolBadge protocol={item.protocol} />
                    </td>
                    <td className="py-2.5 px-4">
                      <StatusBadge status={item.detection_status} />
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-100">
                      {item.predicted_attack_type}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-cyan-300">
                      {(item.class_score * 100).toFixed(2)}%
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300">
                      {(item.attack_score * 100).toFixed(2)}%
                    </td>
                    <td className="py-2.5 px-4 font-mono">
                      <span
                        className={
                          item.gaussian_is_anomalous ? 'text-amber-300 font-semibold' : 'text-slate-400'
                        }
                      >
                        {item.gaussian_anomaly_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 space-x-1">
                      <span className="text-slate-300">{item.dataset_profile}</span>
                      <SourceBadge source={item.data_source} />
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedAlert(item)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Xem
                      </button>
                    </td>
                  </tr>
                ))
              )}
              {!loading && (!data?.items || data.items.length === 0) && (
                <tr>
                  <td colSpan={11} className="py-10 text-center text-slate-500">
                    Không tìm thấy bản ghi cảnh báo nào khớp bộ lọc.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-5 py-3.5 border-t border-slate-800 flex items-center justify-between text-xs">
          <button
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40"
          >
            <ChevronLeft className="w-4 h-4" />
            Trang trước
          </button>
          <span className="text-slate-400">
            Trang <strong className="text-slate-200">{data?.page || 1}</strong> /{' '}
            {data?.total_pages || 1}
          </span>
          <button
            disabled={!data || page >= data.total_pages}
            onClick={() => setPage((p) => p + 1)}
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40"
          >
            Trang tiếp
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#111827] border border-slate-700 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-100">
                  Chi tiết bản ghi phát hiện #{selectedAlert.alert_id}
                </h3>
                <p className="text-xs text-slate-400">
                  Session: {selectedAlert.monitoring_session} • Nguồn: {selectedAlert.data_source}
                </p>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Trạng thái quyết định</span>
                <div className="mt-1">
                  <StatusBadge status={selectedAlert.detection_status} />
                </div>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Loại tấn công dự đoán</span>
                <span className="text-sm font-bold text-slate-100 mt-1 block">
                  {selectedAlert.predicted_attack_type}
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Model Profile</span>
                <span className="text-sm font-bold text-cyan-400 mt-1 block">
                  {selectedAlert.dataset_profile}
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Source IP : Port</span>
                <span className="font-mono text-slate-200 mt-1 block">
                  {selectedAlert.source_ip}:{selectedAlert.source_port}
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Destination IP : Port</span>
                <span className="font-mono text-slate-200 mt-1 block">
                  {selectedAlert.destination_ip}:{selectedAlert.destination_port}
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Protocol</span>
                <div className="mt-1">
                  <ProtocolBadge protocol={selectedAlert.protocol} />
                </div>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Class Confidence Score</span>
                <span className="font-mono text-cyan-300 font-bold mt-1 block">
                  {(selectedAlert.class_score * 100).toFixed(4)}%
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Total Attack Softmax Score</span>
                <span className="font-mono text-red-300 font-bold mt-1 block">
                  {(selectedAlert.attack_score * 100).toFixed(4)}%
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Inference Latency</span>
                <span className="font-mono text-emerald-300 mt-1 block">
                  {selectedAlert.inference_latency_ms.toFixed(3)} ms
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 col-span-2">
                <span className="text-slate-400 block">
                  Gaussian Auxiliary Anomaly Score (Squared Mahalanobis)
                </span>
                <span className="font-mono text-slate-200 mt-1 block">
                  Score: <strong>{selectedAlert.gaussian_anomaly_score.toFixed(4)}</strong> / Threshold:{' '}
                  <strong>{selectedAlert.gaussian_threshold.toFixed(4)}</strong>{' '}
                  {selectedAlert.gaussian_is_anomalous ? (
                    <span className="text-amber-300 font-semibold">(ANOMALOUS SIGNAL)</span>
                  ) : (
                    <span className="text-emerald-400">(WITHIN NORMAL ENVELOPE)</span>
                  )}
                </span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Ground Truth (Nếu có)</span>
                <span className="font-mono text-slate-200 mt-1 block">
                  {selectedAlert.ground_truth_label || 'N/A (Unlabeled)'}
                </span>
              </div>
            </div>

            {selectedAlert.note && (
              <div className="text-xs bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-slate-300">
                Ghi chú: {selectedAlert.note}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
