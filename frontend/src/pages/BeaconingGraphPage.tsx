import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  GitBranch,
  Info,
  RadioTower,
  RefreshCw,
  Share2,
} from 'lucide-react';
import { nidsApi } from '../services/api';
import { BeaconingResponse, GraphNodeInfo, NetworkGraphResponse } from '../types/nids';
import { ProtocolBadge } from '../components/StatusBadge';

export function BeaconingGraphPage() {
  const [beaconing, setBeaconing] = useState<BeaconingResponse | null>(null);
  const [graph, setGraph] = useState<NetworkGraphResponse | null>(null);
  const [onlySuspected, setOnlySuspected] = useState<boolean>(false);
  const [selectedNode, setSelectedNode] = useState<GraphNodeInfo | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const loadAnalysis = async () => {
    setLoading(true);
    try {
      const [bRes, gRes] = await Promise.all([
        nidsApi.getBeaconing(onlySuspected),
        nidsApi.getNetworkGraph(),
      ]);
      setBeaconing(bRes);
      setGraph(gRes);
      if (gRes.nodes.length > 0 && !selectedNode) {
        setSelectedNode(gRes.nodes[0]);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalysis();
  }, [onlySuspected]);

  // Tính tọa độ SVG hình tròn cho tối đa 16 node nổi bật nhất để trực quan hóa đồ thị giao tiếp mạng
  const displayNodes = (graph?.nodes || []).slice(0, 16);
  const nodePositions = new Map<string, { x: number; y: number }>();
  const cx = 300;
  const cy = 180;
  const radius = 125;

  displayNodes.forEach((n, idx) => {
    if (idx === 0 && displayNodes.length > 2) {
      nodePositions.set(n.ip, { x: cx, y: cy });
    } else {
      const angle = (2 * Math.PI * idx) / Math.max(1, displayNodes.length);
      nodePositions.set(n.ip, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      });
    }
  });

  const displayEdges = (graph?.edges || []).filter(
    (e) => nodePositions.has(e.source) && nodePositions.has(e.target)
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Share2 className="w-5 h-5 text-cyan-400" />
            Beaconing Heuristic & NetworkX Communication Graph
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Phân tích bổ trợ: Gaussian Anomaly Score, thống kê chu kỳ kết nối (Suspected Beaconing) và cấu trúc đồ thị giao tiếp mạng
          </p>
        </div>

        <button
          onClick={loadAnalysis}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Làm mới phân tích
        </button>
      </div>

      {/* Advisory Note */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold text-amber-300">Nguyên tắc phân tích bổ trợ (Auxiliary Signals): </span>
          Gaussian Mahalanobis distance, Beaconing thống kê (Mean interval, Std, Coefficient of Variation) và NetworkX Graph
          chỉ đóng vai trò tín hiệu nghi ngờ bổ trợ cho chuyên viên SOC. Kết quả định kỳ chỉ được đánh dấu là{' '}
          <code className="text-amber-200">SUSPECTED_BEACONING</code> (không kết luận cứng là botnet và không tự động phủ quyết CNN-LSTM).
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400">SUSPECTED BEACONING PAIRS</span>
          <p className="text-2xl font-bold text-amber-400 mt-1">
            {beaconing?.suspected_count || 0}{' '}
            <span className="text-xs font-normal text-slate-400">
              / {beaconing?.total_candidates || 0} cặp kết nối
            </span>
          </p>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400">GRAPH NODES & EDGES</span>
          <p className="text-2xl font-bold text-cyan-400 mt-1">
            {graph?.total_nodes || 0} <span className="text-sm font-normal text-slate-400">IPs</span> •{' '}
            {graph?.total_edges || 0} <span className="text-sm font-normal text-slate-400">Edges</span>
          </p>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400">GRAPH RECIPROCITY</span>
          <p className="text-2xl font-bold text-slate-100 mt-1">
            {((graph?.reciprocity || 0) * 100).toFixed(1)}%
          </p>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400">TOPOLOGY PATTERN</span>
          <p className="text-lg font-bold text-amber-300 mt-1 font-mono">
            {graph?.topology_pattern || 'EMPTY'}
          </p>
        </div>
      </div>

      {/* Graph Visualization + Node Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-cyan-400" />
                Đồ thị giao tiếp mạng (NetworkX Topology View)
              </h2>
              <p className="text-xs text-slate-400">
                Node đỏ: có flow ATTACK • Node cam: Hub / Gaussian cao • Nhấn vào từng Node để xem chi tiết
              </p>
            </div>
          </div>

          <div className="bg-[#090d16] border border-slate-800 rounded-xl overflow-hidden flex items-center justify-center">
            {displayNodes.length === 0 ? (
              <div className="h-80 flex items-center justify-center text-slate-500 text-xs">
                Chưa có node giao tiếp mạng trong đồ thị.
              </div>
            ) : (
              <svg viewBox="0 0 600 360" className="w-full h-80">
                {displayEdges.map((edge, idx) => {
                  const s = nodePositions.get(edge.source)!;
                  const t = nodePositions.get(edge.target)!;
                  const isAttackEdge = edge.attack_count > 0;
                  return (
                    <g key={idx}>
                      <line
                        x1={s.x}
                        y1={s.y}
                        x2={t.x}
                        y2={t.y}
                        stroke={isAttackEdge ? '#ef4444' : '#334155'}
                        strokeWidth={Math.min(4, 1 + Math.log2(edge.weight + 1))}
                        strokeOpacity={0.75}
                      />
                    </g>
                  );
                })}

                {displayNodes.map((node) => {
                  const pos = nodePositions.get(node.ip)!;
                  const fill =
                    node.attack_flows > 0
                      ? '#ef4444'
                      : node.is_hub
                      ? '#f59e0b'
                      : '#06b6d4';
                  const isSelected = selectedNode?.ip === node.ip;
                  return (
                    <g
                      key={node.ip}
                      onClick={() => setSelectedNode(node)}
                      className="cursor-pointer"
                    >
                      <circle
                        cx={pos.x}
                        cy={pos.y}
                        r={node.is_hub ? 16 : 12}
                        fill={fill}
                        fillOpacity={0.25}
                        stroke={fill}
                        strokeWidth={isSelected ? 3 : 1.5}
                      />
                      <circle cx={pos.x} cy={pos.y} r={4} fill={fill} />
                      <text
                        x={pos.x}
                        y={pos.y + 24}
                        textAnchor="middle"
                        fill="#e2e8f0"
                        fontSize="10"
                        fontFamily="monospace"
                      >
                        {node.ip}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>
        </div>

        {/* Selected Node & Hub Details */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Chi tiết Node & Tín hiệu bất thường
          </h2>

          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block">Địa chỉ IP Node</span>
                <span className="text-base font-mono font-bold text-cyan-300">
                  {selectedNode.ip}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block">Degree Centrality</span>
                  <span className="font-mono font-bold text-slate-100">
                    {selectedNode.degree_centrality.toFixed(4)}
                  </span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block">Max Gaussian Score</span>
                  <span className="font-mono font-bold text-amber-300">
                    {selectedNode.max_gaussian_score.toFixed(2)}
                  </span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block">In / Out Degree</span>
                  <span className="font-mono text-slate-200">
                    {selectedNode.in_degree} in / {selectedNode.out_degree} out
                  </span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block">Attack / Benign Flows</span>
                  <span className="font-mono">
                    <span className="text-red-400 font-bold">{selectedNode.attack_flows}</span> /{' '}
                    <span className="text-emerald-400">{selectedNode.benign_flows}</span>
                  </span>
                </div>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">Dấu hiệu vai trò (Auxiliary Roles)</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedNode.roles.length > 0 ? (
                    selectedNode.roles.map((r) => (
                      <span
                        key={r}
                        className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-mono text-[11px]"
                      >
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500">NORMAL_ENDPOINT</span>
                  )}
                </div>
              </div>

              {selectedNode.attack_types.length > 0 && (
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Loại tấn công liên quan</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.attack_types.map((at) => (
                      <span
                        key={at}
                        className="px-2 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30 font-semibold text-[11px]"
                      >
                        {at}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500">Chọn một node trên đồ thị để xem chi tiết.</p>
          )}
        </div>
      </div>

      {/* Beaconing Candidates Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <RadioTower className="w-4 h-4 text-amber-400" />
              Danh sách kiểm tra kết nối định kỳ (Suspected Beaconing Connections)
            </h2>
            <p className="text-xs text-slate-400">
              Đánh giá dựa trên Connection Count, Mean Interval ($\mu$), Standard Deviation ($\sigma$) và Coefficient of Variation ($CV = \sigma/\mu$)
            </p>
          </div>

          <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={onlySuspected}
              onChange={(e) => setOnlySuspected(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-cyan-500"
            />
            Chỉ hiện Suspected Beaconing
          </label>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase">
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP:Port</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Connections</th>
                <th className="py-3 px-4">Mean Interval (s)</th>
                <th className="py-3 px-4">Std Dev (s)</th>
                <th className="py-3 px-4">Coeff. of Variation (CV)</th>
                <th className="py-3 px-4">Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    Đang tính toán thống kê Beaconing...
                  </td>
                </tr>
              ) : (
                (beaconing?.candidates || []).map((c, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 font-mono text-slate-200">{c.source_ip}</td>
                    <td className="py-2.5 px-4 font-mono text-slate-200">
                      {c.destination_ip}:{c.destination_port}
                    </td>
                    <td className="py-2.5 px-4">
                      <ProtocolBadge protocol={c.protocol} />
                    </td>
                    <td className="py-2.5 px-4 font-mono font-bold text-slate-100">
                      {c.connection_count}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-cyan-300">
                      {c.mean_interval.toFixed(3)}s
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300">
                      {c.std_interval.toFixed(3)}s
                    </td>
                    <td className="py-2.5 px-4 font-mono">
                      <span
                        className={
                          c.is_suspected ? 'text-amber-300 font-bold' : 'text-slate-400'
                        }
                      >
                        {c.coefficient_of_variation.toFixed(4)}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      {c.is_suspected ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                          <AlertTriangle className="w-3 h-3" />
                          SUSPECTED_BEACONING
                        </span>
                      ) : (
                        <span className="px-2.5 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400">
                          IRREGULAR
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
              {!loading && (!beaconing?.candidates || beaconing.candidates.length === 0) && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    Chưa có cặp IP nào đạt số kết nối tối thiểu (&ge; 5 kết nối). Hãy chạy PCAP Replay hoặc CSV Replay.
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
