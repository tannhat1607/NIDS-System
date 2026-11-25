import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Award,
  BarChart3,
  CheckCircle2,
  Layers,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { nidsApi } from '../services/api';
import { ProfilePerformanceData } from '../types/nids';

export function ModelPerformancePage() {
  const [perfMap, setPerfMap] = useState<Record<'CIC-IDS2017' | 'CIC-DDoS2019', ProfilePerformanceData> | null>(null);
  const [activeTab, setActiveTab] = useState<'CIC-IDS2017' | 'CIC-DDoS2019'>('CIC-IDS2017');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    nidsApi
      .getModelPerformance()
      .then((res) => setPerfMap(res))
      .catch((err) => setError(err?.message || 'Không thể tải dữ liệu hiệu năng từ artifact.'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-sm">
        Đang đọc kết quả đánh giá trực tiếp từ artifact Google Colab...
      </div>
    );
  }

  if (error || !perfMap) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 text-red-300 text-sm">
        {error || 'Không tìm thấy dữ liệu đánh giá mô hình.'}
      </div>
    );
  }

  const current = perfMap[activeTab];
  const cm = current.confusion_matrix;

  return (
    <div className="space-y-6">
      {/* Header & Dataset Switcher */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Offline Model Evaluation & Artifact Performance (Colab Exports)
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Đọc trực tiếp từ file artifact đã export (`test_metrics`, `classification_report.csv`, `confusion_matrix.csv`, `model_comparison.csv`, `pipeline_comparison.csv`)
          </p>
        </div>

        <div className="inline-flex rounded-lg bg-slate-900 p-1 border border-slate-800">
          <button
            onClick={() => setActiveTab('CIC-IDS2017')}
            className={`px-4 py-1.5 rounded-md text-xs font-bold transition ${
              activeTab === 'CIC-IDS2017'
                ? 'bg-cyan-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CIC-IDS2017 (70 Features, 12 Classes)
          </button>
          <button
            onClick={() => setActiveTab('CIC-DDoS2019')}
            className={`px-4 py-1.5 rounded-md text-xs font-bold transition ${
              activeTab === 'CIC-DDoS2019'
                ? 'bg-cyan-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CIC-DDoS2019 V2 (8x66 Temporal, 17 Classes)
          </button>
        </div>
      </div>

      <p className="text-xs text-amber-300">AUTO hybrid performance has not been evaluated on a shared labeled test set. Metrics below are for individual models.</p>
      {/* Important Distinction Alert for CIC-DDoS2019 */}
      {activeTab === 'CIC-DDoS2019' ? (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-200">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-bold text-amber-300 uppercase">
              Phân biệt rõ Kết quả Nhị phân (BENIGN vs ATTACK) và Phân loại Đa lớp (17-Class Multiclass) trên tập Test Offline
            </p>
            <p className="text-slate-300">
              • <strong>Offline Binary Detection (BENIGN vs ATTACK):</strong> Binary Accuracy ={' '}
              <strong className="text-emerald-300">99.69%</strong>, Attack Precision ={' '}
              <strong className="text-emerald-300">99.86%</strong>, Attack Recall ={' '}
              <strong className="text-emerald-300">99.81%</strong>, Binary F1 ={' '}
              <strong className="text-emerald-300">99.84%</strong>, False Positive Rate ={' '}
              <strong className="text-amber-300">3.33%</strong>.
            </p>
            <p className="text-slate-300">
              • <strong>Offline 17-Class Multiclass Classification:</strong> Multiclass Accuracy ={' '}
              <strong className="text-cyan-300">55.36%</strong>, Macro-F1 ={' '}
              <strong className="text-cyan-300">52.43%</strong> (do các biến thể tấn công khuếch đại UDP/DrDoS có hành vi thống kê chồng lấn cao).
              Các con số này là kết quả đánh giá trên tập Test offline, không phải cam kết độ chính xác tuyệt đối trên mọi môi trường mạng realtime.
            </p>
          </div>
        </div>
      ) : (
        <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-200">
          <CheckCircle2 className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-bold text-cyan-300">
              CIC-IDS2017 — Feature-sequence CNN-LSTM (Best Epoch: {current.best_epoch})
            </p>
            <p className="text-slate-300 mt-0.5">{current.evaluation_note}</p>
          </div>
        </div>
      )}

      {/* Metrics Summary Cards */}
      {activeTab === 'CIC-IDS2017' ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
            <span className="text-xs text-slate-400">MULTICLASS ACCURACY (12 LỚP)</span>
            <p className="text-2xl font-bold text-cyan-400 mt-1">
              {(current.multiclass_metrics.accuracy * 100).toFixed(2)}%
            </p>
          </div>
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
            <span className="text-xs text-slate-400">TEST MACRO-F1</span>
            <p className="text-2xl font-bold text-emerald-400 mt-1">
              {(current.multiclass_metrics.macro_f1 * 100).toFixed(2)}%
            </p>
          </div>
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
            <span className="text-xs text-slate-400">MACRO PRECISION</span>
            <p className="text-2xl font-bold text-slate-100 mt-1">
              {(current.multiclass_metrics.macro_precision * 100).toFixed(2)}%
            </p>
          </div>
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
            <span className="text-xs text-slate-400">BALANCED ACCURACY (MACRO RECALL)</span>
            <p className="text-2xl font-bold text-slate-100 mt-1">
              {(current.multiclass_metrics.macro_recall * 100).toFixed(2)}%
            </p>
          </div>
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
            <span className="text-xs text-slate-400">BINARY FALSE POSITIVE RATE</span>
            <p className="text-2xl font-bold text-amber-300 mt-1">
              {((current.multiclass_metrics.false_positive_rate || 0) * 100).toFixed(2)}%
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Multiclass vs Binary separated clearly */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-[#111827] border border-cyan-500/30 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-300 uppercase">
                  1. Multiclass Classification (17 Classes Offline Test)
                </span>
                <Layers className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-900 p-3 rounded-lg">
                  <span className="text-[11px] text-slate-400 block">17-Class Accuracy</span>
                  <span className="text-lg font-bold text-cyan-400">
                    {(current.multiclass_metrics.accuracy * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg">
                  <span className="text-[11px] text-slate-400 block">Macro-F1</span>
                  <span className="text-lg font-bold text-cyan-300">
                    {(current.multiclass_metrics.macro_f1 * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg">
                  <span className="text-[11px] text-slate-400 block">Macro Precision</span>
                  <span className="text-lg font-bold text-slate-200">
                    {(current.multiclass_metrics.macro_precision * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg">
                  <span className="text-[11px] text-slate-400 block">Macro Recall</span>
                  <span className="text-lg font-bold text-slate-200">
                    {(current.multiclass_metrics.macro_recall * 100).toFixed(2)}%
                  </span>
                </div>
              </div>
            </div>

            {current.binary_metrics && (
              <div className="bg-[#111827] border border-emerald-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-300 uppercase">
                    2. Binary Attack Detection (BENIGN vs ATTACK Offline Test)
                  </span>
                  <Award className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                  <div className="bg-slate-900 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400 block">Binary Accuracy</span>
                    <span className="text-lg font-bold text-emerald-400">
                      {(current.binary_metrics.binary_accuracy * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400 block">Attack Precision</span>
                    <span className="text-lg font-bold text-slate-100">
                      {(current.binary_metrics.attack_precision * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400 block">Attack Recall</span>
                    <span className="text-lg font-bold text-slate-100">
                      {(current.binary_metrics.attack_recall * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400 block">Binary F1</span>
                    <span className="text-lg font-bold text-emerald-300">
                      {(current.binary_metrics.binary_f1 * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400 block">False Positive Rate</span>
                    <span className="text-lg font-bold text-amber-300">
                      {(current.binary_metrics.false_positive_rate * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Per-Class Performance Chart & Table */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-1">
            Biểu đồ Precision / Recall / F1-Score theo từng lớp ({current.n_classes} lớp)
          </h2>
          <p className="text-xs text-slate-400 mb-4">
            Trích xuất từ `classification_report.csv`
          </p>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={current.per_class}
                margin={{ top: 10, right: 15, left: 0, bottom: 45 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="class_name"
                  stroke="#94a3b8"
                  fontSize={10}
                  angle={-30}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis stroke="#94a3b8" fontSize={11} domain={[0, 1]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="precision" name="Precision" fill="#06b6d4" />
                <Bar dataKey="recall" name="Recall" fill="#3b82f6" />
                <Bar dataKey="f1_score" name="F1-Score" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-slate-800">
            <h2 className="text-sm font-semibold text-slate-200">
              Bảng chi tiết Per-Class Classification Report
            </h2>
          </div>
          <div className="overflow-y-auto max-h-80">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="sticky top-0 bg-slate-900 text-slate-400 border-b border-slate-800 uppercase">
                <tr>
                  <th className="py-2.5 px-4">Class Name</th>
                  <th className="py-2.5 px-4">Precision</th>
                  <th className="py-2.5 px-4">Recall</th>
                  <th className="py-2.5 px-4">F1-Score</th>
                  <th className="py-2.5 px-4 text-right">Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {current.per_class.map((cls) => (
                  <tr key={cls.class_name} className="hover:bg-slate-800/40">
                    <td className="py-2 px-4 font-semibold text-slate-200">{cls.class_name}</td>
                    <td className="py-2 px-4 font-mono text-cyan-300">
                      {(cls.precision * 100).toFixed(2)}%
                    </td>
                    <td className="py-2 px-4 font-mono text-blue-300">
                      {(cls.recall * 100).toFixed(2)}%
                    </td>
                    <td className="py-2 px-4 font-mono text-emerald-300 font-bold">
                      {(cls.f1_score * 100).toFixed(2)}%
                    </td>
                    <td className="py-2 px-4 font-mono text-right text-slate-300">
                      {cls.support.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Confusion Matrix */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-slate-200 mb-1">
          Ma trận nhầm lẫn (Confusion Matrix — {current.dataset})
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Hàng: Nhãn thực tế (Actual) • Cột: Nhãn dự đoán (Predicted)
        </p>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[11px] font-mono">
            <thead>
              <tr>
                <th className="p-2 bg-slate-900 border border-slate-800 text-slate-400 text-left">
                  Actual \ Pred
                </th>
                {cm.labels.map((lbl) => (
                  <th
                    key={lbl}
                    className="p-2 bg-slate-900 border border-slate-800 text-slate-300 text-center"
                  >
                    {lbl}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cm.matrix.map((row, rIdx) => {
                const rowSum = Math.max(1, row.reduce((a, b) => a + b, 0));
                return (
                  <tr key={cm.labels[rIdx]}>
                    <td className="p-2 bg-slate-900 border border-slate-800 font-sans font-semibold text-slate-200 whitespace-nowrap">
                      {cm.labels[rIdx]}
                    </td>
                    {row.map((val, cIdx) => {
                      const isDiag = rIdx === cIdx;
                      const ratio = val / rowSum;
                      let bg = 'bg-slate-950 text-slate-500';
                      if (val > 0) {
                        if (isDiag) {
                          bg =
                            ratio > 0.5
                              ? 'bg-emerald-500/25 text-emerald-200 font-bold'
                              : 'bg-cyan-500/20 text-cyan-200';
                        } else {
                          bg =
                            ratio > 0.15
                              ? 'bg-red-500/25 text-red-200 font-bold'
                              : 'bg-amber-500/10 text-amber-200';
                        }
                      }
                      return (
                        <td
                          key={cIdx}
                          className={`p-2 border border-slate-800 text-center ${bg}`}
                        >
                          {val}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model Comparison & Pipeline Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800">
            <h2 className="text-sm font-semibold text-slate-200">
              So sánh kiến trúc mô hình trên Google Colab (Model Comparison)
            </h2>
          </div>
          <div className="overflow-x-auto">
            {activeTab === 'CIC-IDS2017' ? (
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase">
                  <tr>
                    <th className="py-2.5 px-4">Model</th>
                    <th className="py-2.5 px-4">Val Macro-F1</th>
                    <th className="py-2.5 px-4">Test Macro-F1</th>
                    <th className="py-2.5 px-4">Test Accuracy</th>
                    <th className="py-2.5 px-4">Best Epoch</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {current.model_comparison.map((m: any) => (
                    <tr
                      key={m.model}
                      className={
                        m.model === 'CNN-LSTM'
                          ? 'bg-cyan-500/10 font-semibold'
                          : 'hover:bg-slate-800/40'
                      }
                    >
                      <td className="py-2.5 px-4 text-slate-100">{m.model}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-300">
                        {(Number(m.val_macro_f1) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-emerald-300">
                        {(Number(m.test_macro_f1) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-cyan-300">
                        {(Number(m.test_accuracy) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300">{m.best_epoch}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase">
                  <tr>
                    <th className="py-2.5 px-4">Model</th>
                    <th className="py-2.5 px-4">Val 17-Class Acc</th>
                    <th className="py-2.5 px-4">Val Macro-F1</th>
                    <th className="py-2.5 px-4">Binary Acc</th>
                    <th className="py-2.5 px-4">P50 / P95 (ms)</th>
                    <th className="py-2.5 px-4">Params</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {current.model_comparison.map((m: any) => (
                    <tr
                      key={m.model}
                      className={
                        m.model === 'CNN-LSTM'
                          ? 'bg-cyan-500/10 font-semibold'
                          : 'hover:bg-slate-800/40'
                      }
                    >
                      <td className="py-2.5 px-4 text-slate-100">{m.model}</td>
                      <td className="py-2.5 px-4 font-mono text-cyan-300">
                        {(Number(m.multiclass_accuracy) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-emerald-300">
                        {(Number(m.macro_f1) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-200">
                        {(Number(m.binary_accuracy) * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300">
                        {Number(m.latency_p50_ms).toFixed(2)} / {Number(m.latency_p95_ms).toFixed(2)}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400">
                        {Number(m.parameters).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Pipeline Comparison or Training History */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
          {activeTab === 'CIC-DDoS2019' ? (
            <>
              <div className="px-5 py-4 border-b border-slate-800">
                <h2 className="text-sm font-semibold text-slate-200">
                  So sánh Pipeline kết hợp Gaussian vs CNN-LSTM (`pipeline_comparison.csv`)
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase">
                    <tr>
                      <th className="py-2.5 px-4">Pipeline</th>
                      <th className="py-2.5 px-4">Binary Acc</th>
                      <th className="py-2.5 px-4">Precision</th>
                      <th className="py-2.5 px-4">Recall</th>
                      <th className="py-2.5 px-4">F1</th>
                      <th className="py-2.5 px-4">FPR</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {current.pipeline_comparison.map((p: any) => (
                      <tr
                        key={p.pipeline}
                        className={
                          p.pipeline === 'CNN-LSTM Only'
                            ? 'bg-emerald-500/10 font-semibold'
                            : 'hover:bg-slate-800/40'
                        }
                      >
                        <td className="py-2.5 px-4 text-slate-100">{p.pipeline}</td>
                        <td className="py-2.5 px-4 font-mono text-cyan-300">
                          {(Number(p.binary_accuracy) * 100).toFixed(2)}%
                        </td>
                        <td className="py-2.5 px-4 font-mono text-slate-200">
                          {(Number(p.attack_precision) * 100).toFixed(2)}%
                        </td>
                        <td className="py-2.5 px-4 font-mono text-slate-200">
                          {(Number(p.attack_recall) * 100).toFixed(2)}%
                        </td>
                        <td className="py-2.5 px-4 font-mono text-emerald-300">
                          {(Number(p.binary_f1) * 100).toFixed(2)}%
                        </td>
                        <td className="py-2.5 px-4 font-mono text-amber-300">
                          {(Number(p.fpr) * 100).toFixed(2)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <>
              <div className="px-5 py-4 border-b border-slate-800">
                <h2 className="text-sm font-semibold text-slate-200">
                  Lịch sử huấn luyện theo Epoch (`training_history.csv`)
                </h2>
              </div>
              <div className="overflow-y-auto max-h-64">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase">
                    <tr>
                      <th className="py-2.5 px-4">Epoch</th>
                      <th className="py-2.5 px-4">Train Loss</th>
                      <th className="py-2.5 px-4">Validation Macro-F1</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {current.training_history.map((h) => (
                      <tr
                        key={h.epoch}
                        className={
                          h.epoch === current.best_epoch
                            ? 'bg-cyan-500/10 font-bold'
                            : 'hover:bg-slate-800/40'
                        }
                      >
                        <td className="py-2 px-4 font-mono text-slate-200">
                          Epoch {h.epoch} {h.epoch === current.best_epoch ? '(Best)' : ''}
                        </td>
                        <td className="py-2 px-4 font-mono text-slate-300">
                          {h.train_loss.toFixed(4)}
                        </td>
                        <td className="py-2 px-4 font-mono text-emerald-300">
                          {(h.val_macro_f1 * 100).toFixed(2)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
