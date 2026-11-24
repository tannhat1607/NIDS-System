import React, { useState } from 'react';
import {
  Activity,
  BarChart3,
  History,
  Radio,
  Share2,
  Shield,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useNidsWebSocket } from './hooks/useNidsWebSocket';
import { OverviewPage } from './pages/OverviewPage';
import { LiveMonitoringPage } from './pages/LiveMonitoringPage';
import { AttackHistoryPage } from './pages/AttackHistoryPage';
import { BeaconingGraphPage } from './pages/BeaconingGraphPage';
import { ModelPerformancePage } from './pages/ModelPerformancePage';

type PageId = 'overview' | 'live' | 'history' | 'analysis' | 'performance';

export function App() {
  const [activePage, setActivePage] = useState<PageId>('overview');
  const { connected, liveStatus, liveFeed, clearLiveFeed } = useNidsWebSocket();

  const navItems: Array<{ id: PageId; label: string; sub: string; icon: React.ReactNode }> = [
    {
      id: 'overview',
      label: '1. Overview',
      sub: 'SOC Summary & Timeline',
      icon: <Activity className="w-4 h-4" />,
    },
    {
      id: 'live',
      label: '2. Live Monitoring',
      sub: 'Capture & Replay Stream',
      icon: <Radio className="w-4 h-4" />,
    },
    {
      id: 'history',
      label: '3. Attack History',
      sub: 'SQLite Log & CSV Export',
      icon: <History className="w-4 h-4" />,
    },
    {
      id: 'analysis',
      label: '4. Beaconing & Graph',
      sub: 'Periodic & Topology Signals',
      icon: <Share2 className="w-4 h-4" />,
    },
    {
      id: 'performance',
      label: '5. Model Performance',
      sub: 'Colab Artifact Metrics',
      icon: <BarChart3 className="w-4 h-4" />,
    },
  ];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col lg:flex-row">
      {/* Sidebar Navigation */}
      <aside className="w-full lg:w-64 bg-[#0d1322] border-b lg:border-b-0 lg:border-r border-slate-800 shrink-0 flex flex-col justify-between">
        <div>
          {/* Brand Header */}
          <div className="p-5 border-b border-slate-800 flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="text-sm font-bold tracking-wide text-slate-100 block">
                CNN-LSTM NIDS
              </span>
              <span className="text-[11px] text-cyan-400 font-medium block">
                Realtime Intrusion Detection
              </span>
            </div>
          </div>

          {/* Navigation Menu */}
          <nav className="p-3 space-y-1.5">
            {navItems.map((item) => {
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-left transition ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div className={isActive ? 'text-cyan-400' : 'text-slate-400'}>
                    {item.icon}
                  </div>
                  <div>
                    <div className="text-xs font-bold">{item.label}</div>
                    <div className="text-[10px] text-slate-400">{item.sub}</div>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer System Telemetry */}
        <div className="p-4 border-t border-slate-800 space-y-2.5 text-xs">
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Active Profile:</span>
              <span className="font-mono font-bold text-cyan-300">
                {liveStatus?.active_profile || 'CIC-IDS2017'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Inference Device:</span>
              <span className="font-mono text-slate-200">CPU (TorchScript)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">WS Stream:</span>
              <span
                className={`inline-flex items-center gap-1 font-semibold ${
                  connected ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {connected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
                {connected ? 'LIVE' : 'OFFLINE'}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
        {activePage === 'overview' && (
          <OverviewPage
            wsConnected={connected}
            liveStatus={liveStatus}
            onNavigate={(p) => setActivePage(p as PageId)}
          />
        )}
        {activePage === 'live' && (
          <LiveMonitoringPage
            wsConnected={connected}
            liveStatus={liveStatus}
            liveFeed={liveFeed}
            clearLiveFeed={clearLiveFeed}
          />
        )}
        {activePage === 'history' && <AttackHistoryPage />}
        {activePage === 'analysis' && <BeaconingGraphPage />}
        {activePage === 'performance' && <ModelPerformancePage />}
      </main>
    </div>
  );
}
export default App;
