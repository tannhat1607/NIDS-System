import React, { useEffect, useState } from 'react';
import {
  Activity,
  BarChart3,
  History,
  Moon,
  Radio,
  Share2,
  Shield,
  Sun,
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
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('nids-theme');
    return saved === 'light' ? 'light' : 'dark';
  });
  const { connected, liveStatus, liveFeed, clearLiveFeed } = useNidsWebSocket();

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'light') {
      root.classList.add('light');
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
      root.classList.remove('light');
    }
    localStorage.setItem('nids-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

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
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col lg:flex-row relative overflow-x-hidden">
      {/* Ambient Gradient Depth Orbs behind Glass Panels (Vision UI Cosmic Cobalt Glow) */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div className="absolute -top-24 left-1/4 w-[34rem] h-[34rem] rounded-full bg-[#0075ff]/25 blur-[130px]" />
        <div className="absolute top-1/3 -right-20 w-[32rem] h-[32rem] rounded-full bg-[#0052d4]/25 blur-[130px]" />
        <div className="absolute -bottom-24 left-1/3 w-[30rem] h-[30rem] rounded-full bg-[#21d4fd]/15 blur-[120px]" />
      </div>

      {/* Vision UI Floating Sidebar Navigation */}
      <aside className="w-full lg:w-64 lg:m-4 lg:rounded-[20px] bg-[#0d1322] border-b lg:border border-slate-800 shrink-0 flex flex-col justify-between relative z-10">
        <div>
          {/* Brand Header with Vision UI Gradient Divider */}
          <div className="p-5 flex items-center justify-center gap-3">
            <div className="p-2 rounded-xl bg-[#0075ff] text-white shadow-[0_4px_14px_rgba(0,117,255,0.5)]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="text-xs font-extrabold tracking-[0.14em] uppercase text-slate-100 block">
                VISION NIDS UI
              </span>
              <span className="text-[10px] text-cyan-400 font-medium block">
                CNN-LSTM Security Center
              </span>
            </div>
          </div>
          <div
            className="h-px mx-4 mb-2"
            style={{
              background:
                'linear-gradient(90deg, rgba(224,225,226,0) 0%, rgba(224,225,226,0.25) 50%, rgba(224,225,226,0) 100%)',
            }}
          />

          {/* Navigation Menu with Vision UI Electric Blue Icon Badges */}
          <nav className="p-3 space-y-2">
            {navItems.map((item) => {
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-[15px] text-left transition-all ${
                    isActive
                      ? theme === 'light'
                        ? 'bg-white/95 text-slate-900 shadow-[0_8px_20px_rgba(0,117,255,0.12)] border border-blue-200/80'
                        : 'bg-[#1a1f37]/90 text-white shadow-[0_10px_20px_rgba(0,0,0,0.25)] border border-white/10'
                      : theme === 'light'
                      ? 'text-slate-600 hover:bg-white/60 hover:text-slate-900 border border-transparent'
                      : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div
                    className={`w-8 h-8 rounded-xl flex items-center justify-center transition-all ${
                      isActive
                        ? 'bg-[#0075ff] text-white shadow-[0_4px_12px_rgba(0,117,255,0.45)]'
                        : theme === 'light'
                        ? 'bg-blue-50 text-[#0075ff] border border-blue-100'
                        : 'bg-[#1a1f37] text-[#0075ff]'
                    }`}
                  >
                    {item.icon}
                  </div>
                  <div>
                    <div
                      className={`text-xs font-bold ${
                        isActive
                          ? theme === 'light'
                            ? 'text-slate-900'
                            : 'text-white'
                          : ''
                      }`}
                    >
                      {item.label}
                    </div>
                    <div
                      className={`text-[10px] ${
                        isActive
                          ? theme === 'light'
                            ? 'text-slate-500'
                            : 'text-slate-300'
                          : 'text-slate-400'
                      }`}
                    >
                      {item.sub}
                    </div>
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
                {liveStatus?.active_profile || 'AUTO'}
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
      <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto relative z-10">
        {/* Top-Right Theme Toggle Icon Button */}
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Chuyển sang Light Mode' : 'Chuyển sang Dark Mode'}
          aria-label="Toggle Light/Dark Mode"
          className="fixed top-4 right-4 z-50 p-2.5 rounded-full bg-[#111827] hover:bg-slate-800 border border-slate-700 text-slate-200 shadow-lg transition"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-slate-700" />
          )}
        </button>

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
