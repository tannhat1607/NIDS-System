import {
  AttackStatsResponse,
  BeaconingResponse,
  DetectionAlert,
  ModelProfileInfo,
  MonitoringStatus,
  NetworkGraphResponse,
  NetworkInterfaceInfo,
  PaginatedAlertsResponse,
  ProfilePerformanceData,
  TrafficStats,
} from '../types/nids';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function requestJson<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
    ...options,
  });
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errBody = await response.json();
      if (errBody?.detail) {
        errorMessage = typeof errBody.detail === 'string' ? errBody.detail : JSON.stringify(errBody.detail);
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errorMessage);
  }
  return response.json() as Promise<T>;
}

export const nidsApi = {
  getHealth: () =>
    requestJson<{
      status: string;
      timestamp: string;
      os_platform: string;
      device: string;
      active_profile: string;
      loaded_profiles: string[];
      live_capture_validation: string;
      monitoring_active: boolean;
    }>('/api/health'),

  getProfiles: () =>
    requestJson<{ active_profile: string; profiles: ModelProfileInfo[] }>('/api/profiles'),

  selectProfile: (profile_id: string) =>
    requestJson<{
      active_profile: string;
      n_features: number;
      n_classes: number;
      window_size: number;
      stride: number;
    }>('/api/profiles/select', {
      method: 'POST',
      body: JSON.stringify({ profile_id }),
    }),

  getInterfaces: () =>
    requestJson<{ platform: string; interfaces: NetworkInterfaceInfo[] }>('/api/interfaces'),

  getMonitoringStatus: () => requestJson<MonitoringStatus>('/api/monitoring/status'),

  startMonitoring: (payload: {
    profile_id: string;
    data_source: string;
    interface?: string;
    file_path?: string;
    replay_delay_ms?: number;
    max_rows?: number;
  }) =>
    requestJson<MonitoringStatus>('/api/monitoring/start', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  stopMonitoring: () =>
    requestJson<MonitoringStatus>('/api/monitoring/stop', {
      method: 'POST',
    }),

  runSampleReplay: (profile_id: string, data_source: 'CSV_REPLAY' | 'PCAP_REPLAY') =>
    requestJson<{
      session_id: string;
      profile_id: string;
      data_source: string;
      file_name: string;
      packets_processed: number;
      flows_processed: number;
      inferences_completed: number;
      attack_count: number;
      benign_count: number;
      buffering_count: number;
      records: DetectionAlert[];
    }>(`/api/replay/sample?profile_id=${encodeURIComponent(profile_id)}&data_source=${encodeURIComponent(data_source)}`, {
      method: 'POST',
    }),

  uploadReplayFile: async (
    file: File,
    profile_id: string,
    data_source: 'CSV_REPLAY' | 'PCAP_REPLAY',
    max_rows = 200
  ) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('profile_id', profile_id);
    formData.append('data_source', data_source);
    formData.append('max_rows', String(max_rows));

    const response = await fetch(`${API_BASE}/api/replay/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      let msg = `HTTP ${response.status}`;
      try {
        const err = await response.json();
        if (err?.detail) msg = err.detail;
      } catch {
        // ignore
      }
      throw new Error(msg);
    }
    return response.json();
  },

  getTrafficStats: (dataset_profile?: string) => {
    const q = dataset_profile && dataset_profile !== 'ALL' ? `?dataset_profile=${encodeURIComponent(dataset_profile)}` : '';
    return requestJson<TrafficStats>(`/api/stats/traffic${q}`);
  },

  getAttackStats: (dataset_profile?: string) => {
    const q = dataset_profile && dataset_profile !== 'ALL' ? `?dataset_profile=${encodeURIComponent(dataset_profile)}` : '';
    return requestJson<AttackStatsResponse>(`/api/stats/attacks${q}`);
  },

  getAlerts: (params: {
    page?: number;
    page_size?: number;
    detection_status?: string;
    dataset_profile?: string;
    attack_type?: string;
    ip?: string;
    data_source?: string;
    start_time?: string;
    end_time?: string;
    search?: string;
  }) => {
    const sp = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'ALL') {
        sp.set(k, String(v));
      }
    });
    return requestJson<PaginatedAlertsResponse>(`/api/alerts?${sp.toString()}`);
  },

  getAlertDetail: (alert_id: string) =>
    requestJson<DetectionAlert>(`/api/alerts/${encodeURIComponent(alert_id)}`),

  getExportAlertsUrl: (params: {
    detection_status?: string;
    dataset_profile?: string;
    attack_type?: string;
    ip?: string;
  }) => {
    const sp = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v && v !== 'ALL') sp.set(k, v);
    });
    return `${API_BASE}/api/alerts/export?${sp.toString()}`;
  },

  getBeaconing: (only_suspected = false) =>
    requestJson<BeaconingResponse>(`/api/analysis/beaconing?only_suspected=${only_suspected}`),

  getNetworkGraph: () => requestJson<NetworkGraphResponse>('/api/analysis/graph'),

  getModelPerformance: () =>
    requestJson<Record<'CIC-IDS2017' | 'CIC-DDoS2019', ProfilePerformanceData>>('/api/performance'),
};
