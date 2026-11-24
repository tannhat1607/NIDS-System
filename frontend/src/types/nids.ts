export interface ModelProfileInfo {
  profile_id: string;
  display_name: string;
  description: string;
  dataset: string;
  architecture: string;
  model_name: string;
  n_features: number;
  n_classes: number;
  window_size: number;
  stride: number;
  max_window_seconds: number;
  gaussian_threshold: number;
  best_epoch: number;
  is_loaded: boolean;
  is_active: boolean;
  artifact_dir: string;
}

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  description: string;
  ip: string;
  mac: string;
  platform: string;
}

export interface DetectionAlert {
  alert_id: string;
  detected_at: string;
  flow_timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: number;
  detection_status: 'BENIGN' | 'ATTACK' | 'BUFFERING';
  predicted_attack_type: string;
  class_score: number;
  attack_score: number;
  gaussian_anomaly_score: number;
  gaussian_threshold: number;
  gaussian_is_anomalous: boolean;
  inference_latency_ms: number;
  dataset_profile: string;
  monitoring_session: string;
  data_source: 'LIVE' | 'CSV_REPLAY' | 'PCAP_REPLAY' | string;
  buffered_flows: number;
  required_window_size: number;
  ground_truth_label?: string | null;
  note?: string | null;
}

export interface MonitoringStatus {
  is_monitoring: boolean;
  data_source: string;
  active_profile: string;
  session_id: string;
  interface?: string | null;
  file_path?: string | null;
  started_at?: string | null;
  last_error?: string | null;
  packets_processed: number;
  flows_queued: number;
  flows_dropped: number;
  live_validation_status: string;
  current_session_id: string;
  total_flows_seen: number;
  total_inferences: number;
  total_attacks: number;
  total_benign: number;
  total_buffering: number;
  total_gaussian_anomalies: number;
  inference_coverage_ratio: number;
  latency_avg_ms: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  buffered_ips: Record<string, number>;
  recent_detections?: DetectionAlert[];
}

export interface TrafficStats {
  active_profile: string;
  is_monitoring: boolean;
  data_source: string;
  live_validation_status: string;
  packets_processed: number;
  total_flows_seen: number;
  total_inferences: number;
  total_attacks: number;
  total_benign: number;
  total_buffering: number;
  total_gaussian_anomalies: number;
  attack_ratio: number;
  benign_ratio: number;
  latency_avg_ms: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latest_alerts: DetectionAlert[];
}

export interface AttackDistributionItem {
  attack_type: string;
  detection_status: string;
  count: number;
  avg_score: number;
  avg_latency_ms: number;
}

export interface TimelineBucket {
  time_bucket: string;
  attack_count: number;
  benign_count: number;
}

export interface AttackStatsResponse {
  total_records: number;
  total_attacks: number;
  total_benign: number;
  attack_ratio: number;
  benign_ratio: number;
  distribution: AttackDistributionItem[];
  timeline: TimelineBucket[];
}

export interface PaginatedAlertsResponse {
  items: DetectionAlert[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface BeaconingCandidate {
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: number;
  connection_count: number;
  mean_interval: number;
  std_interval: number;
  coefficient_of_variation: number;
  min_interval: number;
  max_interval: number;
  last_seen: string;
  status: string;
  is_suspected: boolean;
  session_id: string;
}

export interface BeaconingResponse {
  note: string;
  total_candidates: number;
  suspected_count: number;
  candidates: BeaconingCandidate[];
}

export interface GraphNodeInfo {
  ip: string;
  in_degree: number;
  out_degree: number;
  weighted_in_flows: number;
  weighted_out_flows: number;
  degree_centrality: number;
  in_degree_centrality: number;
  out_degree_centrality: number;
  attack_flows: number;
  benign_flows: number;
  max_gaussian_score: number;
  attack_types: string[];
  roles: string[];
  is_hub: boolean;
  is_suspicious: boolean;
}

export interface GraphEdgeInfo {
  source: string;
  target: string;
  weight: number;
  attack_count: number;
  last_attack_type: string;
}

export interface NetworkGraphResponse {
  note: string;
  total_nodes: number;
  total_edges: number;
  total_flows_in_graph: number;
  reciprocity: number;
  topology_pattern: string;
  hub_nodes: GraphNodeInfo[];
  suspicious_nodes: GraphNodeInfo[];
  nodes: GraphNodeInfo[];
  edges: GraphEdgeInfo[];
}

export interface PerClassMetric {
  class_name: string;
  precision: number;
  recall: number;
  f1_score: number;
  support: number;
}

export interface ProfilePerformanceData {
  profile_id: string;
  dataset: string;
  model_name: string;
  architecture: string;
  input_shape: number[];
  n_features: number;
  n_classes: number;
  window_size: number;
  stride: number;
  best_epoch: number;
  gaussian_threshold: number;
  evaluation_note: string;
  multiclass_metrics: {
    accuracy: number;
    balanced_accuracy?: number;
    macro_precision: number;
    macro_recall: number;
    macro_f1: number;
    val_macro_f1?: number;
    false_positive_rate?: number;
  };
  binary_metrics?: {
    binary_accuracy: number;
    attack_precision: number;
    attack_recall: number;
    binary_f1: number;
    false_positive_rate: number;
    tp: number;
    tn: number;
    fp: number;
    fn: number;
  } | null;
  per_class: PerClassMetric[];
  confusion_matrix: {
    labels: string[];
    matrix: number[][];
  };
  model_comparison: Array<Record<string, number | string>>;
  pipeline_comparison: Array<Record<string, number | string>>;
  training_history: Array<{
    epoch: number;
    train_loss: number;
    val_macro_f1: number;
  }>;
}
