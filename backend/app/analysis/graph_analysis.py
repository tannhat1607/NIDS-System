"""NetworkX Graph Analysis for communication topology and supplementary suspicious signals.

Sử dụng NetworkX DiGraph:
- Node: Địa chỉ IP.
- Edge: Kết nối có hướng từ Source IP -> Destination IP.
- Edge weight: Số lượng network flows giữa hai IP.
- Tính toán:
  + Degree centrality (in-degree, out-degree, total degree centrality).
  + Reciprocity (tỷ lệ giao tiếp hai chiều trên toàn đồ thị và từng node).
  + Hub nodes (các nút có bậc kết nối cao bất thường).
  + Dấu hiệu cấu trúc giao tiếp tập trung (Centralized C2 / DDoS target / Scanner hub).
  + Dấu hiệu P2P (Peer-to-Peer: nhiều nút có cả kết nối vào/ra đối xứng và reciprocity cao).
- Giới hạn bộ nhớ, số lượng node tối đa (`max_nodes`) và thời gian lưu trữ (`retention_seconds`).
- Chỉ xem kết quả là tín hiệu nghi ngờ bổ trợ (auxiliary topology signals).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

import networkx as nx


@dataclass
class GraphSummary:
    """Kết quả phân tích cấu trúc đồ thị giao tiếp mạng."""

    total_nodes: int
    total_edges: int
    total_flows_in_graph: int
    reciprocity: float
    topology_pattern: str  # "CENTRALIZED_HUB", "P2P_MESH_SUSPECTED", "DISTRIBUTED_NORMAL", "EMPTY"
    hub_nodes: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_nodes: List[Dict[str, Any]] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)


class NetworkGraphAnalyzer:
    """Bộ phân tích đồ thị giao tiếp mạng có giới hạn số node và thời gian lưu trữ."""

    def __init__(
        self,
        max_nodes: int = 500,
        retention_seconds: float = 1800.0,
    ) -> None:
        self.max_nodes = max(20, max_nodes)
        self.retention_seconds = retention_seconds
        self._graph = nx.DiGraph()

    def reset(self) -> None:
        self._graph.clear()

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        timestamp: float,
        is_attack: bool = False,
        attack_label: str = "BENIGN",
        gaussian_anomaly_score: float = 0.0,
    ) -> None:
        """Cập nhật node và edge trong đồ thị khi có một flow hoàn thành."""
        self._evict_expired(timestamp)

        # Kiểm tra giới hạn số lượng node trước khi thêm node mới
        for ip in (src_ip, dst_ip):
            if not self._graph.has_node(ip):
                if self._graph.number_of_nodes() >= self.max_nodes:
                    self._evict_oldest_node()
                self._graph.add_node(
                    ip,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    attack_flows=0,
                    benign_flows=0,
                    max_gaussian_score=0.0,
                    attack_types=set(),
                )

        # Cập nhật thuộc tính của 2 node
        for ip in (src_ip, dst_ip):
            ndata = self._graph.nodes[ip]
            ndata["last_seen"] = max(float(ndata.get("last_seen", timestamp)), timestamp)
            if is_attack:
                ndata["attack_flows"] = int(ndata.get("attack_flows", 0)) + 1
                attack_set: Set[str] = ndata.get("attack_types", set())
                attack_set.add(attack_label)
                ndata["attack_types"] = attack_set
            else:
                ndata["benign_flows"] = int(ndata.get("benign_flows", 0)) + 1
            if gaussian_anomaly_score > float(ndata.get("max_gaussian_score", 0.0)):
                ndata["max_gaussian_score"] = float(gaussian_anomaly_score)

        # Cập nhật hoặc tạo edge có hướng src_ip -> dst_ip với weight = số flow
        if self._graph.has_edge(src_ip, dst_ip):
            edata = self._graph[src_ip][dst_ip]
            edata["weight"] = int(edata.get("weight", 0)) + 1
            edata["last_seen"] = max(float(edata.get("last_seen", timestamp)), timestamp)
            if is_attack:
                edata["attack_count"] = int(edata.get("attack_count", 0)) + 1
                edata["last_attack_type"] = attack_label
        else:
            self._graph.add_edge(
                src_ip,
                dst_ip,
                weight=1,
                attack_count=1 if is_attack else 0,
                last_attack_type=attack_label if is_attack else "BENIGN",
                last_seen=timestamp,
            )

    def analyze(self) -> GraphSummary:
        """Tính toán degree centrality, reciprocity, hub nodes, cấu trúc tập trung / P2P."""
        n_nodes = self._graph.number_of_nodes()
        n_edges = self._graph.number_of_edges()

        if n_nodes == 0:
            return GraphSummary(
                total_nodes=0,
                total_edges=0,
                total_flows_in_graph=0,
                reciprocity=0.0,
                topology_pattern="EMPTY",
            )

        degree_centrality = nx.degree_centrality(self._graph) if n_nodes > 1 else {
            n: 0.0 for n in self._graph.nodes()
        }
        in_centrality = nx.in_degree_centrality(self._graph) if n_nodes > 1 else {
            n: 0.0 for n in self._graph.nodes()
        }
        out_centrality = nx.out_degree_centrality(self._graph) if n_nodes > 1 else {
            n: 0.0 for n in self._graph.nodes()
        }

        try:
            overall_reciprocity = float(nx.overall_reciprocity(self._graph) or 0.0)
        except Exception:
            overall_reciprocity = 0.0

        nodes_list: List[Dict[str, Any]] = []
        hub_nodes: List[Dict[str, Any]] = []
        suspicious_nodes: List[Dict[str, Any]] = []

        for node_ip, ndata in self._graph.nodes(data=True):
            in_deg = int(self._graph.in_degree(node_ip))
            out_deg = int(self._graph.out_degree(node_ip))
            weighted_in = int(self._graph.in_degree(node_ip, weight="weight"))
            weighted_out = int(self._graph.out_degree(node_ip, weight="weight"))
            deg_cent = round(float(degree_centrality.get(node_ip, 0.0)), 4)
            in_cent = round(float(in_centrality.get(node_ip, 0.0)), 4)
            out_cent = round(float(out_centrality.get(node_ip, 0.0)), 4)
            attack_flows = int(ndata.get("attack_flows", 0))
            benign_flows = int(ndata.get("benign_flows", 0))
            max_gaussian = round(float(ndata.get("max_gaussian_score", 0.0)), 2)
            attack_types = sorted(list(ndata.get("attack_types", set())))

            # Xác định vai trò nghi ngờ bổ trợ (Auxiliary Role)
            roles: List[str] = []
            if out_deg >= 3 and out_cent >= 0.4:
                roles.append("HIGH_OUT_DEGREE_SOURCE")
            if in_deg >= 3 and in_cent >= 0.4:
                roles.append("CENTRALIZED_TARGET_OR_HUB")
            if in_deg >= 2 and out_deg >= 2 and abs(in_deg - out_deg) <= 2:
                roles.append("SYMMETRIC_P2P_PEER")
            if attack_flows > 0:
                roles.append("ATTACK_PARTICIPANT")

            is_hub = bool((in_deg + out_deg) >= 3 or deg_cent >= 0.5)
            is_suspicious = bool(attack_flows > 0 or len(roles) > 0)

            node_info = {
                "ip": node_ip,
                "in_degree": in_deg,
                "out_degree": out_deg,
                "weighted_in_flows": weighted_in,
                "weighted_out_flows": weighted_out,
                "degree_centrality": deg_cent,
                "in_degree_centrality": in_cent,
                "out_degree_centrality": out_cent,
                "attack_flows": attack_flows,
                "benign_flows": benign_flows,
                "max_gaussian_score": max_gaussian,
                "attack_types": attack_types,
                "roles": roles,
                "is_hub": is_hub,
                "is_suspicious": is_suspicious,
            }
            nodes_list.append(node_info)
            if is_hub:
                hub_nodes.append(node_info)
            if is_suspicious:
                suspicious_nodes.append(node_info)

        nodes_list.sort(
            key=lambda x: (x["degree_centrality"], x["weighted_in_flows"] + x["weighted_out_flows"]),
            reverse=True,
        )
        hub_nodes.sort(key=lambda x: x["degree_centrality"], reverse=True)
        suspicious_nodes.sort(
            key=lambda x: (x["attack_flows"], x["degree_centrality"]), reverse=True
        )

        edges_list: List[Dict[str, Any]] = []
        total_flows = 0
        for u, v, edata in self._graph.edges(data=True):
            w = int(edata.get("weight", 1))
            total_flows += w
            edges_list.append(
                {
                    "source": u,
                    "target": v,
                    "weight": w,
                    "attack_count": int(edata.get("attack_count", 0)),
                    "last_attack_type": str(edata.get("last_attack_type", "BENIGN")),
                }
            )
        edges_list.sort(key=lambda e: e["weight"], reverse=True)

        # Nhận diện mẫu hình cấu trúc giao tiếp bổ trợ
        max_cent = max((n["degree_centrality"] for n in nodes_list), default=0.0)
        p2p_peers = sum(1 for n in nodes_list if "SYMMETRIC_P2P_PEER" in n["roles"])
        if overall_reciprocity >= 0.45 and p2p_peers >= 2:
            pattern = "P2P_MESH_SUSPECTED"
        elif max_cent >= 0.6 and n_nodes >= 3:
            pattern = "CENTRALIZED_HUB"
        else:
            pattern = "DISTRIBUTED_NORMAL"

        return GraphSummary(
            total_nodes=n_nodes,
            total_edges=n_edges,
            total_flows_in_graph=total_flows,
            reciprocity=round(overall_reciprocity, 4),
            topology_pattern=pattern,
            hub_nodes=hub_nodes[:20],
            suspicious_nodes=suspicious_nodes[:30],
            nodes=nodes_list[:150],
            edges=edges_list[:300],
        )

    def _evict_expired(self, current_ts: float) -> None:
        if self.retention_seconds <= 0 or self._graph.number_of_nodes() == 0:
            return
        cutoff = current_ts - self.retention_seconds
        expired_nodes = [
            n
            for n, data in self._graph.nodes(data=True)
            if float(data.get("last_seen", current_ts)) < cutoff
        ]
        for n in expired_nodes:
            self._graph.remove_node(n)

    def _evict_oldest_node(self) -> None:
        if self._graph.number_of_nodes() == 0:
            return
        oldest_node = min(
            self._graph.nodes(),
            key=lambda n: float(self._graph.nodes[n].get("last_seen", 0.0)),
        )
        self._graph.remove_node(oldest_node)
