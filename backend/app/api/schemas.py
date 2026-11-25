"""Pydantic schemas for FastAPI validation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProfileSelectRequest(BaseModel):
    profile_id: str = Field(
        ...,
        description="Model profile ID: 'CIC-IDS2017' or 'CIC-DDoS2019'",
        examples=["CIC-IDS2017"],
    )


class StartMonitoringRequest(BaseModel):
    profile_id: str = Field(
        default="AUTO",
        description="Monitoring mode: AUTO, CIC-IDS2017 or CIC-DDoS2019",
    )
    data_source: str = Field(
        default="PCAP_REPLAY",
        description="Data source: 'LIVE', 'CSV_REPLAY', or 'PCAP_REPLAY'",
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface ID/name when data_source is 'LIVE'",
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Optional path to CSV or PCAP file on server; uses built-in sample if omitted",
    )
    replay_delay_ms: int = Field(
        default=80,
        ge=0,
        le=5000,
        description="Delay in milliseconds between replayed flows for realtime dashboard visualization",
    )
    max_rows: Optional[int] = Field(
        default=200,
        ge=1,
        le=10000,
        description="Maximum rows/packets to process in replay mode",
    )


class DirectInferenceRequest(BaseModel):
    profile_id: str = Field(default="CIC-IDS2017")
    source_ip: str = Field(default="192.168.1.100")
    destination_ip: str = Field(default="10.0.0.1")
    source_port: int = Field(default=50000, ge=0, le=65535)
    destination_port: int = Field(default=80, ge=0, le=65535)
    protocol: int = Field(default=6, ge=0, le=255)
    features: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Single flow feature dictionary (70 features for CIC-IDS2017)",
    )
    window_features: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of 8 flow feature dictionaries (66 features each for CIC-DDoS2019)",
    )
