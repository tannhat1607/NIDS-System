import { useEffect, useRef, useState } from 'react';
import { DetectionAlert, MonitoringStatus } from '../types/nids';

interface WsEventMessage {
  type: 'INITIAL_STATE' | 'STATUS_UPDATE' | 'DETECTION_EVENT' | 'PONG';
  data: any;
  status?: MonitoringStatus;
}

export function useNidsWebSocket(onDetectionEvent?: (alert: DetectionAlert) => void) {
  const [connected, setConnected] = useState(false);
  const [liveStatus, setLiveStatus] = useState<MonitoringStatus | null>(null);
  const [liveFeed, setLiveFeed] = useState<DetectionAlert[]>([]);
  const callbackRef = useRef(onDetectionEvent);
  callbackRef.current = onDetectionEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let pingTimer: number | null = null;
    let unmounted = false;

    const connect = () => {
      if (unmounted) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = import.meta.env.VITE_WS_HOST || window.location.host;
      const wsUrl = `${protocol}//${host}/ws/live`;

      try {
        ws = new WebSocket(wsUrl);
      } catch {
        setConnected(false);
        reconnectTimer = window.setTimeout(connect, 3000);
        return;
      }

      ws.onopen = () => {
        if (unmounted) return;
        setConnected(true);
        pingTimer = window.setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 15000);
      };

      ws.onmessage = (evt) => {
        if (unmounted) return;
        try {
          const msg: WsEventMessage = JSON.parse(evt.data);
          if (msg.type === 'INITIAL_STATE' || msg.type === 'STATUS_UPDATE' || msg.type === 'PONG') {
            setLiveStatus(msg.data as MonitoringStatus);
          } else if (msg.type === 'DETECTION_EVENT') {
            const alert = msg.data as DetectionAlert;
            if (msg.status) {
              setLiveStatus(msg.status);
            }
            setLiveFeed((prev) => [alert, ...prev].slice(0, 120));
            if (callbackRef.current) {
              callbackRef.current(alert);
            }
          }
        } catch {
          // ignore malformed ws message
        }
      };

      ws.onclose = () => {
        setConnected(false);
        if (pingTimer) window.clearInterval(pingTimer);
        if (!unmounted) {
          reconnectTimer = window.setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        setConnected(false);
      };
    };

    connect();

    return () => {
      unmounted = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (pingTimer) window.clearInterval(pingTimer);
      if (ws) ws.close();
    };
  }, []);

  return { connected, liveStatus, liveFeed, clearLiveFeed: () => setLiveFeed([]) };
}
