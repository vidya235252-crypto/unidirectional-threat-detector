import { useEffect, useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE ?? `${window.location.protocol}//${window.location.hostname}:8000`;
const WS_URL = import.meta.env.VITE_WS_URL ?? `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.hostname}:8000/ws/events`;

export function useEvents() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("disconnected");
  const [currentScenario, setCurrentScenario] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    let cancelled = false;

    async function loadRecentAlerts() {
      try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=20`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setAlerts(data.slice(0, 5));
      } catch {
        // Live WebSocket remains available when REST is unavailable.
      }
    }

    loadRecentAlerts();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const socket = new WebSocket(WS_URL);
    wsRef.current = socket;

    socket.onopen = () => setStatus("connected");

    socket.onclose = () => setStatus("disconnected");

    socket.onerror = () => setStatus("error");

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);

      if (message.type === "alert") {
        const alert = { ...message.alert, scenario: message.scenario ?? null };
        setAlerts((prev) => [alert, ...prev.filter((item) => item.alert_id !== alert.alert_id)].slice(0, 20));
      }

      if (message.type === "scenario_started") {
        setCurrentScenario(message.scenario);
      }

      if (
        message.type === "scenario_complete" ||
        message.type === "scenario_stopped"
      ) {
        setCurrentScenario(null);
      }
    };

    return () => {
      socket.close();
    };
  }, []);

  /*
   * WebSocket events are used for live updates, but the REST API is
   * the authoritative source for whether a scenario is still running.
   *
   * This prevents the UI from getting stuck if a completion/stop
   * WebSocket event is missed.
   */
  useEffect(() => {
    let cancelled = false;

    async function syncScenarioState() {
      try {
        const res = await fetch(`${API_BASE}/api/stats`);

        if (!res.ok || cancelled) {
          return;
        }

        const stats = await res.json();

        if (stats.running && stats.current_scenario) {
          setCurrentScenario(stats.current_scenario);
        } else {
          setCurrentScenario(null);
        }
      } catch {
        // WebSocket remains the primary live channel.
      }
    }

    async function syncRecentAlerts() {
      try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=20`);
        if (!res.ok || cancelled) return;

        const data = await res.json();
        setAlerts((prev) => {
          const merged = new Map();
          for (const alert of [...data, ...prev]) {
            if (alert?.alert_id && !merged.has(alert.alert_id)) {
              merged.set(alert.alert_id, alert);
            }
          }
          return [...merged.values()]
            .sort((a, b) => String(b.timestamp ?? '').localeCompare(String(a.timestamp ?? '')))
            .slice(0, 20);
        });
      } catch {
        // WebSocket remains the primary live channel.
      }
    }

    syncScenarioState();
    syncRecentAlerts();

    const interval = setInterval(() => {
      syncScenarioState();
      syncRecentAlerts();
    }, 500);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return {
    alerts,
    status,
    currentScenario,
  };
}