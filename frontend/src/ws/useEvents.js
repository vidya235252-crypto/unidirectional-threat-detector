import { useEffect, useRef, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";
const WS_URL = "ws://127.0.0.1:8000/ws/events";

export function useEvents() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("disconnected");
  const [currentScenario, setCurrentScenario] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    let cancelled = false;

    async function loadRecentAlerts() {
      try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=5`);
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
        // Keep the selected session visible while events are arriving.
        // Clearing here can race with the first alert on fast scenarios.
        setCurrentScenario(message.scenario);
      }

      if (
        message.type === "scenario_complete" ||
        message.type === "scenario_stopped"
      ) {
        // Do not clear the UI session immediately. The selected scenario
        // remains responsible for filtering the live feed after completion.
        // The REST stats poll still tracks the actual backend runtime state.
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

    syncScenarioState();

    const interval = setInterval(syncScenarioState, 500);

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