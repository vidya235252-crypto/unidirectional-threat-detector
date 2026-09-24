import { useEffect, useRef, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";
const WS_URL = "ws://127.0.0.1:8000/ws/events";

export function useEvents() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("disconnected");
  const [currentScenario, setCurrentScenario] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const socket = new WebSocket(WS_URL);
    wsRef.current = socket;

    socket.onopen = () => setStatus("connected");

    socket.onclose = () => setStatus("disconnected");

    socket.onerror = () => setStatus("error");

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);

      if (message.type === "alert") {
        setAlerts((prev) => [message.alert, ...prev]);
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