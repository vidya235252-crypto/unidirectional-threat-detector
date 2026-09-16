import { useEffect, useRef, useState } from "react";

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
      } else if (message.type === "scenario_started") {
        setCurrentScenario(message.scenario);
      } else if (message.type === "scenario_complete" || message.type === "scenario_stopped") {
        setCurrentScenario(null);
      }
    };

    return () => {
      socket.close();
    };
  }, []);

  return { alerts, status, currentScenario };
}