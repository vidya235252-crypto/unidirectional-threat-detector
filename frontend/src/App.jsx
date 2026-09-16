import { useEvents } from "./ws/useEvents";

function App() {
  const { alerts, status, currentScenario } = useEvents();

  return (
    <div style={{ padding: "2rem", color: "white", background: "#1a1a1a", minHeight: "100vh" }}>
      <h1>WS test</h1>
      <p>WebSocket: {status}</p>
      <p>Running: {currentScenario ?? "none"}</p>
      <ul>
        {alerts.map((a) => (
          <li key={a.alert_id}>
            {a.threat_class} — {a.severity} (confidence {a.confidence})
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
