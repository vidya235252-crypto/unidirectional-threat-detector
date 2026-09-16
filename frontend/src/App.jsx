import "./App.css";
import { useEvents } from "./ws/useEvents";
import { ScenarioControls } from "./components/ScenarioControls";
import { AlertFeed } from "./components/AlertFeed";
import { StatsPanel } from "./components/StatsPanel";

function App() {
  const { alerts, status, currentScenario } = useEvents();

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>Unidirectional Threat Detector</h1>
        <div className="connection">
          <span className={`connection-dot ${status}`} />
          <span>{status}{currentScenario ? `, running ${currentScenario}` : ""}</span>
        </div>
      </header>

      <ScenarioControls currentScenario={currentScenario} />
      <StatsPanel refreshKey={currentScenario} />

      <section className="alert-log">
        <h2>Live alerts</h2>
        <AlertFeed alerts={alerts} />
      </section>
    </div>
  );
}

export default App;
