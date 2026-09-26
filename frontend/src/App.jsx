import "./App.css";
import { useEvents } from "./ws/useEvents";
import { ScenarioControls } from "./components/ScenarioControls";
import { AlertFeed } from "./components/AlertFeed";
import { StatsPanel } from "./components/StatsPanel";

function App() {
  const { alerts, status, currentScenario } = useEvents();

  const connectionLabel =
    status === "connected"
      ? "SENSOR LINK ACTIVE"
      : status === "error"
        ? "SENSOR LINK ERROR"
        : "SENSOR LINK OFFLINE";

  return (
    <div className="app-shell">
      <aside className="side-nav" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <div className="brand-name">UDT</div>
            <div className="brand-subtitle">THREAT DETECTOR</div>
          </div>
        </div>

        <div className="nav-section-label">OPERATIONS</div>
        <nav>
          <button className="nav-item active" type="button">
            <span className="nav-index">01</span>
            Overview
          </button>
          <button className="nav-item" type="button">
            <span className="nav-index">02</span>
            Live detections
          </button>
          <button className="nav-item" type="button">
            <span className="nav-index">03</span>
            Investigations
          </button>
          <button className="nav-item" type="button">
            <span className="nav-index">04</span>
            Traffic intelligence
          </button>
          <button className="nav-item" type="button">
            <span className="nav-index">05</span>
            System health
          </button>
        </nav>

        <div className="side-nav-footer">
          <div className="diode-badge">
            <span className="status-pulse" />
            <div>
              <strong>PASSIVE MODE</strong>
              <span>ONE-WAY TELEMETRY</span>
            </div>
          </div>
          <div className="build-meta">SIH 26145 · NTRO</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="app-header">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div>
            <h1>Unidirectional Threat Detector</h1>
            <p className="header-subtitle">
              Passive network intelligence for one-way traffic environments
            </p>
          </div>

          <div className="header-status">
            <div className="connection">
              <span className={`connection-dot ${status}`} />
              <div>
                <strong>{connectionLabel}</strong>
                <span>
                  {currentScenario
                    ? `SCENARIO / ${currentScenario.replaceAll("_", " ").toUpperCase()}`
                    : "MONITORING CHANNEL"}
                </span>
              </div>
            </div>
            <div className="header-time">LIVE</div>
          </div>
        </header>

        <section className="sensor-banner" aria-label="Passive sensor status">
          <div className="sensor-flow">
            <div className="flow-node">
              <span className="flow-kicker">SOURCE</span>
              <strong>NETWORK TRAFFIC</strong>
              <span>Observed IP flows</span>
            </div>
            <div className="flow-direction" aria-hidden="true">
              <span className="flow-line" />
              <span className="flow-arrow">›</span>
            </div>
            <div className="flow-node diode-node">
              <span className="flow-kicker">BOUNDARY</span>
              <strong>DATA DIODE</strong>
              <span>Unidirectional ingress</span>
            </div>
            <div className="flow-direction" aria-hidden="true">
              <span className="flow-line" />
              <span className="flow-arrow">›</span>
            </div>
            <div className="flow-node">
              <span className="flow-kicker">ANALYSIS</span>
              <strong>DETECTION ENGINE</strong>
              <span>ML + behavioral evidence</span>
            </div>
          </div>
          <div className="sensor-rule">
            <span className="rule-dot" />
            NO RETURN PATH
          </div>
        </section>

        <section className="overview-grid">
          <div className="section-heading">
            <div>
              <div className="eyebrow">TELEMETRY</div>
              <h2>Detection posture</h2>
            </div>
            <span className="section-state">
              <span className="mini-dot" />
              {status === "connected" ? "INGESTING" : "WAITING FOR SENSOR"}
            </span>
          </div>

          <StatsPanel refreshKey={currentScenario} />
        </section>

        <section className="scenario-section">
          <div className="section-heading compact">
            <div>
              <div className="eyebrow">DEMO / VALIDATION</div>
              <h2>Detection scenarios</h2>
            </div>
            <span className="section-note">
              Synthetic traffic controls · local environment
            </span>
          </div>
          <ScenarioControls currentScenario={currentScenario} />
        </section>

        <section className="alert-log">
          <div className="section-heading compact">
            <div>
              <div className="eyebrow">REAL-TIME EVENTS</div>
              <h2>Live detections</h2>
            </div>
            <div className="alert-counter">
              <span>{alerts.length}</span> events in session
            </div>
          </div>
          <AlertFeed alerts={alerts} />
        </section>
      </main>
    </div>
  );
}

export default App;
