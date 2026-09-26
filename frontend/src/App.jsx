import "./App.css";
import { useState } from "react";
import { useEvents } from "./ws/useEvents";
import { ScenarioControls } from "./components/ScenarioControls";
import { AlertFeed } from "./components/AlertFeed";
import { StatsPanel } from "./components/StatsPanel";

function App() {
  const { alerts, status, currentScenario } = useEvents();
  const [selectedScenario, setSelectedScenario] = useState(null);

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
            <div className="brand-name">TRACELINE</div>
            <div className="brand-subtitle">THREAT DETECTOR</div>
          </div>
        </div>

        <div className="nav-section-label">OPERATIONS</div>
        <nav>
          <a className="nav-item active" href="#overview"><span className="nav-index">01</span>Overview</a>
          <a className="nav-item" href="#scenarios"><span className="nav-index">02</span>Detection scenarios</a>
          <a className="nav-item" href="#detections"><span className="nav-index">03</span>Live detections</a>
          <a className="nav-item" href="#sensor-path"><span className="nav-index">04</span>Sensor path</a>
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
            <div className="eyebrow">SECURITY OPERATIONS / THREAT INTELLIGENCE</div>
            <h1>TRACELINE</h1>
            <p className="header-subtitle">Passive threat intelligence for unidirectional network environments</p>
          </div>

          <div className="header-status">
            <div className="connection">
              <span className={`connection-dot ${status}`} />
              <div>
                <strong>{connectionLabel}</strong>
                <span>{currentScenario ? `SCENARIO / ${currentScenario.replaceAll("_", " ").toUpperCase()}` : "MONITORING CHANNEL"}</span>
              </div>
            </div>
            <div className="header-time">LIVE</div>
          </div>
        </header>

        <div className="constraint-strip" role="status" aria-label="Passive monitoring constraints">
          <span className="constraint-active"><i /> PASSIVE SENSOR</span>
          <span>ONE-WAY ONLY</span>
          <span>RX / METADATA PATH</span>
          <span>NO DECRYPTION</span>
          <span>NO RETURN PATH</span>
        </div>

        <section id="sensor-path" className="sensor-banner" aria-label="Passive sensor pipeline">
          <div className="pipeline">
            <div className="pipeline-node">
              <span className="pipeline-index">01</span>
              <div><span className="flow-kicker">INGEST</span><strong>NETWORK TRAFFIC</strong><span>Passive IP flow stream</span></div>
            </div>
            <div className="pipeline-connector" aria-hidden="true"><span>ONE-WAY</span><i /></div>
            <div className="pipeline-node pipeline-boundary">
              <span className="pipeline-index">02</span>
              <div><span className="flow-kicker">BOUNDARY</span><strong>DATA DIODE</strong><span>RX-only monitoring path</span></div>
            </div>
            <div className="pipeline-connector" aria-hidden="true"><span>METADATA</span><i /></div>
            <div className="pipeline-node">
              <span className="pipeline-index">03</span>
              <div><span className="flow-kicker">ANALYSIS</span><strong>DETECTION ENGINE</strong><span>Features · ML · behavioral rules</span></div>
            </div>
            <div className="pipeline-connector" aria-hidden="true"><span>OUTPUT</span><i /></div>
            <div className="pipeline-node pipeline-output">
              <span className="pipeline-index">04</span>
              <div><span className="flow-kicker">INTELLIGENCE</span><strong>THREAT ALERTS</strong><span>Class · confidence · evidence</span></div>
            </div>
          </div>
          <div className="sensor-rule"><span className="rule-dot" />NO RETURN PATH</div>
        </section>

        <section id="overview" className="overview-grid">
          <div className="section-heading">
            <div><div className="eyebrow">TELEMETRY</div><h2>Detection posture</h2></div>
            <span className="section-state"><span className="mini-dot" />{status === "connected" ? "INGESTING" : "WAITING FOR SENSOR"}</span>
          </div>
          <StatsPanel refreshKey={currentScenario} />
        </section>

        <section id="scenarios" className="scenario-section">
          <div className="section-heading compact">
            <div><div className="eyebrow">DEMO / VALIDATION</div><h2>Detection scenarios</h2></div>
            <span className="section-note">Synthetic traffic controls · local environment</span>
          </div>
          <ScenarioControls
            currentScenario={currentScenario}
            onScenarioSelect={setSelectedScenario}
/>
        </section>

        <section id="detections" className="alert-log">
          <div className="section-heading compact">
            <div>
              <div className="eyebrow">REAL-TIME EVENTS</div>
              <h2>Live detections</h2>
              <p className="section-subnote">Expand an event to inspect traffic, temporal behaviour, ML signal and rule evidence.</p>
            </div>
          </div>
          <AlertFeed alerts={alerts} currentScenario={selectedScenario ?? currentScenario} />
        </section>
      </main>
    </div>
  );
}

export default App;
