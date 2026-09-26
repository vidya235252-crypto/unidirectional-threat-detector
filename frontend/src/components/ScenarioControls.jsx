import { useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const SCENARIOS = [
  { key: "port_scan", label: "Port scan", code: "PS", kind: "Reconnaissance" },
  { key: "c2_beaconing", label: "C2 beaconing", code: "C2", kind: "Command channel" },
  { key: "syn_flood", label: "SYN flood", code: "SF", kind: "Flood pattern" },
  { key: "data_exfiltration", label: "Data exfiltration", code: "DE", kind: "Outbound transfer" },
  { key: "dga_dns_tunneling", label: "DGA DNS tunneling", code: "DG", kind: "DNS anomaly" },
  { key: "malicious_tls", label: "Malicious TLS", code: "MT", kind: "TLS metadata" },
];

export function ScenarioControls({ currentScenario, onScenarioSelect }) {
  const [sequenceRunning, setSequenceRunning] = useState(false);
  const [error, setError] = useState(null);

  async function startScenario(name) {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/scenario/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: name }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.detail ?? "Failed to start scenario");
        return false;
      }

      onScenarioSelect?.(name);
      return true;
    } catch {
      setError("Could not reach backend");
      return false;
    }
  }

  async function stopScenario() {
    setError(null);
    try {
      await fetch(`${API_BASE}/api/scenario/stop`, { method: "POST" });
    } catch {
      setError("Could not reach backend");
    }
  }

  function waitForIdle(pollIntervalMs = 300) {
    return new Promise((resolve) => {
      const check = async () => {
        try {
          const res = await fetch(`${API_BASE}/api/stats`);
          const stats = await res.json();
          if (!stats.running) {
            resolve();
          } else {
            setTimeout(check, pollIntervalMs);
          }
        } catch {
          setTimeout(check, pollIntervalMs);
        }
      };
      check();
    });
  }

  async function runSequence() {
    setSequenceRunning(true);
    setError(null);

    try {
      for (const { key } of SCENARIOS) {
        const started = await startScenario(key);
        if (!started) return;
        await new Promise((r) => setTimeout(r, 300));
        await waitForIdle();
      }
    } finally {
      setSequenceRunning(false);
    }
  }

  const busy = currentScenario !== null || sequenceRunning;
  const activeScenario = SCENARIOS.find(({ key }) => key === currentScenario);

  return (
    <div className="scenario-controls">
      <div className="scenario-toolbar">
        <div className="scenario-console-label">
          <span>VALIDATION CONSOLE</span>
          <small>READ-ONLY TRAFFIC REPLAY</small>
        </div>
        <div className="scenario-state">
          <span className={`scenario-state-dot ${busy ? "running" : ""}`} />
          <div>
            <span className="scenario-state-label">
              {sequenceRunning ? "DEMO SEQUENCE" : busy ? "SCENARIO RUNNING" : "READY"}
            </span>
            <strong>
              {sequenceRunning
                ? "Executing validation set"
                : activeScenario?.label ?? "Select a traffic scenario"}
            </strong>
          </div>
        </div>

        <div className="scenario-actions">
          <button
            className="scenario-stop"
            type="button"
            onClick={stopScenario}
            disabled={!busy}
          >
            <span aria-hidden="true">■</span>
            Stop
          </button>
          <button
            className="scenario-sequence"
            type="button"
            onClick={runSequence}
            disabled={busy}
          >
            <span>RUN</span>
            Demo sequence
          </button>
        </div>
      </div>

      <div className="scenario-grid">
        {SCENARIOS.map(({ key, label, code, kind }) => {
          const active = currentScenario === key;

          return (
            <button
              key={key}
              className={`scenario-card ${active ? "active" : ""}`}
              type="button"
              onClick={() => startScenario(key)}
              disabled={busy}
              aria-pressed={active}
            >
              <span className="scenario-card-index">{String(SCENARIOS.findIndex((item) => item.key === key) + 1).padStart(2, "0")}</span>
              <span className="scenario-card-code">{code}</span>
              <span className="scenario-card-copy">
                <strong>{label}</strong>
                <span>{kind}</span>
              </span>
              <span className="scenario-card-arrow" aria-hidden="true">
                {active ? "●" : "↗"}
              </span>
            </button>
          );
        })}
      </div>

      {error && (
        <p className="error-line" role="alert">
          <span>ERROR</span>
          {error}
        </p>
      )}
    </div>
  );
}
