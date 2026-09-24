import { useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const SCENARIOS = [
  { key: "benign", label: "Benign" },
  { key: "port_scan", label: "Port scan" },
  { key: "c2_beaconing", label: "C2 beaconing" },
  { key: "syn_flood", label: "SYN flood" },
  { key: "data_exfiltration", label: "Data exfiltration" },
  { key: "dga_dns_tunneling", label: "DGA DNS tunneling" },
  { key: "malicious_tls", label: "Malicious TLS" },
];

export function ScenarioControls({ currentScenario }) {
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
        const body = await res.json();
        setError(body.detail ?? "Failed to start scenario");
      }
    } catch {
      setError("Could not reach backend");
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
    for (const { key } of SCENARIOS) {
      await startScenario(key);
      await new Promise((r) => setTimeout(r, 500));
      await waitForIdle();
    }
    setSequenceRunning(false);
  }

  const busy = currentScenario !== null || sequenceRunning;

  return (
    <div>
      <div className="control-rail">
        {SCENARIOS.map(({ key, label }) => (
          <button key={key} onClick={() => startScenario(key)} disabled={busy}>
            {label}
          </button>
        ))}
        <button onClick={stopScenario} disabled={!busy}>
          Stop
        </button>
        <span className="spacer" />
        <button className="primary" onClick={runSequence} disabled={busy}>
          Run demo sequence
        </button>
      </div>
      {error && <p className="error-line">{error}</p>}
    </div>
  );
}