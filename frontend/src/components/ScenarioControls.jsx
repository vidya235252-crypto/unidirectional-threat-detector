import { useState } from "react";
import {
  ShieldCheck,
  Search,
  Radio,
  Zap,
  UploadCloud,
  Globe2,
  Lock,
  Square,
  PlaySquare,
  AlertCircle,
} from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

const SCENARIOS = [
  { key: "benign", label: "Benign", icon: ShieldCheck },
  { key: "port_scan", label: "Port scan", icon: Search },
  { key: "c2_beaconing", label: "C2 beaconing", icon: Radio },
  { key: "syn_flood", label: "SYN flood", icon: Zap },
  { key: "data_exfiltration", label: "Data exfiltration", icon: UploadCloud },
  { key: "dga_dns_tunneling", label: "DGA DNS tunneling", icon: Globe2 },
  { key: "malicious_tls", label: "Malicious TLS", icon: Lock },
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
      <div className="flex flex-wrap items-center gap-2 rounded-2xl border border-slate-800 bg-slate-900/60 p-3">
        {SCENARIOS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => startScenario(key)}
            disabled={busy}
            className="group flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-300 transition-all duration-150 hover:border-slate-600 hover:bg-slate-800 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-slate-800 disabled:hover:bg-slate-900"
          >
            <Icon className="h-3.5 w-3.5 text-slate-500 transition-colors group-hover:text-emerald-400" />
            {label}
          </button>
        ))}

        <button
          onClick={stopScenario}
          disabled={!busy}
          className="flex items-center gap-1.5 rounded-lg border border-rose-900/60 bg-rose-950/40 px-3 py-2 text-sm font-medium text-rose-300 transition-all duration-150 hover:border-rose-700 hover:bg-rose-900/50 disabled:cursor-not-allowed disabled:opacity-30 disabled:hover:border-rose-900/60 disabled:hover:bg-rose-950/40"
        >
          <Square className="h-3.5 w-3.5" fill="currentColor" />
          Stop
        </button>

        <span className="flex-1" />

        <button
          onClick={runSequence}
          disabled={busy}
          className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2 text-sm font-semibold text-emerald-300 shadow-[0_0_0_0_rgba(16,185,129,0)] transition-all duration-150 hover:border-emerald-400/70 hover:bg-emerald-500/20 hover:shadow-[0_0_20px_-4px_rgba(16,185,129,0.5)] disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:shadow-none"
        >
          <PlaySquare className="h-3.5 w-3.5" />
          Run demo sequence
        </button>
      </div>

      {error && (
        <p className="mt-2 flex items-center gap-1.5 font-mono text-xs text-rose-400">
          <AlertCircle className="h-3.5 w-3.5" />
          {error}
        </p>
      )}
    </div>
  );
}
