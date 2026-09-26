import { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const CLASS_LABELS = {
  PORT_SCAN: "Port scan",
  C2_BEACONING: "C2 beaconing",
  SYN_FLOOD: "SYN flood",
  DATA_EXFILTRATION: "Data exfiltration",
  DGA_DNS_TUNNELING: "DGA / DNS tunneling",
  MALICIOUS_TLS: "Malicious TLS",
};

const numberFormatter = new Intl.NumberFormat("en-IN");

export function StatsPanel({ refreshKey }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchStats() {
      try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const data = await res.json();
        if (!cancelled) setStats(data);
      } catch {
        // backend unreachable, leave previous stats displayed
      }
    }

    fetchStats();
    const interval = setInterval(fetchStats, 2000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [refreshKey]);

  if (!stats) {
    return <p className="alert-empty">Loading telemetry snapshot…</p>;
  }

  const alertClasses = Object.entries(stats.alerts_by_class ?? {}).sort(
    ([, countA], [, countB]) => countB - countA
  );

  const peakClassCount = Math.max(
    1,
    ...alertClasses.map(([, count]) => Number(count) || 0)
  );

  return (
    <div className="stats-panel">
      <div className="stats-strip">
      <Stat
        label="Flows observed"
        value={stats.total_flows}
        variant="primary"
        detail="Telemetry received"
      />
      <Stat
        label="Threat alerts"
        value={stats.total_alerts}
        variant="alert"
        detail="Detections raised"
      />

      {alertClasses.map(([cls, count]) => (
        <Stat
          key={cls}
          label={CLASS_LABELS[cls] ?? cls.toLowerCase().replaceAll("_", " ")}
          value={count}
          variant="threat"
          detail="Class detections"
          barValue={(Number(count) || 0) / peakClassCount}
        />
      ))}
      </div>
      <div className="stats-caption">
        <span><i /> LIVE TELEMETRY SNAPSHOT</span>
        <span>REFRESH / 2S</span>
      </div>
    </div>
  );
}

function Stat({ label, value, variant = "", detail, barValue }) {
  return (
    <div className={`stat ${variant ? `stat-${variant}` : ""}`}>
      <div className="stat-topline">
        <span className="stat-label">{label}</span>
        {variant === "primary" && <span className="stat-index">01</span>}
        {variant === "alert" && <span className="stat-index">02</span>}
      </div>

      <div className="stat-value">{numberFormatter.format(Number(value) || 0)}</div>

      <div className="stat-footer">
        <span>{detail}</span>
        {typeof barValue === "number" && (
          <span>{Math.round(barValue * 100)}%</span>
        )}
      </div>

      {typeof barValue === "number" && (
        <div className="stat-bar" aria-hidden="true">
          <span style={{ width: `${Math.max(0, Math.min(1, barValue)) * 100}%` }} />
        </div>
      )}
    </div>
  );
}
